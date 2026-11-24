//! Bare-metal S-mode platform runtime facade implementing [`Clock`], [`HartTopology`], and [`HartCoordinator`].

pub(crate) mod boot;
pub(crate) mod console;
pub(crate) mod counters;
pub(crate) mod dtb;
pub(crate) mod hsm;
pub(crate) mod icache;
pub(crate) mod misalign;
pub(crate) mod mmu;
pub(crate) mod shmem;
pub(crate) mod smp;
pub(crate) mod sse;
pub(crate) mod susp;
pub(crate) mod timer;
pub(crate) mod trap;

use mbench_core::{
    engine::{Clock, CounterSnap, HartCoordinator, ParallelSample, ParallelWorkFn},
    record::{
        CounterAvailability, FailReason, HartTopology, MetaRecord, SbiExtensionId, SkipReason,
    },
};
use riscv::register::{sie, sip, sstatus};

use self::{
    console::ConsoleBackend,
    counters::RiscvCounters,
    dtb::HardwareInfo,
    hsm::{HsmSuspendProbe, HsmSuspendWorker, SuspendWakeMode},
    misalign::MisalignProbe,
    mmu::{SatpTarget, Sv39Config},
    shmem::{DbtrAcquire, ShmemAcquire, ShmemLease, ShmemOwner, ShmemPool},
    smp::HsmHartPool,
    sse::SseSession,
    timer::TimerMode,
    trap::TrapHookMode,
};
use crate::sbi::{self, SbiCaps, SbiError, SbiRet};

/// Encapsulated S-mode runtime environment passed to conformance checks and benchmark suites.
pub(crate) struct Platform {
    pub(in crate::platform) info: HardwareInfo,
    pub(in crate::platform) caps: SbiCaps,
    pub(in crate::platform) console: ConsoleBackend,
    pub(in crate::platform) counters: RiscvCounters,
    pub(in crate::platform) harts: HsmHartPool,
    pub(in crate::platform) shmem: ShmemPool,
    sv39: Sv39Config,
    sv39_active: bool,
    sv39_faulted: bool,
    pmu_counter_count: usize,
    pmu_tainted_mask: u64,
    pmu_tainted_overflow: bool,
    boot_ticks: u64,
    load_addr: usize,
}

/// RAII guard activating Sv39 identity mapping across all online harts and restoring `Bare` on finish/drop.
///
/// Does not implement `DerefMut<Target = Platform>` to prevent re-entrant `enable_sv39()` calls.
#[must_use = "Sv39Guard should be explicitly finished to check remote teardown results"]
pub(crate) struct Sv39Guard<'a> {
    platform: &'a mut Platform,
    active: bool,
}

impl Sv39Guard<'_> {
    pub(crate) fn sv39_asid(&self) -> usize {
        self.platform.sv39.asid()
    }

    pub(crate) fn target_page_addr(&self) -> usize {
        self.platform.sv39.target_page_addr()
    }

    pub(crate) fn self_hart_mask(&self) -> (usize, usize) {
        self.platform.self_hart_mask()
    }

    pub(in crate::platform) fn cfg(&self) -> Sv39Config {
        self.platform.sv39
    }

    pub(in crate::platform) fn read_u64_on_worker(
        &mut self,
        slot_idx: usize,
        addr: usize,
    ) -> Result<u64, FailReason> {
        self.platform.harts.read_u64_on_worker(slot_idx, addr)
    }

    /// Restores `Bare` mode on BSP and all online workers, reporting any remote failure.
    pub(crate) fn finish(mut self) -> Result<(), FailReason> {
        let res = self.platform.disable_sv39_all_harts_checked();
        self.active = false;
        res
    }
}

impl Drop for Sv39Guard<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.platform.disable_sv39_all_harts_checked();
            self.active = false;
        }
    }
}

impl Clock for Sv39Guard<'_> {
    fn snap_begin(&self) -> CounterSnap {
        self.platform.snap_begin()
    }

    fn snap_end(&self) -> CounterSnap {
        self.platform.snap_end()
    }

    fn read_cycles(&self) -> u64 {
        self.platform.read_cycles()
    }

    fn read_ticks(&self) -> u64 {
        self.platform.read_ticks()
    }

    fn availability(&self) -> CounterAvailability {
        self.platform.availability()
    }

    fn timebase_hz(&self) -> u64 {
        self.platform.timebase_hz()
    }
}

impl HartTopology for Sv39Guard<'_> {
    fn total_harts(&self) -> usize {
        self.platform.total_harts()
    }
}

impl HartCoordinator for Sv39Guard<'_> {
    fn online_harts(&self) -> usize {
        self.platform.online_harts()
    }

    fn run_parallel(
        &mut self,
        parallel: usize,
        iters: u64,
        work_fn: ParallelWorkFn,
        out_samples: &mut [ParallelSample],
    ) -> Result<(), FailReason> {
        self.platform
            .run_parallel(parallel, iters, work_fn, out_samples)
    }
}

/// RAII guard configuring IPI hook modes on selected online worker slots and resetting them on finish/drop.
#[must_use]
pub(crate) struct WorkerIpiModeGuard<'a> {
    platform: &'a mut Platform,
    end_slot: usize,
    active: bool,
}

impl WorkerIpiModeGuard<'_> {
    pub(crate) fn timebase_hz(&self) -> u64 {
        self.platform.timebase_hz()
    }

    pub(crate) fn hart_id(&self, slot_idx: usize) -> usize {
        self.platform.harts.hart_id(slot_idx)
    }

    pub(crate) fn wait_until(
        &self,
        timeout_ticks: u64,
        cond: impl FnMut() -> bool,
    ) -> Result<(), FailReason> {
        self.platform.wait_until(timeout_ticks, cond)
    }

    pub(crate) fn install_self_ipi_capture(&self) -> Result<trap::IpiCaptureHookGuard, FailReason> {
        trap::IpiCaptureHookGuard::install(self.platform.availability())
    }

    /// Resets configured worker IPI hooks back to [`TrapHookMode::None`].
    pub(crate) fn finish(mut self) -> Result<(), FailReason> {
        let res = self.reset_workers();
        self.active = false;
        res
    }

    fn reset_workers(&mut self) -> Result<(), FailReason> {
        let mut first_err: Option<FailReason> = None;
        let avail = self.platform.availability();
        for slot in 1..self.end_slot {
            if let Err(err) =
                self.platform
                    .harts
                    .set_worker_ipi_mode(slot, TrapHookMode::None, avail, 0)
                && first_err.is_none()
            {
                first_err = Some(err);
            }
        }
        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

impl Drop for WorkerIpiModeGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.reset_workers();
            self.active = false;
        }
    }
}

impl Clock for WorkerIpiModeGuard<'_> {
    fn snap_begin(&self) -> CounterSnap {
        self.platform.snap_begin()
    }

    fn snap_end(&self) -> CounterSnap {
        self.platform.snap_end()
    }

    fn read_cycles(&self) -> u64 {
        self.platform.read_cycles()
    }

    fn read_ticks(&self) -> u64 {
        self.platform.read_ticks()
    }

    fn availability(&self) -> CounterAvailability {
        self.platform.availability()
    }

    fn timebase_hz(&self) -> u64 {
        self.platform.timebase_hz()
    }
}

impl HartTopology for WorkerIpiModeGuard<'_> {
    fn total_harts(&self) -> usize {
        self.platform.total_harts()
    }
}

impl Platform {
    /// Initializes trap vectors, FDT topology, SBI capabilities, console, counters, and Sv39.
    ///
    /// # Safety
    ///
    /// Must be called exactly once by the bootstrap hart after `.bss` is cleared and `tp` is set.
    pub(in crate::platform) unsafe fn boot(boot_hart_id: usize, dtb_paddr: usize) -> Self {
        // SAFETY: Bootstrap `tp` was set to `HART_LOCALS[0]` in `mbench_bsp_start`.
        unsafe { trap::init_on_current_hart() };
        // SAFETY: `dtb_paddr` comes from firmware entry contract and lives for `'static`.
        let mut info = unsafe { HardwareInfo::from_dtb(boot_hart_id, dtb_paddr) };
        if info.has_sstc {
            info.has_sstc = timer::probe_stimecmp_writable();
        }
        let caps = SbiCaps::probe();
        let console = ConsoleBackend::select(&caps, info.uart16550);
        let counters = RiscvCounters::probe(&caps, info.timebase_hz);
        // SAFETY: Called once during single-hart BSP boot before any AP or Sv39 activation.
        let sv39 = unsafe { mmu::init_sv39_identity_table() };
        // SAFETY: Constructed once during BSP boot for exclusive runtime ownership.
        let shmem = unsafe { ShmemPool::take_once() };
        let harts = HsmHartPool::new(&info, counters.availability(), sv39);

        let pmu_counter_count = if caps.extensions.contains_ext(SbiExtensionId::Pmu) {
            sbi::into_result(sbi::pmu::num_counters()).unwrap_or(0)
        } else {
            0
        };

        Self {
            info,
            caps,
            console,
            counters,
            harts,
            shmem,
            sv39,
            sv39_active: false,
            sv39_faulted: false,
            pmu_counter_count,
            pmu_tainted_mask: 0,
            pmu_tainted_overflow: false,
            boot_ticks: boot::boot_ticks(),
            load_addr: boot::LOAD_ADDR,
        }
    }

    pub(crate) fn info(&self) -> &HardwareInfo {
        &self.info
    }

    pub(crate) fn caps(&self) -> &SbiCaps {
        &self.caps
    }

    pub(crate) fn console(&self) -> ConsoleBackend {
        self.console
    }

    /// Returns `true` if PMU counter index `idx` failed to stop cleanly and must remain isolated.
    pub(crate) const fn is_pmu_counter_tainted(&self, idx: usize) -> bool {
        if idx < u64::BITS as usize {
            (self.pmu_tainted_mask & (1u64 << idx)) != 0
        } else {
            self.pmu_tainted_overflow
        }
    }

    /// Marks PMU counter `idx` permanently tainted so future cases do not reuse unclean state.
    pub(crate) fn taint_pmu_counter(&mut self, idx: usize) {
        if idx < u64::BITS as usize {
            self.pmu_tainted_mask |= 1u64 << idx;
        } else {
            self.pmu_tainted_overflow = true;
        }
    }

    /// Returns `true` when any PMU counter suffered an unrecovered teardown error.
    pub(crate) const fn has_tainted_pmu_counters(&self) -> bool {
        self.pmu_tainted_mask != 0 || self.pmu_tainted_overflow
    }

    pub(crate) fn target_page_addr(&self) -> usize {
        self.sv39.target_page_addr()
    }

    pub(crate) fn sv39_asid(&self) -> usize {
        self.sv39.asid()
    }

    pub(crate) fn boot_ticks(&self) -> u64 {
        self.boot_ticks
    }

    pub(crate) fn hart_id(&self, slot_idx: usize) -> usize {
        self.harts.hart_id(slot_idx)
    }

    pub(crate) fn bringup_secondary_harts(
        &mut self,
        max_total_harts: usize,
    ) -> Result<usize, FailReason> {
        self.harts.bringup_up_to(max_total_harts)
    }

    pub(crate) fn stop_secondary_harts(&mut self) -> Result<(), FailReason> {
        self.harts.stop_all()
    }

    /// Builds the [`MetaRecord`] emitted at Phase 0.
    pub(crate) fn meta_record<'a>(
        &'a self,
        config: mbench_core::config::RunConfig<'a>,
    ) -> MetaRecord<'a> {
        MetaRecord {
            sbi_spec_version: self.caps.spec_version,
            impl_id: self.caps.impl_id,
            impl_version: self.caps.impl_version,
            mvendorid: self.caps.mvendorid,
            marchid: self.caps.marchid,
            mimpid: self.caps.mimpid,
            extensions: self.caps.extensions,
            hart_count: self.info.hart_count,
            boot_hart_id: self.info.boot_hart_id,
            timebase_hz: self.info.timebase_hz,
            counters: self.counters.availability(),
            has_sstc: self.info.has_sstc,
            has_h_ext: self.info.has_h_ext,
            boot_ticks: self.boot_ticks,
            reserved_mem_bytes: self.info.reserved_mem_bytes,
            console_backend: self.console.name(),
            pmu_counter_count: self.pmu_counter_count,
            load_addr: self.load_addr,
            config,
        }
    }

    /// Returns `(hart_mask, hart_mask_base)` targeting `hart_id`.
    pub(crate) const fn hart_mask_single(hart_id: usize) -> (usize, usize) {
        (1usize << (hart_id & 63), hart_id & !63)
    }

    /// Returns `(hart_mask, hart_mask_base)` targeting the bootstrap hart.
    pub(crate) const fn self_hart_mask(&self) -> (usize, usize) {
        Self::hart_mask_single(self.info.boot_hart_id)
    }

    /// Returns `(hart_mask, hart_mask_base)` covering all online worker harts (`1..online_harts`).
    pub(crate) fn workers_hart_mask(&self) -> Option<(usize, usize)> {
        let online = self.online_harts();
        if online < 2 {
            return None;
        }
        self.hart_mask_for_slot_range(1, online)
    }

    /// Returns `(hart_mask, hart_mask_base)` covering all online remote workers (`None` if single-hart).
    pub(crate) fn all_remote_hart_mask(&self) -> Option<(usize, usize)> {
        self.workers_hart_mask()
    }

    fn hart_mask_for_slot_range(
        &self,
        start_slot: usize,
        end_slot: usize,
    ) -> Option<(usize, usize)> {
        if start_slot >= end_slot {
            return None;
        }
        let mut min_hid = usize::MAX;
        let mut max_hid = 0usize;
        for slot in start_slot..end_slot {
            let hid = self.harts.hart_id(slot);
            min_hid = min_hid.min(hid);
            max_hid = max_hid.max(hid);
        }
        if max_hid.saturating_sub(min_hid) >= usize::BITS as usize {
            return None;
        }
        let mut mask = 0usize;
        for slot in start_slot..end_slot {
            mask |= 1usize << (self.harts.hart_id(slot) - min_hid);
        }
        Some((mask, min_hid))
    }

    /// Polls `cond` until true or `timeout_ticks` (or `50_000_000` spin fallback) expires.
    pub(crate) fn wait_until(
        &self,
        timeout_ticks: u64,
        cond: impl FnMut() -> bool,
    ) -> Result<(), FailReason> {
        counters::wait_until(
            self.availability().has_time,
            timeout_ticks,
            50_000_000,
            cond,
        )
    }

    /// Activates the Sv39 identity page table across all online harts with rollback on partial failure.
    pub(crate) fn enable_sv39(&mut self) -> Result<Sv39Guard<'_>, FailReason> {
        if self.sv39_active || self.sv39_faulted {
            return Err(FailReason::HardwareInconsistent);
        }
        let actual = mmu::apply(SatpTarget::Sv39(self.sv39));
        if !mmu::is_sv39_active() || actual.bits() == 0 {
            let _ = mmu::apply(SatpTarget::Bare);
            return Err(FailReason::HardwareInconsistent);
        }
        if let Err(err) = self.harts.set_satp_all_workers(SatpTarget::Sv39(self.sv39)) {
            let _ = mmu::apply(SatpTarget::Bare);
            if self.harts.set_satp_all_workers(SatpTarget::Bare).is_err() || mmu::is_sv39_active() {
                self.sv39_faulted = true;
            }
            return Err(err);
        }
        self.sv39_active = true;
        Ok(Sv39Guard {
            platform: self,
            active: true,
        })
    }

    fn disable_sv39_all_harts_checked(&mut self) -> Result<(), FailReason> {
        if !self.sv39_active && !mmu::is_sv39_active() && !self.sv39_faulted {
            return Ok(());
        }
        let _ = mmu::apply(SatpTarget::Bare);
        let worker_res = self.harts.set_satp_all_workers(SatpTarget::Bare);
        let bsp_bare = !mmu::is_sv39_active();
        self.sv39_active = !bsp_bare;
        match (bsp_bare, worker_res) {
            (true, Ok(())) => {
                self.sv39_faulted = false;
                Ok(())
            }
            (false, _) => {
                self.sv39_faulted = true;
                Err(FailReason::HardwareInconsistent)
            }
            (true, Err(err)) => {
                self.sv39_faulted = true;
                Err(err)
            }
        }
    }

    /// Exclusively leases the static shared-memory pool for `owner`.
    pub(crate) fn lease_shmem(
        &mut self,
        owner: ShmemOwner,
    ) -> Result<ShmemAcquire<'_>, FailReason> {
        ShmemLease::acquire(self, owner)
    }

    /// Starts an exclusive DBTR shared-memory and hardware debug trigger session.
    pub(crate) fn start_dbtr_session(&mut self) -> Result<DbtrAcquire<'_>, FailReason> {
        shmem::DbtrSession::start(self)
    }

    /// Runs non-short-circuiting boundary security checks for `target` shared-memory registration.
    pub(crate) fn probe_shmem_security(
        &mut self,
        target: ShmemOwner,
        ctx: &mut mbench_core::check::CheckCtx,
    ) -> Result<bool, FailReason> {
        let mmode_addr = self.info.mmode_reserved_addr;
        shmem::probe_security(self, target, mmode_addr, ctx)
    }

    /// Queries `sbi_pmu_event_get_info` using exclusive scratch memory at `byte_offset`.
    pub(crate) fn probe_pmu_event_get_info(
        &mut self,
        entries: &mut [sbi::pmu::EventInfoEntry],
        flags: usize,
        byte_offset: usize,
    ) -> Result<SbiRet, FailReason> {
        shmem::probe_pmu_event_get_info(self, entries, flags, byte_offset)
    }

    /// Configures a wake-up device before `sbi_system_suspend(SUSPEND_TO_RAM)` when available.
    pub(crate) fn arm_system_suspend_wake_source(&mut self) -> Result<(), SkipReason> {
        // Per SBI v3.0 ext-sys-suspend.adoc, caller must configure a wake-up device prior to suspend;
        // QEMU `virt` / `mbench-target` currently provisions no wake-capable platform device driver.
        Err(SkipReason::WakeSourceUnavailable)
    }

    /// Probes `sbi_system_suspend` with the reserved invalid sleep type under full resume context protection.
    pub(crate) fn probe_invalid_sleep_type(&mut self) -> Result<isize, FailReason> {
        susp::probe_invalid_sleep_type(self)
    }

    /// Probes invalid `sbi_sse_register` call (unaligned PC or invalid event ID).
    pub(crate) fn probe_sse_invalid_register(&self, event_id: usize, unaligned: bool) -> SbiRet {
        sse::probe_invalid_register(event_id, unaligned)
    }

    /// Probes `sbi_hart_suspend` on `peer_hart_id` and returns observed state.
    pub(crate) fn probe_secondary_suspend(
        &mut self,
        peer_hart_id: usize,
        suspend_type: u32,
        wake_mode: SuspendWakeMode,
        timeout_ticks: u64,
    ) -> Result<HsmSuspendProbe, FailReason> {
        hsm::probe_secondary_suspend(self, peer_hart_id, suspend_type, wake_mode, timeout_ticks)
    }

    /// Delivers an IPI using `(hart_mask, hart_mask_base)` and verifies worker trap capture counts.
    pub(crate) fn probe_remote_ipi_delivery(
        &mut self,
        hart_mask: usize,
        hart_mask_base: usize,
        expected_workers: usize,
    ) -> Result<(SbiRet, usize), FailReason> {
        let online = self.online_harts();
        if online < 2 {
            return Err(FailReason::HardwareInconsistent);
        }
        let timeout = self.timebase_hz().saturating_mul(2).max(1);
        let guard = self.configure_worker_ipi_mode(online, TrapHookMode::IpiCapture)?;
        let ret = sbi::spi::send_ipi(hart_mask, hart_mask_base);
        let mut received = 0usize;
        if ret.error == 0 {
            let wait_res = guard.wait_until(timeout, || {
                let mut count = 0usize;
                for slot in 1..online {
                    if trap::read_slot_hook_flag(slot) >= 1 {
                        count += 1;
                    }
                }
                received = count;
                count >= expected_workers
            });
            let fin_res = guard.finish();
            fin_res?;
            wait_res?;
            return Ok((ret, received));
        }
        guard.finish()?;
        Ok((ret, 0))
    }

    /// Verifies remote `SFENCE.VMA` (or `SFENCE.VMA_ASID`) visibly invalidates stale worker TLBs.
    pub(crate) fn probe_remote_sfence_visibility(
        &mut self,
        use_asid: bool,
    ) -> Result<(SbiRet, bool), FailReason> {
        if self.online_harts() < 2 {
            return Err(FailReason::HardwareInconsistent);
        }
        let (mask, base) = self
            .workers_hart_mask()
            .ok_or(FailReason::HardwareInconsistent)?;
        let mut guard = self.enable_sv39()?;
        let target_va = guard.target_page_addr();
        let cfg = guard.cfg();
        let asid = guard.sv39_asid();

        let before = match guard.read_u64_on_worker(1, target_va) {
            Ok(val) => val,
            Err(err) => {
                let _ = guard.finish();
                return Err(err);
            }
        };

        // SAFETY: Remaps `target_va` -> `RFENCE_ALT_PAGE` exclusively while `guard` is active.
        unsafe { mmu::remap_target_page_to_alt(&cfg) };

        let ret = if use_asid {
            sbi::rfnc::remote_sfence_vma_asid(mask, base, target_va, 4096, asid)
        } else {
            sbi::rfnc::remote_sfence_vma(mask, base, target_va, 4096)
        };

        let after_res = guard.read_u64_on_worker(1, target_va);

        // SAFETY: Always restore identity PTE and flush worker TLBs before dropping `Sv39Guard`.
        unsafe { mmu::restore_target_page_identity(&cfg) };
        let _ = sbi::rfnc::remote_sfence_vma(mask, base, target_va, 4096);
        guard.finish()?;

        let after = after_res?;
        Ok((
            ret,
            before == mmu::TARGET_PAGE_SENTINEL && after == mmu::ALT_PAGE_SENTINEL,
        ))
    }

    /// Grants exclusive BSP access to the misaligned load/store probe buffer.
    pub(crate) fn misalign_probe(&mut self) -> MisalignProbe<'_> {
        MisalignProbe::new(self)
    }

    /// Registers `EVENT_LOCAL_SOFTWARE` on BSP and returns an RAII [`SseSession`].
    pub(crate) fn register_local_sse(&mut self) -> Result<SseSession<'_>, SbiError> {
        SseSession::register_local(self)
    }

    /// Probes `ATTR_STATUS` of `EVENT_LOCAL_SOFTWARE` prior to registration.
    pub(crate) fn probe_sse_local_status(&mut self) -> Result<usize, SbiError> {
        sse::probe_local_status(self)
    }

    /// Probes reading attributes for an unknown SSE event using exclusive scratch shmem.
    pub(crate) fn probe_sse_unknown_event(&mut self) -> SbiRet {
        sse::probe_unknown_event(self)
    }

    /// Executes `sbi_system_suspend` exclusively from single-hart BSP state.
    pub(crate) fn system_suspend(&mut self, sleep_type: u32) -> Result<isize, FailReason> {
        susp::call_system_suspend(self, sleep_type)
    }

    /// Starts a single-instance secondary HSM suspend worker for `peer_hart_id`.
    pub(crate) fn start_hsm_suspend_worker(
        &mut self,
        peer_hart_id: usize,
        suspend_type: u32,
        timeout_ticks: u64,
    ) -> Result<Option<HsmSuspendWorker<'_>>, FailReason> {
        HsmSuspendWorker::start(self, peer_hart_id, suspend_type, timeout_ticks)
    }

    /// Configures worker IPI hook mode on slot `1..end_slot` with RAII restoration on finish/drop.
    pub(crate) fn configure_worker_ipi_mode(
        &mut self,
        end_slot: usize,
        mode: TrapHookMode,
    ) -> Result<WorkerIpiModeGuard<'_>, FailReason> {
        let online = self.online_harts();
        if end_slot < 2 || end_slot > online {
            return Err(FailReason::HardwareInconsistent);
        }
        let avail = self.availability();
        let boot_hart = self.info.boot_hart_id;
        for slot in 1..end_slot {
            if let Err(err) = self.harts.set_worker_ipi_mode(slot, mode, avail, boot_hart) {
                for undo in 1..slot {
                    let _ = self
                        .harts
                        .set_worker_ipi_mode(undo, TrapHookMode::None, avail, 0);
                }
                return Err(err);
            }
        }
        Ok(WorkerIpiModeGuard {
            platform: self,
            end_slot,
            active: true,
        })
    }

    /// Resets and audits S-mode state between benchmark/check cases, returning warning count.
    pub(crate) fn quarantine_reset(&mut self) -> usize {
        let mut warnings = 0usize;

        // 1. Disable interrupts and clear pending software interrupt bit.
        // SAFETY: Executed sequentially by BSP at case boundary.
        unsafe {
            sstatus::clear_sie();
            sie::write(sie::Sie::from_bits(0));
            sip::clear_ssoft();
        }

        // 2. Cancel any leftover timer deadline.
        if self.caps.extensions.contains_ext(SbiExtensionId::Time) {
            let _ = timer::clear_timer(TimerMode::Sbi);
        }
        if self.info.has_sstc {
            // SAFETY: `self.info.has_sstc` was verified at boot via `probe_stimecmp_writable()`.
            unsafe { timer::clear_timer_sstc_direct() };
        }

        // 3. Ensure Sv39 is torn down across all online harts and flag prior partial faults.
        if self.sv39_faulted {
            warnings += 1;
        }
        if (self.sv39_active || mmu::is_sv39_active() || self.sv39_faulted)
            && self.disable_sv39_all_harts_checked().is_err()
        {
            warnings += 1;
        }

        // 4. Restore default S-mode trap vector and clear any active hooks.
        if !trap::is_default_stvec() {
            warnings += 1;
        }
        // SAFETY: BSP `tp` points to `HART_LOCALS[0]`.
        unsafe { trap::init_on_current_hart() };

        // 5. Reset worker IPI hooks if secondary workers are parked.
        if self.harts.is_poisoned() || self.harts.dedicated_worker_active() {
            warnings += 1;
        } else {
            let avail = self.counters.availability();
            for idx in 1..self.harts.online_harts() {
                if self
                    .harts
                    .set_worker_ipi_mode(idx, TrapHookMode::None, avail, 0)
                    .is_err()
                {
                    warnings += 1;
                }
            }
        }

        // 6. Audit shared-memory pool lease/poison, DBTR leak, and PMU taint state.
        if self.shmem.is_poisoned()
            || self.shmem.is_registered()
            || self.shmem.has_leaked_dbtr_trigger()
            || self.has_tainted_pmu_counters()
        {
            warnings += 1;
        }

        // 7. Audit residual sip.STIP / sip.SSIP.
        if timer::is_timer_pending() || trap::is_ssip_pending() {
            warnings += 1;
        }

        warnings
    }

    /// Requests system shutdown via SBI SRST (if available) and halts forever.
    pub(crate) fn shutdown(&self) -> ! {
        if self.caps.extensions.contains_ext(SbiExtensionId::Srst) {
            let _ = sbi::srst::system_reset(
                sbi::srst::ResetType::Shutdown,
                sbi::srst::ResetReason::NoReason,
            );
        }
        loop {
            riscv::asm::wfi();
        }
    }
}

impl Clock for Platform {
    fn snap_begin(&self) -> CounterSnap {
        self.counters.snap_begin()
    }

    fn snap_end(&self) -> CounterSnap {
        self.counters.snap_end()
    }

    fn read_cycles(&self) -> u64 {
        self.counters.read_cycles()
    }

    fn read_ticks(&self) -> u64 {
        self.counters.read_ticks()
    }

    fn availability(&self) -> CounterAvailability {
        self.counters.availability()
    }

    fn timebase_hz(&self) -> u64 {
        self.counters.timebase_hz()
    }
}

impl HartTopology for Platform {
    fn total_harts(&self) -> usize {
        <HsmHartPool as HartTopology>::total_harts(&self.harts)
    }
}

impl HartCoordinator for Platform {
    fn online_harts(&self) -> usize {
        self.harts.online_harts()
    }

    fn run_parallel(
        &mut self,
        parallel: usize,
        iters: u64,
        work_fn: ParallelWorkFn,
        out_samples: &mut [ParallelSample],
    ) -> Result<(), FailReason> {
        self.harts
            .run_parallel(parallel, iters, work_fn, out_samples)
    }
}
