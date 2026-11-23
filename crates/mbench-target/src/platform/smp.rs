//! Cache-line-isolated multi-hart worker pool synchronized via SBI HSM and cancellable barriers.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use mbench_core::{
    engine::{CounterSnap, HartCoordinator, ParallelSample, ParallelWorkFn},
    record::{CounterAvailability, FailReason, HartTopology},
};
use riscv::register::{sie, sip, sstatus};

use crate::{
    platform::{
        boot::{self, MAX_HARTS, SyncUnsafeCell},
        counters,
        dtb::HardwareInfo,
        hsm,
        mmu::{self, SatpTarget, Sv39Config},
        trap::{self, TrapHookMode},
    },
    sbi,
};

const CMD_NONE: usize = 0;
const CMD_RUN_PARALLEL: usize = 1;
const CMD_SET_SATP: usize = 2;
const CMD_SET_IPI_MODE: usize = 3;
const CMD_STOP: usize = 4;
const CMD_READ_TARGET_PAGE: usize = 5;

const WORKER_OFFLINE: usize = 0;
const WORKER_PARKED: usize = 1;
const WORKER_STOPPED: usize = 2;

#[repr(C, align(64))]
struct HartSlot {
    hart_id: AtomicUsize,
    cmd: AtomicUsize,
    epoch: AtomicUsize,
    param0: AtomicUsize,
    param1: AtomicUsize,
    param2: AtomicUsize,
    done_epoch: AtomicUsize,
    state: AtomicUsize,
    sample_cycles: AtomicU64,
    sample_instret: AtomicU64,
    sample_ticks: AtomicU64,
    sample_errors: AtomicUsize,
    probe_val: AtomicU64,
}

impl HartSlot {
    const fn new() -> Self {
        Self {
            hart_id: AtomicUsize::new(0),
            cmd: AtomicUsize::new(CMD_NONE),
            epoch: AtomicUsize::new(0),
            param0: AtomicUsize::new(0),
            param1: AtomicUsize::new(0),
            param2: AtomicUsize::new(0),
            done_epoch: AtomicUsize::new(0),
            state: AtomicUsize::new(WORKER_OFFLINE),
            sample_cycles: AtomicU64::new(0),
            sample_instret: AtomicU64::new(0),
            sample_ticks: AtomicU64::new(0),
            sample_errors: AtomicUsize::new(0),
            probe_val: AtomicU64::new(0),
        }
    }
}

static HART_SLOTS: SyncUnsafeCell<[HartSlot; MAX_HARTS]> =
    SyncUnsafeCell::new([const { HartSlot::new() }; MAX_HARTS]);
static READY_BARRIER: AtomicUsize = AtomicUsize::new(0);
// Bit 0 encodes cancellation (1 = abort/skip work, 0 = execute), upper bits encode `epoch`.
static START_BARRIER: AtomicUsize = AtomicUsize::new(0);
static COUNTER_AVAIL_BITS: AtomicUsize = AtomicUsize::new(0);
static SV39_CFG: SyncUnsafeCell<Option<Sv39Config>> = SyncUnsafeCell::new(None);

#[inline(always)]
fn slot_ref(slot_idx: usize) -> &'static HartSlot {
    debug_assert!(slot_idx < MAX_HARTS);
    // SAFETY: `HART_SLOTS` is `'static` and each slot is cache-line aligned.
    unsafe { &(*HART_SLOTS.get())[slot_idx] }
}

/// Returns the hardware hart ID assigned to pool slot `slot_idx`.
pub(crate) fn slot_hart_id(slot_idx: usize) -> usize {
    slot_ref(slot_idx.min(MAX_HARTS - 1))
        .hart_id
        .load(Ordering::Relaxed)
}

/// Samples counters at batch entry safely from any worker or BSP using probed availability.
pub(crate) fn worker_snap_begin() -> CounterSnap {
    counters::snap_begin_with_mask(COUNTER_AVAIL_BITS.load(Ordering::Relaxed))
}

/// Samples counters at batch exit safely from any worker or BSP using probed availability.
pub(crate) fn worker_snap_end() -> CounterSnap {
    counters::snap_end_with_mask(COUNTER_AVAIL_BITS.load(Ordering::Relaxed))
}

/// Manages secondary harts across `STOPPED <-> PARKED <-> RUNNING` phases with fault poisoning.
pub(crate) struct HsmHartPool {
    hart_ids: [usize; MAX_HARTS],
    total_harts: usize,
    active_workers: usize,
    slot_started: [bool; MAX_HARTS],
    dedicated_worker_hart: Option<usize>,
    poisoned: bool,
    next_epoch: usize,
    timebase_hz: u64,
    has_time: bool,
}

impl HsmHartPool {
    /// Creates a new pool from parsed FDT topology; starts in single-hart state until Phase 3.
    pub(crate) fn new(info: &HardwareInfo, avail: CounterAvailability, sv39: Sv39Config) -> Self {
        slot_ref(0)
            .hart_id
            .store(info.boot_hart_id, Ordering::Relaxed);
        COUNTER_AVAIL_BITS.store(trap::counter_mask(avail), Ordering::Relaxed);
        // SAFETY: Called once by BSP during boot before any secondary worker hart is started.
        unsafe { *SV39_CFG.get() = Some(sv39) };
        Self {
            hart_ids: info.hart_ids,
            total_harts: info.hart_count,
            active_workers: 0,
            slot_started: [false; MAX_HARTS],
            dedicated_worker_hart: None,
            poisoned: false,
            next_epoch: 0,
            timebase_hz: info.timebase_hz,
            has_time: avail.has_time,
        }
    }

    /// Returns the hart ID at slot `slot_idx` (`0` is always the boot hart).
    pub(crate) fn hart_id(&self, slot_idx: usize) -> usize {
        self.hart_ids[slot_idx]
    }

    pub(crate) const fn online_harts_count(&self) -> usize {
        self.active_workers + 1
    }

    pub(crate) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) fn mark_poisoned(&mut self) {
        self.poisoned = true;
    }

    pub(in crate::platform) const fn dedicated_worker_active(&self) -> bool {
        self.dedicated_worker_hart.is_some()
    }

    pub(in crate::platform) fn claim_dedicated_worker(
        &mut self,
        hart_id: usize,
    ) -> Result<(), FailReason> {
        if self.poisoned || self.active_workers != 0 || self.dedicated_worker_hart.is_some() {
            return Err(FailReason::HardwareInconsistent);
        }
        self.dedicated_worker_hart = Some(hart_id);
        Ok(())
    }

    pub(in crate::platform) fn release_dedicated_worker(&mut self) {
        self.dedicated_worker_hart = None;
    }

    /// Starts up to `max_total_harts` (capped at `total_harts`) secondary harts into the parked pool.
    pub(crate) fn bringup_up_to(&mut self, max_total_harts: usize) -> Result<usize, FailReason> {
        if self.poisoned || self.dedicated_worker_hart.is_some() {
            return Err(FailReason::HardwareInconsistent);
        }
        let target_total = self.total_harts.min(max_total_harts);
        if target_total <= 1 {
            self.active_workers = 0;
            return Ok(1);
        }
        READY_BARRIER.store(0, Ordering::Release);
        START_BARRIER.store(self.next_epoch << 1, Ordering::Release);

        let mut online = 1usize;
        for slot_idx in 1..target_total {
            let slot = slot_ref(slot_idx);
            let hid = self.hart_ids[slot_idx];
            slot.hart_id.store(hid, Ordering::Relaxed);
            slot.cmd.store(CMD_NONE, Ordering::Relaxed);
            slot.epoch.store(self.next_epoch, Ordering::Relaxed);
            slot.done_epoch.store(self.next_epoch, Ordering::Relaxed);
            slot.state.store(WORKER_OFFLINE, Ordering::Release);

            // SAFETY: Slot `slot_idx` is STOPPED; BSP owns `AP_BOOT_INFO[slot_idx]` exclusively.
            let info_ptr = unsafe { boot::prepare_ap_boot_info(slot_idx) };
            // SAFETY: `mbench_ap_start` expects `(hart_id, info_ptr)` and uses isolated stack & `HartLocal`.
            let ret = unsafe {
                sbi::hsm::hart_start(hid, boot::mbench_ap_start as *const () as usize, info_ptr)
            };
            if ret.error != 0 {
                let _ = self.stop_all();
                return Err(FailReason::SecondaryHartError(sbi::error_code(ret)));
            }
            self.slot_started[slot_idx] = true;
            if let Err(err) =
                self.wait_until(|| slot.state.load(Ordering::Acquire) == WORKER_PARKED)
            {
                self.poisoned = true;
                return Err(err);
            }
            online += 1;
            self.active_workers = online - 1;
        }
        Ok(online)
    }

    /// Broadcasts `SatpTarget` (`Bare` or static identity `Sv39`) to all active secondary workers.
    pub(in crate::platform) fn set_satp_all_workers(
        &mut self,
        target: SatpTarget,
    ) -> Result<(), FailReason> {
        if self.active_workers == 0 {
            return Ok(());
        }
        if self.poisoned {
            return Err(FailReason::HardwareInconsistent);
        }
        let mode_arg = match target {
            SatpTarget::Bare => 0usize,
            SatpTarget::Sv39(_) => 1usize,
        };
        self.next_epoch = self.next_epoch.wrapping_add(1);
        let ep = self.next_epoch;
        for idx in 1..=self.active_workers {
            let slot = slot_ref(idx);
            slot.param0.store(mode_arg, Ordering::Relaxed);
            slot.cmd.store(CMD_SET_SATP, Ordering::Relaxed);
            slot.epoch.store(ep, Ordering::Release);
        }
        for idx in 1..=self.active_workers {
            let slot = slot_ref(idx);
            if let Err(err) = self.wait_until(|| slot.done_epoch.load(Ordering::Acquire) == ep) {
                self.poisoned = true;
                return Err(err);
            }
        }
        Ok(())
    }

    /// Configures S-mode software interrupt hook mode on worker `slot_idx`.
    pub(crate) fn set_worker_ipi_mode(
        &mut self,
        slot_idx: usize,
        hook_mode: TrapHookMode,
        avail: CounterAvailability,
        bounce_target_hart: usize,
    ) -> Result<(), FailReason> {
        if self.poisoned || slot_idx == 0 || slot_idx > self.active_workers {
            return Err(FailReason::HardwareInconsistent);
        }
        self.next_epoch = self.next_epoch.wrapping_add(1);
        let ep = self.next_epoch;
        let slot = slot_ref(slot_idx);
        slot.param0.store(hook_mode as usize, Ordering::Relaxed);
        slot.param1
            .store(trap::counter_mask(avail), Ordering::Relaxed);
        slot.param2.store(bounce_target_hart, Ordering::Relaxed);
        slot.cmd.store(CMD_SET_IPI_MODE, Ordering::Relaxed);
        slot.epoch.store(ep, Ordering::Release);
        if let Err(err) = self.wait_until(|| slot.done_epoch.load(Ordering::Acquire) == ep) {
            self.poisoned = true;
            return Err(err);
        }
        Ok(())
    }

    /// Orders parked secondary worker `slot_idx` to perform a volatile `u64` read at `addr`.
    pub(in crate::platform) fn read_u64_on_worker(
        &mut self,
        slot_idx: usize,
        addr: usize,
    ) -> Result<u64, FailReason> {
        if self.poisoned || slot_idx == 0 || slot_idx > self.active_workers {
            return Err(FailReason::HardwareInconsistent);
        }
        self.next_epoch = self.next_epoch.wrapping_add(1);
        let ep = self.next_epoch;
        let slot = slot_ref(slot_idx);
        slot.param0.store(addr, Ordering::Relaxed);
        slot.cmd.store(CMD_READ_TARGET_PAGE, Ordering::Relaxed);
        slot.epoch.store(ep, Ordering::Release);
        if let Err(err) = self.wait_until(|| slot.done_epoch.load(Ordering::Acquire) == ep) {
            self.poisoned = true;
            return Err(err);
        }
        Ok(slot.probe_val.load(Ordering::Acquire))
    }

    /// Stops all started secondary workers via `sbi::hsm::hart_stop` and verifies `STOPPED` per hart.
    pub(crate) fn stop_all(&mut self) -> Result<(), FailReason> {
        let mut any_started = false;
        for idx in 1..self.total_harts {
            if self.slot_started[idx] {
                any_started = true;
                break;
            }
        }
        if !any_started {
            self.active_workers = 0;
            return Ok(());
        }

        self.next_epoch = self.next_epoch.wrapping_add(1);
        let ep = self.next_epoch;
        for idx in 1..self.total_harts {
            if self.slot_started[idx] {
                let slot = slot_ref(idx);
                slot.cmd.store(CMD_STOP, Ordering::Relaxed);
                slot.epoch.store(ep, Ordering::Release);
            }
        }

        let mut first_err: Option<FailReason> = None;
        for idx in 1..self.total_harts {
            if !self.slot_started[idx] {
                continue;
            }
            let hid = self.hart_ids[idx];
            match hsm::wait_hart_state(
                hid,
                sbi::hsm::state::STOPPED,
                self.has_time,
                self.timebase_hz.saturating_mul(5),
            ) {
                Ok(()) => {
                    slot_ref(idx).state.store(WORKER_STOPPED, Ordering::Release);
                    self.slot_started[idx] = false;
                }
                Err(err) => {
                    self.poisoned = true;
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }
        if first_err.is_none() {
            self.active_workers = 0;
            Ok(())
        } else {
            Err(first_err.unwrap_or(FailReason::Timeout))
        }
    }

    fn wait_until(&self, cond: impl FnMut() -> bool) -> Result<(), FailReason> {
        counters::wait_until(
            self.has_time,
            self.timebase_hz.saturating_mul(5),
            200_000_000,
            cond,
        )
    }
}

impl HartTopology for HsmHartPool {
    fn total_harts(&self) -> usize {
        self.total_harts
    }
}

impl HartCoordinator for HsmHartPool {
    fn online_harts(&self) -> usize {
        self.active_workers + 1
    }

    fn run_parallel(
        &mut self,
        parallel: usize,
        iters: u64,
        work_fn: ParallelWorkFn,
        out_samples: &mut [ParallelSample],
    ) -> Result<(), FailReason> {
        if self.poisoned
            || parallel == 0
            || parallel > self.online_harts()
            || parallel > out_samples.len()
        {
            return Err(FailReason::HardwareInconsistent);
        }
        if parallel == 1 {
            out_samples[0] = work_fn(0, 1, iters);
            return Ok(());
        }

        self.next_epoch = self.next_epoch.wrapping_add(1);
        let ep = self.next_epoch;
        READY_BARRIER.store(0, Ordering::Release);

        for idx in 1..parallel {
            let slot = slot_ref(idx);
            slot.param0.store(work_fn as usize, Ordering::Relaxed);
            slot.param1.store(iters as usize, Ordering::Relaxed);
            slot.param2.store(parallel, Ordering::Relaxed);
            slot.cmd.store(CMD_RUN_PARALLEL, Ordering::Relaxed);
            slot.epoch.store(ep, Ordering::Release);
        }

        if let Err(err) = self.wait_until(|| READY_BARRIER.load(Ordering::Acquire) == parallel - 1)
        {
            // Cancel the epoch so ready workers exit cleanly rather than spinning on stale state.
            START_BARRIER.store((ep << 1) | 1, Ordering::Release);
            for idx in 1..parallel {
                let slot = slot_ref(idx);
                if self
                    .wait_until(|| slot.done_epoch.load(Ordering::Acquire) == ep)
                    .is_err()
                {
                    self.poisoned = true;
                }
            }
            return Err(err);
        }

        START_BARRIER.store(ep << 1, Ordering::Release);

        out_samples[0] = work_fn(0, parallel, iters);

        for (idx, out_slot) in out_samples.iter_mut().enumerate().take(parallel).skip(1) {
            let slot = slot_ref(idx);
            if let Err(err) = self.wait_until(|| slot.done_epoch.load(Ordering::Acquire) == ep) {
                self.poisoned = true;
                return Err(err);
            }
            *out_slot = ParallelSample {
                delta: CounterSnap {
                    cycles: slot.sample_cycles.load(Ordering::Relaxed),
                    instret: slot.sample_instret.load(Ordering::Relaxed),
                    ticks: slot.sample_ticks.load(Ordering::Relaxed),
                },
                error_bits: slot.sample_errors.load(Ordering::Relaxed),
            };
        }
        Ok(())
    }
}

/// Secondary worker loop entered from [`boot::mbench_ap_start`] with `a0 = hart_id` and `a1 = slot_idx`.
///
/// # Safety
///
/// Must be entered only once per secondary hart start with a unique `slot_idx` in `1..MAX_HARTS`.
#[unsafe(no_mangle)]
unsafe extern "C" fn mbench_ap_rust_entry(_hart_id: usize, slot_idx: usize) -> ! {
    // SAFETY: `mbench_ap_start` initialized `tp` to `&HART_LOCALS[slot_idx]`.
    unsafe { trap::init_on_current_hart() };
    let slot = slot_ref(slot_idx);
    let mut seen_epoch = slot.epoch.load(Ordering::Acquire);
    slot.state.store(WORKER_PARKED, Ordering::Release);

    loop {
        let ep = loop {
            let cur = slot.epoch.load(Ordering::Acquire);
            if cur != seen_epoch {
                break cur;
            }
            core::hint::spin_loop();
        };
        seen_epoch = ep;

        match slot.cmd.load(Ordering::Relaxed) {
            CMD_RUN_PARALLEL => {
                let fn_addr = slot.param0.load(Ordering::Relaxed);
                let iters = slot.param1.load(Ordering::Relaxed) as u64;
                let parallel = slot.param2.load(Ordering::Relaxed);
                // SAFETY: `fn_addr` was written by BSP from a valid `ParallelWorkFn`.
                let work_fn: ParallelWorkFn = unsafe { core::mem::transmute(fn_addr) };

                READY_BARRIER.fetch_add(1, Ordering::AcqRel);
                let barrier = loop {
                    let cur = START_BARRIER.load(Ordering::Acquire);
                    if (cur >> 1) == ep {
                        break cur;
                    }
                    core::hint::spin_loop();
                };
                if (barrier & 1) != 0 {
                    slot.done_epoch.store(ep, Ordering::Release);
                    continue;
                }

                let sample = work_fn(slot_idx, parallel, iters);
                slot.sample_cycles
                    .store(sample.delta.cycles, Ordering::Relaxed);
                slot.sample_instret
                    .store(sample.delta.instret, Ordering::Relaxed);
                slot.sample_ticks
                    .store(sample.delta.ticks, Ordering::Relaxed);
                slot.sample_errors
                    .store(sample.error_bits, Ordering::Relaxed);
                slot.done_epoch.store(ep, Ordering::Release);
            }
            CMD_SET_SATP => {
                let target = if slot.param0.load(Ordering::Relaxed) == 0 {
                    SatpTarget::Bare
                } else {
                    // SAFETY: `SV39_CFG` was initialized by BSP prior to starting secondary harts.
                    let cfg = unsafe { (*SV39_CFG.get()).expect("SV39_CFG initialized at boot") };
                    SatpTarget::Sv39(cfg)
                };
                let _ = mmu::apply(target);
                slot.done_epoch.store(ep, Ordering::Release);
            }
            CMD_SET_IPI_MODE => {
                let mode = TrapHookMode::from_usize(slot.param0.load(Ordering::Relaxed));
                let bounce_target = slot.param2.load(Ordering::Relaxed);
                let mask_val = slot.param1.load(Ordering::Relaxed);
                let avail = CounterAvailability {
                    has_cycle: (mask_val & 1) != 0,
                    has_instret: (mask_val & 2) != 0,
                    has_time: (mask_val & 4) != 0,
                    is_rdtime_emulated: false,
                    is_pmu_gated: false,
                };
                // SAFETY: `tp` is valid and owned exclusively by this worker hart with IRQs disabled first.
                unsafe {
                    sstatus::clear_sie();
                    sie::write(sie::Sie::from_bits(0));
                    sip::clear_ssoft();
                    trap::set_hook_raw(mode, avail, bounce_target);
                    if mode != TrapHookMode::None {
                        sie::set_ssoft();
                        sstatus::set_sie();
                    }
                }
                slot.done_epoch.store(ep, Ordering::Release);
            }
            CMD_STOP => {
                // SAFETY: Disable interrupts and trap hooks before relinquishing hart to SBI HSM.
                unsafe {
                    sstatus::clear_sie();
                    sie::write(sie::Sie::from_bits(0));
                    sip::clear_ssoft();
                    trap::set_hook_raw(TrapHookMode::None, CounterAvailability::default(), 0);
                    let _ = sbi::hsm::hart_stop();
                }
                loop {
                    riscv::asm::wfi();
                }
            }
            CMD_READ_TARGET_PAGE => {
                let addr = slot.param0.load(Ordering::Relaxed);
                // SAFETY: BSP passes identity/Sv39-mapped `RFENCE_TARGET_PAGE` address under `Sv39Guard`.
                let val = unsafe { core::ptr::read_volatile(addr as *const u64) };
                slot.probe_val.store(val, Ordering::Release);
                slot.done_epoch.store(ep, Ordering::Release);
            }
            _ => {
                slot.done_epoch.store(ep, Ordering::Release);
            }
        }
    }
}
