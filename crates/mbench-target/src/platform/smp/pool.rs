//! Multi-hart worker pool state machine and parallel-run coordination.

use core::sync::atomic::Ordering;

use mbench_core::{
    engine::{CounterSnap, HartCoordinator, ParallelSample, ParallelWorkFn},
    record::{CounterAvailability, FailReason, HartTopology},
};

use super::{
    CMD_NONE, CMD_READ_TARGET_PAGE, CMD_RUN_PARALLEL, CMD_SET_IPI_MODE, CMD_SET_SATP, CMD_STOP,
    COUNTER_AVAIL_BITS, READY_BARRIER, START_BARRIER, SV39_CFG, WORKER_OFFLINE, WORKER_PARKED,
    WORKER_STOPPED, barrier_cancel, barrier_epoch, slot_ref,
};
use crate::{
    platform::{
        boot::MAX_HARTS,
        counters,
        dtb::HardwareInfo,
        hsm,
        mmu::SatpTarget,
        trap::{self, TrapHookMode},
    },
    sbi,
};

/// Manages secondary harts across `STOPPED <-> PARKED <-> RUNNING` phases with fault poisoning.
///
/// # Invariants
///
/// - `active_workers` equals the number of started workers currently parked/running.
/// - `slot_started[idx]` is true only while `HART_SLOTS[idx]` is owned by this pool.
/// - `dedicated_worker_hart` is either `None` or a stopped hart not counted in `active_workers`.
/// - `next_epoch` is intentionally wrapping; each mailbox compares the exact epoch value.
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
    pub(crate) fn new(
        info: &HardwareInfo,
        avail: CounterAvailability,
        sv39: crate::platform::mmu::Sv39Config,
    ) -> Self {
        slot_ref(0)
            .hart_id
            .store(info.boot_hart_id, Ordering::Relaxed);
        COUNTER_AVAIL_BITS.store(trap::counter_mask(avail), Ordering::Relaxed);
        // SAFETY: Called once by BSP during boot before any secondary worker hart is started.
        // INVARIANT: `SV39_CFG` is written once before workers can observe it.
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
        assert!(slot_idx < self.total_harts, "hart slot out of bounds");
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
        START_BARRIER.store(barrier_epoch(self.next_epoch), Ordering::Release);

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
            let info_ptr = unsafe { crate::platform::boot::prepare_ap_boot_info(slot_idx) };
            // SAFETY: `mbench_ap_start` expects `(hart_id, info_ptr)` and uses isolated stack & `HartLocal`.
            // CAST: RISC-V entry PC is a `usize`; the symbol is a valid executable S-mode address.
            let ret = unsafe {
                sbi::hsm::hart_start(
                    hid,
                    crate::platform::boot::mbench_ap_start as *const () as usize,
                    info_ptr,
                )
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
            // CAST: the function pointer is published as a register-width address for the worker.
            slot.param0.store(work_fn as usize, Ordering::Relaxed);
            slot.param1.store(iters as usize, Ordering::Relaxed);
            slot.param2.store(parallel, Ordering::Relaxed);
            slot.cmd.store(CMD_RUN_PARALLEL, Ordering::Relaxed);
            slot.epoch.store(ep, Ordering::Release);
        }

        if let Err(err) = self.wait_until(|| READY_BARRIER.load(Ordering::Acquire) == parallel - 1)
        {
            // Cancel the epoch so ready workers exit cleanly rather than spinning on stale state.
            START_BARRIER.store(barrier_cancel(ep), Ordering::Release);
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

        START_BARRIER.store(barrier_epoch(ep), Ordering::Release);

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
