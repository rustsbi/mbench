//! RAII guards that temporarily change platform-wide Sv39 or worker-IPI state.

use mbench_core::{
    engine::{Clock, HartCoordinator, ParallelSample, ParallelWorkFn},
    record::FailReason,
};

use crate::platform::{
    Platform, impl_platform_clock_topology, mmu::Sv39Config, trap::TrapHookMode,
};

/// RAII guard activating Sv39 identity mapping across all online harts and restoring `Bare` on finish/drop.
///
/// Does not implement `DerefMut<Target = Platform>` to prevent re-entrant `enable_sv39()` calls.
#[clippy::has_significant_drop]
#[must_use = "Sv39Guard should be explicitly finished to check remote teardown results"]
pub(crate) struct Sv39Guard<'a> {
    pub(super) platform: &'a mut Platform,
    pub(super) active: bool,
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

impl_platform_clock_topology!(Sv39Guard<'_>);

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
#[clippy::has_significant_drop]
#[must_use = "WorkerIpiModeGuard should be explicitly finished to reset worker hook modes"]
pub(crate) struct WorkerIpiModeGuard<'a> {
    pub(super) platform: &'a mut Platform,
    pub(super) end_slot: usize,
    pub(super) active: bool,
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

    pub(crate) fn install_self_ipi_capture(
        &self,
    ) -> Result<crate::platform::trap::IpiCaptureHookGuard, FailReason> {
        crate::platform::trap::IpiCaptureHookGuard::install(self.platform.availability())
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

impl_platform_clock_topology!(WorkerIpiModeGuard<'_>);
