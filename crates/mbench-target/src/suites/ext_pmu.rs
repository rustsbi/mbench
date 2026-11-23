//! SBI PMU extension benchmarks using firmware/programmable counters (`pmu/*`).

use mbench_core::{
    engine::{
        BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, Clock, CounterSnap, FinishedBench,
    },
    record::{
        BenchGroup, CounterAvailability, FailReason, HartTopology, SbiExtensionId, SkipReason,
    },
};

use crate::{
    mbench_loop,
    platform::{
        Platform,
        shmem::{ShmemAcquire, ShmemOwner},
    },
    sbi::{self, SbiError},
};

/// Exclusive RAII guard for a configured SBI PMU counter, resetting on finish or drop when configured.
#[must_use = "PmuCounterGuard should be finished explicitly to propagate PMU stop errors"]
pub(crate) struct PmuCounterGuard<'a> {
    platform: &'a mut Platform,
    idx: usize,
    configured: bool,
    running: bool,
    active: bool,
}

impl<'a> PmuCounterGuard<'a> {
    const fn adopt_configured(platform: &'a mut Platform, returned_idx: usize) -> Self {
        Self {
            platform,
            idx: returned_idx,
            configured: true,
            running: false,
            active: true,
        }
    }

    pub(crate) fn probe_config_matching_and_cleanup(
        platform: &mut Platform,
        idx_base: usize,
        idx_mask: usize,
        config_flags: usize,
        event_idx: usize,
        event_data: u64,
    ) -> (sbi::SbiRet, Result<(), FailReason>) {
        let ret = sbi::pmu::counter_config_matching(
            idx_base,
            idx_mask,
            config_flags,
            event_idx,
            event_data,
        );
        let cleanup = if ret.error == 0 {
            PmuCounterGuard::adopt_configured(platform, ret.value).finish_reset()
        } else {
            Ok(())
        };
        (ret, cleanup)
    }

    pub(crate) fn try_configure_firmware(
        platform: &'a mut Platform,
        event_idx: usize,
    ) -> Result<Option<Self>, FailReason> {
        let count = sbi::into_result(sbi::pmu::num_counters())
            .map_err(|e| FailReason::UnexpectedSbiError(e.as_code()))?;
        for idx in 0..count {
            if platform.is_pmu_counter_tainted(idx) {
                continue;
            }
            let info = match sbi::into_result(sbi::pmu::counter_get_info(idx)) {
                Ok(v) => v,
                // Counter index 1 (`time`) and unimplemented HW slots return `INVALID_PARAM`.
                Err(SbiError::InvalidParam) => continue,
                Err(err) => return Err(FailReason::UnexpectedSbiError(err.as_code())),
            };
            if !sbi::pmu::info_is_firmware(info) {
                continue;
            }
            let cfg = sbi::pmu::counter_config_matching(idx, 1, 0, event_idx, 0);
            if cfg.error != 0 {
                let code = sbi::error_code(cfg);
                if code == SbiError::NotSupported.as_code() {
                    continue;
                }
                return Err(FailReason::UnexpectedSbiError(code));
            }
            let guard = Self::adopt_configured(platform, cfg.value);
            if cfg.value != idx {
                guard.finish_reset()?;
                return Err(FailReason::HardwareInconsistent);
            }
            let matched_info = match sbi::into_result(sbi::pmu::counter_get_info(guard.idx())) {
                Ok(v) => v,
                Err(err) => {
                    guard.finish_reset()?;
                    return Err(FailReason::UnexpectedSbiError(err.as_code()));
                }
            };
            if !sbi::pmu::info_is_firmware(matched_info) {
                guard.finish_reset()?;
                return Err(FailReason::HardwareInconsistent);
            }
            return Ok(Some(guard));
        }
        Ok(None)
    }

    pub(crate) fn try_configure_hw(platform: &'a mut Platform) -> Result<Option<Self>, FailReason> {
        let count = sbi::into_result(sbi::pmu::num_counters())
            .map_err(|e| FailReason::UnexpectedSbiError(e.as_code()))?;
        for event in [
            sbi::pmu::HW_CACHE_BPU_READ_MISS,
            sbi::pmu::HW_BRANCH_INSTRUCTIONS,
            sbi::pmu::HW_CACHE_REFERENCES,
        ] {
            for idx in 0..count {
                if platform.is_pmu_counter_tainted(idx) {
                    continue;
                }
                let info = match sbi::into_result(sbi::pmu::counter_get_info(idx)) {
                    Ok(v) => v,
                    Err(SbiError::InvalidParam) => continue,
                    Err(err) => return Err(FailReason::UnexpectedSbiError(err.as_code())),
                };
                // Never reconfigure or stop fixed counters (`cycle = 0xc00`, `time = 0xc01`, `instret = 0xc02`).
                if sbi::pmu::info_is_firmware(info) || sbi::pmu::info_csr(info) < 0x0c03 {
                    continue;
                }
                let cfg = sbi::pmu::counter_config_matching(idx, 1, 0, event, 0);
                if cfg.error != 0 {
                    let code = sbi::error_code(cfg);
                    if code == SbiError::NotSupported.as_code() {
                        continue;
                    }
                    return Err(FailReason::UnexpectedSbiError(code));
                }
                let guard = Self::adopt_configured(platform, cfg.value);
                if cfg.value != idx {
                    guard.finish_reset()?;
                    return Err(FailReason::HardwareInconsistent);
                }
                let matched_info = match sbi::into_result(sbi::pmu::counter_get_info(guard.idx())) {
                    Ok(v) => v,
                    Err(err) => {
                        guard.finish_reset()?;
                        return Err(FailReason::UnexpectedSbiError(err.as_code()));
                    }
                };
                if sbi::pmu::info_is_firmware(matched_info)
                    || sbi::pmu::info_csr(matched_info) < 0x0c03
                {
                    guard.finish_reset()?;
                    return Err(FailReason::HardwareInconsistent);
                }
                return Ok(Some(guard));
            }
        }
        Ok(None)
    }

    pub(crate) const fn idx(&self) -> usize {
        self.idx
    }

    pub(crate) const fn is_configured(&self) -> bool {
        self.configured
    }

    fn adopt_reconfigured(&mut self, returned_idx: usize) -> Result<(), FailReason> {
        if self.configured || returned_idx != self.idx {
            PmuCounterGuard::adopt_configured(self.platform, returned_idx).finish_reset()?;
            return Err(FailReason::HardwareInconsistent);
        }
        self.configured = true;
        self.running = false;
        Ok(())
    }

    pub(crate) fn reconfigure_with_flags(
        &mut self,
        config_flags: usize,
        event_idx: usize,
        event_data: u64,
    ) -> (sbi::SbiRet, Result<(), FailReason>) {
        let ret =
            sbi::pmu::counter_config_matching(self.idx, 1, config_flags, event_idx, event_data);
        let adopt = if ret.error == 0 {
            self.adopt_reconfigured(ret.value)
        } else {
            Ok(())
        };
        (ret, adopt)
    }

    pub(crate) fn mark_running(&mut self) {
        self.configured = true;
        self.running = true;
    }

    pub(crate) fn mark_stopped(&mut self) {
        self.running = false;
    }

    pub(crate) fn stop_and_reset(&mut self) -> Result<(), FailReason> {
        self.reset_inner()
    }

    /// Stops and resets a running counter, failing and tainting on any error.
    pub(crate) fn finish_running(mut self) -> Result<(), FailReason> {
        self.active = false;
        if !self.configured {
            return Ok(());
        }
        let ret = sbi::pmu::counter_stop(self.idx, 1, sbi::pmu::stop_flags::RESET);
        if ret.error == 0 {
            self.configured = false;
            self.running = false;
            Ok(())
        } else {
            self.running = true;
            self.platform.taint_pmu_counter(self.idx);
            Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)))
        }
    }

    /// Stops and resets an active counter configuration, keeping it tainted if reset fails.
    pub(crate) fn finish_reset(mut self) -> Result<(), FailReason> {
        self.active = false;
        self.reset_inner()
    }

    fn reset_inner(&mut self) -> Result<(), FailReason> {
        if !self.configured {
            return Ok(());
        }
        if !self.running {
            let st = sbi::pmu::counter_start(self.idx, 1, 0, 0);
            if st.error != 0 && sbi::error_code(st) != SbiError::AlreadyStarted.as_code() {
                self.platform.taint_pmu_counter(self.idx);
                return Err(FailReason::UnexpectedSbiError(sbi::error_code(st)));
            }
            self.running = true;
        }
        let ret = sbi::pmu::counter_stop(self.idx, 1, sbi::pmu::stop_flags::RESET);
        if ret.error == 0 {
            self.configured = false;
            self.running = false;
            Ok(())
        } else {
            self.platform.taint_pmu_counter(self.idx);
            Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)))
        }
    }
}

impl Drop for PmuCounterGuard<'_> {
    fn drop(&mut self) {
        if self.active && self.configured {
            let _ = self.reset_inner();
            self.active = false;
        }
    }
}

impl Clock for PmuCounterGuard<'_> {
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

impl HartTopology for PmuCounterGuard<'_> {
    fn total_harts(&self) -> usize {
        self.platform.total_harts()
    }
}

/// Declarative SBI PMU benchmark suite (8 specs).
pub(crate) static SPECS: &[BenchSpec<Platform>] = &[
    pmu_spec("pmu/num_counters", run_pmu_num),
    pmu_spec("pmu/get_info", run_pmu_info),
    pmu_spec("pmu/config_matching", run_pmu_config),
    pmu_spec("pmu/start", run_pmu_start),
    pmu_spec("pmu/stop", run_pmu_stop),
    pmu_spec("pmu/fw_read", run_pmu_fw_read),
    pmu_spec("pmu/snapshot_set_shmem", run_pmu_snapshot_shmem),
    pmu_spec("pmu/hw_counter", run_pmu_hw_counter),
];

const fn pmu_spec(
    id: &'static str,
    run: fn(&mut Platform, BenchRun<'_, '_, '_, '_>) -> FinishedBench,
) -> BenchSpec<Platform> {
    BenchSpec {
        meta: BenchMeta {
            id,
            group: BenchGroup::Pmu,
            unit: "call",
            required_ext: Some(SbiExtensionId::Pmu),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run,
    }
}

fn run_pmu_num(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::pmu::num_counters();
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::pmu::num_counters();
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_pmu_info(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let count = sbi::pmu::num_counters();
    if count.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(count)));
    }
    if count.value == 0 {
        return run.skip(SkipReason::NoUsableResource);
    }
    let ret = sbi::pmu::counter_get_info(0);
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::pmu::counter_get_info(0);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_pmu_config(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut guard = match PmuCounterGuard::try_configure_firmware(env, sbi::pmu::FW_SET_TIMER) {
        Ok(Some(g)) => g,
        Ok(None) => return run.skip(SkipReason::NoUsableResource),
        Err(err) => return run.fail(err),
    };
    if let Err(err) = guard.stop_and_reset() {
        return run.fail(err);
    }

    let idx = guard.idx();
    let pending = run.measure_paired(&mut guard, |g| {
        let t0 = g.snap_begin();
        let ret = sbi::pmu::counter_config_matching(idx, 1, 0, sbi::pmu::FW_SET_TIMER, 0);
        let t1 = g.snap_end();
        if ret.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }
        g.adopt_reconfigured(ret.value)?;
        g.stop_and_reset()?;
        Ok(CounterSnap::delta(t1, t0))
    });
    pending.finish_with(guard.finish_reset())
}

fn run_pmu_start(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut guard = match PmuCounterGuard::try_configure_firmware(env, sbi::pmu::FW_SET_TIMER) {
        Ok(Some(g)) => g,
        Ok(None) => return run.skip(SkipReason::NoUsableResource),
        Err(err) => return run.fail(err),
    };
    let idx = guard.idx();
    let pending = run.measure_paired(&mut guard, |g| {
        let t0 = g.snap_begin();
        let ret = sbi::pmu::counter_start(idx, 1, 1, 0);
        let t1 = g.snap_end();
        if ret.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }
        g.mark_running();
        let stop = sbi::pmu::counter_stop(idx, 1, 0);
        if stop.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(stop)));
        }
        g.mark_stopped();
        Ok(CounterSnap::delta(t1, t0))
    });
    pending.finish_with(guard.finish_reset())
}

fn run_pmu_stop(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut guard = match PmuCounterGuard::try_configure_firmware(env, sbi::pmu::FW_SET_TIMER) {
        Ok(Some(g)) => g,
        Ok(None) => return run.skip(SkipReason::NoUsableResource),
        Err(err) => return run.fail(err),
    };
    let idx = guard.idx();
    let pending = run.measure_paired(&mut guard, |g| {
        let st = sbi::pmu::counter_start(idx, 1, 1, 0);
        if st.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(st)));
        }
        g.mark_running();
        let t0 = g.snap_begin();
        let ret = sbi::pmu::counter_stop(idx, 1, 0);
        let t1 = g.snap_end();
        if ret.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }
        g.mark_stopped();
        Ok(CounterSnap::delta(t1, t0))
    });
    pending.finish_with(guard.finish_reset())
}

fn run_pmu_fw_read(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut guard = match PmuCounterGuard::try_configure_firmware(env, sbi::pmu::FW_SET_TIMER) {
        Ok(Some(g)) => g,
        Ok(None) => return run.skip(SkipReason::NoUsableResource),
        Err(err) => return run.fail(err),
    };
    let idx = guard.idx();
    let st = sbi::pmu::counter_start(idx, 1, 1, 0);
    if st.error != 0 {
        let _ = guard.finish_reset();
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(st)));
    }
    guard.mark_running();
    let probe = sbi::pmu::counter_fw_read(idx);
    if probe.error != 0 {
        let _ = guard.finish_running();
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(probe)));
    }

    let pending = run.measure_batched(&mut guard, |_g, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::pmu::counter_fw_read(idx);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    });
    pending.finish_with(guard.finish_running())
}

fn run_pmu_snapshot_shmem(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut lease = match env.lease_shmem(ShmemOwner::PmuSnapshot) {
        Ok(ShmemAcquire::Leased(l)) => l,
        Ok(ShmemAcquire::Unsupported) => return run.skip(SkipReason::FunctionUnsupported),
        Ok(ShmemAcquire::TooLarge) => return run.skip(SkipReason::ShmemTooLarge),
        Err(err) => return run.fail(err),
    };
    let pending = run.measure_batched(&mut lease, |l, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = l.reregister();
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    });
    pending.finish_with(lease.finish())
}

fn run_pmu_hw_counter(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut guard = match PmuCounterGuard::try_configure_hw(env) {
        Ok(Some(g)) => g,
        Ok(None) => return run.skip(SkipReason::NoUsableResource),
        Err(err) => return run.fail(err),
    };
    let idx = guard.idx();
    let st = sbi::pmu::counter_start(idx, 1, 1, 0);
    if st.error != 0 {
        let _ = guard.finish_reset();
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(st)));
    }
    guard.mark_running();
    let sp = sbi::pmu::counter_stop(idx, 1, 0);
    if sp.error != 0 {
        let _ = guard.finish_running();
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(sp)));
    }
    guard.mark_stopped();

    let pending = run.measure_paired(&mut guard, |g| {
        let t0 = g.snap_begin();
        let st = sbi::pmu::counter_start(idx, 1, 1, 0);
        if st.error == 0 {
            g.mark_running();
        }
        let sp = sbi::pmu::counter_stop(idx, 1, 0);
        let t1 = g.snap_end();
        if st.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(st)));
        }
        if sp.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(sp)));
        }
        g.mark_stopped();
        Ok(CounterSnap::delta(t1, t0))
    });
    pending.finish_with(guard.finish_reset())
}
