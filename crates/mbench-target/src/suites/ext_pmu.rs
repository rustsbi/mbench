//! SBI PMU extension benchmarks using firmware/programmable counters (`pmu/*`).

use mbench_core::{
    engine::{
        BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, Clock, CounterSnap, FinishedBench,
    },
    record::{BenchGroup, FailReason, SbiExtensionId, SkipReason},
};

use super::run_shmem_reregister;
pub(crate) use crate::platform::pmu::PmuCounterGuard;
use crate::{
    mbench_loop,
    platform::{Platform, shmem::ShmemOwner},
    sbi,
};

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
    run_shmem_reregister(env, run, ShmemOwner::PmuSnapshot)
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
