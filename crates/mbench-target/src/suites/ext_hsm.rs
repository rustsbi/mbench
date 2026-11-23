//! Phase 4 SBI HSM lifecycle benchmarks (`hsm/*`, run after secondary workers return to `STOPPED`).

use mbench_core::{
    engine::{BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, Clock, FinishedBench},
    record::{BenchGroup, FailReason, SbiExtensionId, SkipReason},
};

use crate::{
    mbench_loop,
    platform::{Platform, hsm},
    sbi,
};

/// Declarative Phase 4 SBI HSM benchmark suite (4 specs).
pub(crate) static SPECS: &[BenchSpec<Platform>] = &[
    BenchSpec {
        meta: BenchMeta {
            id: "hsm/get_status",
            group: BenchGroup::Hsm,
            unit: "call",
            required_ext: Some(SbiExtensionId::Hsm),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_hsm_get_status,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "hsm/start_stop",
            group: BenchGroup::Hsm,
            unit: "start",
            required_ext: Some(SbiExtensionId::Hsm),
            min_harts: 2,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_hsm_start_stop,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "hsm/suspend.retentive",
            group: BenchGroup::Hsm,
            unit: "wake",
            required_ext: Some(SbiExtensionId::Hsm),
            min_harts: 2,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_hsm_suspend_retentive,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "hsm/suspend.non_retentive",
            group: BenchGroup::Hsm,
            unit: "wake",
            required_ext: Some(SbiExtensionId::Hsm),
            min_harts: 2,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_hsm_suspend_non_retentive,
    },
];

fn run_hsm_get_status(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let hid = env.info().boot_hart_id;
    let ret = sbi::hsm::hart_get_status(hid);
    if ret.error != 0 || ret.value != sbi::hsm::state::STARTED {
        return run.fail(FailReason::VerificationMismatch);
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::hsm::hart_get_status(hid);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_hsm_start_stop(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    if env.info().hart_count < 2 {
        return run.skip(SkipReason::SingleHartOnly);
    }
    let peer = env.hart_id(1);
    let timeout = env.info().timebase_hz.saturating_mul(2).max(1);
    if hsm::wait_hart_state(
        peer,
        sbi::hsm::state::STOPPED,
        env.availability().has_time,
        timeout,
    )
    .is_err()
    {
        return run.fail(FailReason::HardwareInconsistent);
    }

    run.measure_paired(env, |env| hsm::probe_start_stop_sample(env, peer, timeout))
        .commit()
}

fn run_hsm_suspend(
    env: &mut Platform,
    run: BenchRun<'_, '_, '_, '_>,
    suspend_type: u32,
) -> FinishedBench {
    if env.info().hart_count < 2 {
        return run.skip(SkipReason::SingleHartOnly);
    }
    if !env.caps().extensions.contains_ext(SbiExtensionId::Spi) {
        return run.skip(SkipReason::ExtensionUnsupported);
    }
    let peer = env.hart_id(1);
    let timeout = env.info().timebase_hz.saturating_mul(2).max(1);
    let mut worker = match env.start_hsm_suspend_worker(peer, suspend_type, timeout) {
        Ok(Some(w)) => w,
        Ok(None) => return run.skip(SkipReason::FunctionUnsupported),
        Err(err) => return run.fail(err),
    };

    let pending = run.measure_paired(&mut worker, hsm::HsmSuspendWorker::measure_wake_sample);
    pending.finish_with(worker.finish())
}

fn run_hsm_suspend_retentive(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_hsm_suspend(env, run, sbi::hsm::suspend_type::RETENTIVE)
}

fn run_hsm_suspend_non_retentive(
    env: &mut Platform,
    run: BenchRun<'_, '_, '_, '_>,
) -> FinishedBench {
    run_hsm_suspend(env, run, sbi::hsm::suspend_type::NON_RETENTIVE)
}
