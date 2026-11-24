//! SBI sPI extension benchmarks (`spi/*`) using safe [`crate::platform::WorkerIpiModeGuard`].

use mbench_core::{
    engine::{
        BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, Clock, CounterSnap,
        FinishedBench, HartCoordinator,
    },
    record::{BenchGroup, FailReason, SbiExtensionId, SkipReason},
};

use crate::{
    mbench_loop,
    platform::{Platform, trap::TrapHookMode},
    sbi,
};

/// Declarative SBI sPI benchmark suite (4 specs).
pub(crate) static SPECS: &[BenchSpec<Platform>] = &[
    BenchSpec {
        meta: BenchMeta {
            id: "spi/send_ipi.empty",
            group: BenchGroup::Spi,
            unit: "call",
            required_ext: Some(SbiExtensionId::Spi),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_ipi_empty,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "spi/send_ipi.one",
            group: BenchGroup::Spi,
            unit: "call",
            required_ext: Some(SbiExtensionId::Spi),
            min_harts: 2,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_ipi_send_one,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "spi/send_ipi.all",
            group: BenchGroup::Spi,
            unit: "call",
            required_ext: Some(SbiExtensionId::Spi),
            min_harts: 2,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_ipi_send_all,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "spi/pingpong",
            group: BenchGroup::Spi,
            unit: "one-way-ipi",
            required_ext: Some(SbiExtensionId::Spi),
            min_harts: 2,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_ipi_pingpong,
    },
];

fn run_ipi_empty(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::spi::send_ipi(0, 0);
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::spi::send_ipi(0, 0);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_ipi_send_one(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    if env.online_harts() < 2 {
        return run.skip(SkipReason::SingleHartOnly);
    }
    let mut guard = match env.configure_worker_ipi_mode(2, TrapHookMode::IpiCapture) {
        Ok(g) => g,
        Err(err) => return run.fail(err),
    };
    let (mask, base) = Platform::hart_mask_single(guard.hart_id(1));
    let ret = sbi::spi::send_ipi(mask, base);
    if ret.error != 0 {
        let _ = guard.finish();
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }

    let pending = run.measure_batched(&mut guard, |_g, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::spi::send_ipi(mask, base);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    });
    pending.finish_with(guard.finish())
}

fn run_ipi_send_all(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let online = env.online_harts();
    if online < 2 {
        return run.skip(SkipReason::SingleHartOnly);
    }
    let Some((mask, base)) = env.workers_hart_mask() else {
        return run.skip(SkipReason::NoUsableResource);
    };
    let mut guard = match env.configure_worker_ipi_mode(online, TrapHookMode::IpiCapture) {
        Ok(g) => g,
        Err(err) => return run.fail(err),
    };
    let ret = sbi::spi::send_ipi(mask, base);
    if ret.error != 0 {
        let _ = guard.finish();
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }

    let pending = run.measure_batched(&mut guard, |_g, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::spi::send_ipi(mask, base);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    });
    pending.finish_with(guard.finish())
}

fn run_ipi_pingpong(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    if !env.availability().has_any() {
        return run.skip(SkipReason::CounterUnavailable);
    }
    if env.online_harts() < 2 {
        return run.skip(SkipReason::SingleHartOnly);
    }
    let mut guard = match env.configure_worker_ipi_mode(2, TrapHookMode::IpiBounce) {
        Ok(g) => g,
        Err(err) => return run.fail(err),
    };
    let self_hook = match guard.install_self_ipi_capture() {
        Ok(h) => h,
        Err(err) => {
            let _ = guard.finish();
            return run.fail(err);
        }
    };
    let (peer_mask, peer_base) = Platform::hart_mask_single(guard.hart_id(1));
    let timeout_ticks = guard.timebase_hz().max(1);

    let pending = run.measure_paired(&mut guard, |g| {
        self_hook.reset_flag();
        let t0 = g.snap_begin();
        let _irq = self_hook.enable_ssie();
        let ret = sbi::spi::send_ipi(peer_mask, peer_base);
        if ret.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }
        g.wait_until(timeout_ticks, || self_hook.read_flag() != 0)?;
        let t1 = self_hook.read_snap();
        let rtt = CounterSnap::delta(t1, t0);
        Ok(CounterSnap {
            cycles: rtt.cycles / 2,
            instret: rtt.instret / 2,
            ticks: rtt.ticks / 2,
        })
    });

    drop(self_hook);
    pending.finish_with(guard.finish())
}
