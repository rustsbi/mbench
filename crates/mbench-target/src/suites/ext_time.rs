//! SBI TIME extension and end-to-end M->S timer IRQ delivery vs `Sstc` (`time/*`).

use mbench_core::{
    engine::{
        BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, Clock, CounterSnap, FinishedBench,
    },
    record::{BenchGroup, FailReason, SbiExtensionId, SkipReason},
};

use crate::{
    mbench_loop,
    platform::{
        Platform, counters,
        timer::{self, TimerMode},
        trap,
    },
    sbi,
};

/// Declarative SBI TIME and Sstc benchmark suite (3 specs).
pub(crate) static SPECS: &[BenchSpec<Platform>] = &[
    BenchSpec {
        meta: BenchMeta {
            id: "time/set_timer",
            group: BenchGroup::Time,
            unit: "call",
            required_ext: Some(SbiExtensionId::Time),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_set_timer,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "time/irq.sbi",
            group: BenchGroup::Time,
            unit: "irq",
            required_ext: Some(SbiExtensionId::Time),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_timer_irq_sbi,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "time/irq.sstc",
            group: BenchGroup::Time,
            unit: "irq",
            required_ext: None,
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_timer_irq_sstc,
    },
];

fn run_set_timer(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let now = if env.availability().has_time {
        counters::read_time_raw()
    } else {
        0
    };
    let deadline = now.saturating_add(env.timebase_hz().saturating_mul(60));
    let ret = sbi::time::set_timer(deadline);
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }

    let pending = run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::time::set_timer(deadline);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    });
    let clr = timer::clear_timer(TimerMode::Sbi);
    pending.finish_with(if clr.error != 0 {
        Err(FailReason::UnexpectedSbiError(sbi::error_code(clr)))
    } else {
        Ok(())
    })
}

fn run_timer_irq_sbi(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let avail = env.availability();
    if !avail.has_any() {
        return run.skip(SkipReason::CounterUnavailable);
    }
    let timeout_ticks = env.timebase_hz().max(1);
    let _ = timer::clear_timer(TimerMode::Sbi);
    let guard = match trap::TimerSbiHookGuard::install(avail) {
        Ok(g) => g,
        Err(err) => return run.fail(err),
    };

    let pending = run.measure_paired(env, |env| {
        guard.reset_flag();
        let t0 = env.snap_begin();
        let _irq = guard.enable_stie();
        let ret = sbi::time::set_timer(0);
        if ret.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }
        env.wait_until(timeout_ticks, || guard.read_flag() != 0)?;
        let t1 = guard.read_snap();
        Ok(CounterSnap::delta(t1, t0))
    });

    drop(guard);
    let clr = timer::clear_timer(TimerMode::Sbi);
    pending.finish_with(if clr.error != 0 {
        Err(FailReason::UnexpectedSbiError(sbi::error_code(clr)))
    } else {
        Ok(())
    })
}

fn run_timer_irq_sstc(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    if !env.info().has_sstc || !timer::probe_stimecmp_writable() {
        return run.skip(SkipReason::ExtensionUnsupported);
    }
    let avail = env.availability();
    if !avail.has_any() {
        return run.skip(SkipReason::CounterUnavailable);
    }
    let timeout_ticks = env.timebase_hz().max(1);
    let guard = match trap::TimerSstcHookGuard::install(avail, env.info().has_sstc) {
        Ok(g) => g,
        Err(err) => return run.fail(err),
    };

    let pending = run.measure_paired(env, |env| {
        guard.reset_flag();
        let t0 = env.snap_begin();
        let _irq = guard.arm_sstc_zero();
        env.wait_until(timeout_ticks, || guard.read_flag() != 0)?;
        let t1 = guard.read_snap();
        Ok(CounterSnap::delta(t1, t0))
    });

    drop(guard);
    let _ = timer::clear_timer(TimerMode::Sstc);
    pending.commit()
}
