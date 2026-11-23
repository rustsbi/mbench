//! Phase 1 calibration floor baselines (`baseline/*`).

use mbench_core::{
    engine::{BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, Clock, FinishedBench},
    record::{BenchGroup, FailReason, SkipReason},
};

use crate::{
    mbench_loop,
    platform::{Platform, counters, icache, trap},
    suites::empty_bench_loop,
};

/// Declarative Phase 1 baseline benchmark suite.
pub(crate) static SPECS: &[BenchSpec<Platform>] = &[
    BenchSpec {
        meta: BenchMeta {
            id: "baseline/loop",
            group: BenchGroup::Baseline,
            unit: "iter",
            required_ext: None,
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_base_loop,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "baseline/counter",
            group: BenchGroup::Baseline,
            unit: "read",
            required_ext: None,
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_base_counter,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "baseline/s_trap",
            group: BenchGroup::Baseline,
            unit: "trap",
            required_ext: None,
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_base_s_trap,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "baseline/icache_thrash",
            group: BenchGroup::Baseline,
            unit: "sweep",
            required_ext: None,
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_base_icache_thrash,
    },
];

fn run_base_loop(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run.measure_batched(env, |_env, iters| {
        empty_bench_loop(iters);
        BatchOutcome::ok(iters)
    })
    .commit()
}

fn run_base_counter(env: &mut Platform, mut run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let avail = env.availability();
    if !avail.has_time && !avail.has_cycle {
        return run.skip(SkipReason::CounterUnavailable);
    }
    if avail.is_rdtime_emulated {
        run.set_note("rdtime-emulated-in-m-mode");
    }
    run.measure_batched(env, |env, iters| {
        let mut acc = 0u64;
        if env.availability().has_time {
            mbench_loop!(iters, {
                acc = acc.wrapping_add(counters::read_time_raw());
            });
        } else {
            mbench_loop!(iters, {
                acc = acc.wrapping_add(counters::read_cycle_raw());
            });
        }
        core::hint::black_box(acc);
        BatchOutcome::ok(iters)
    })
    .commit()
}

fn run_base_s_trap(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let guard = match trap::EbreakHookGuard::install(env.availability()) {
        Ok(g) => g,
        Err(err) => return run.fail(err),
    };
    guard.reset_flag();
    guard.exec_ebreak();
    if guard.read_flag() != 1 {
        return run.fail(FailReason::VerificationMismatch);
    }
    guard.reset_flag();

    run.measure_batched(env, |_env, iters| {
        mbench_loop!(iters, {
            guard.exec_ebreak();
        });
        BatchOutcome::ok(iters)
    })
    .commit()
}

fn run_base_icache_thrash(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    icache::thrash();
    run.measure_batched(env, |_env, iters| {
        mbench_loop!(iters, {
            icache::thrash();
        });
        BatchOutcome::ok(iters)
    })
    .commit()
}
