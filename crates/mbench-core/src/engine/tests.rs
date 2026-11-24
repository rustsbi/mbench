#[cfg(not(feature = "std"))]
extern crate std;

#[cfg(not(feature = "std"))]
use std::string::String;

use crate::{
    config::RunConfig,
    protocol,
    record::{CalibrationRecord, CounterAvailability, MetaRecord, SbiCapMask},
};
#[test]
fn emits_well_formed_meta_cal_and_end_frames() {
    let mut out = String::new();
    let meta = MetaRecord {
        sbi_spec_version: 0x0300_0000,
        impl_id: 1,
        impl_version: 2,
        mvendorid: 3,
        marchid: 4,
        mimpid: 5,
        extensions: SbiCapMask::BASE | SbiCapMask::TIME,
        hart_count: 4,
        boot_hart_id: 0,
        timebase_hz: 10_000_000,
        counters: CounterAvailability {
            has_cycle: true,
            has_instret: true,
            has_time: true,
            is_rdtime_emulated: false,
            is_pmu_gated: false,
        },
        has_sstc: true,
        has_h_ext: false,
        boot_ticks: 12345,
        reserved_mem_bytes: 131_072,
        console_backend: "dbcn",
        pmu_counter_count: 16,
        load_addr: 0x8020_0000,
        config: RunConfig::default(),
    };
    protocol::write_meta_line(&meta, &mut out).unwrap();
    protocol::write_cal_line(&CalibrationRecord::default(), &mut out).unwrap();
    protocol::write_end_line(&crate::record::EndRecord::default(), &mut out).unwrap();

    assert!(out.contains("@@MBENCH:META {"));
    assert!(out.contains("\"extensions\":[\"base\",\"time\"]"));
    assert!(out.contains("@@MBENCH:CAL {"));
    assert!(out.contains("@@MBENCH:END {"));
}

#[cfg(feature = "std")]
mod host {
    extern crate std;

    use core::cell::Cell;
    use std::{
        sync::{Arc, Barrier},
        thread,
        time::Instant,
    };

    use crate::{
        config::{OrderMode, Profile, RunConfig},
        engine::{
            BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, Clock, CounterSnap,
            FinishedBench, HartCoordinator, ParallelSample, ParallelWorkFn, calibrate,
            emit_failed_benches, execute_benches,
        },
        record::{
            BenchGroup, CounterAvailability, FailReason, HartTopology, RunState, SbiCapMask,
            SbiExtensionId,
        },
    };

    struct HostRuntime {
        origin: Instant,
        harts: usize,
        observed_sweep_iters: Cell<u64>,
    }

    impl HostRuntime {
        fn new() -> Self {
            Self {
                origin: Instant::now(),
                harts: thread::available_parallelism()
                    .expect("host parallelism is available")
                    .get(),
                observed_sweep_iters: Cell::new(0),
            }
        }
    }

    impl Clock for HostRuntime {
        fn snap_begin(&self) -> CounterSnap {
            CounterSnap {
                cycles: 0,
                instret: 0,
                ticks: self.read_ticks(),
            }
        }

        fn snap_end(&self) -> CounterSnap {
            CounterSnap {
                cycles: 0,
                instret: 0,
                ticks: self.read_ticks(),
            }
        }

        fn read_cycles(&self) -> u64 {
            0
        }

        fn read_ticks(&self) -> u64 {
            u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
        }

        fn availability(&self) -> CounterAvailability {
            CounterAvailability {
                has_cycle: false,
                has_instret: false,
                has_time: true,
                is_rdtime_emulated: false,
                is_pmu_gated: false,
            }
        }

        fn timebase_hz(&self) -> u64 {
            1_000_000_000
        }
    }

    impl HartTopology for HostRuntime {
        fn total_harts(&self) -> usize {
            self.harts
        }
    }

    impl HartCoordinator for HostRuntime {
        fn online_harts(&self) -> usize {
            self.harts
        }

        fn run_parallel(
            &mut self,
            parallel: usize,
            iters: u64,
            work_fn: ParallelWorkFn,
            out_samples: &mut [ParallelSample],
        ) -> Result<(), FailReason> {
            self.observed_sweep_iters.set(iters);
            let barrier = Arc::new(Barrier::new(parallel));
            let results = thread::scope(|scope| {
                let mut handles = Vec::with_capacity(parallel);
                for slot_idx in 0..parallel {
                    let b = Arc::clone(&barrier);
                    handles.push(scope.spawn(move || {
                        b.wait();
                        work_fn(slot_idx, parallel, iters)
                    }));
                }
                let mut collected = Vec::with_capacity(parallel);
                for h in handles {
                    collected.push(h.join().map_err(|_| FailReason::HardwareInconsistent)?);
                }
                Ok::<_, FailReason>(collected)
            })?;
            for (dst, sample) in out_samples.iter_mut().take(parallel).zip(results) {
                *dst = sample;
            }
            Ok(())
        }
    }

    fn host_spin_loop(iters: u64) {
        let mut rem = iters;
        while rem > 0 {
            core::hint::black_box(rem);
            rem -= 1;
        }
    }

    fn host_batched_work(env: &mut HostRuntime, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
        let pending = run.measure_batched(env, |_env, iters| {
            host_spin_loop(iters.saturating_mul(16));
            BatchOutcome::ok(iters)
        });
        pending.commit()
    }

    #[test]
    fn honors_per_case_caps_teardown_failure_and_zero_ops_rejection() {
        let mut env = HostRuntime::new();
        let cal = calibrate(&env, Profile::Quick, host_spin_loop);
        let mut state = RunState::new(
            RunConfig::parse_bootargs("profile=quick io=1"),
            SbiCapMask::BASE,
        );
        state.set_calibration(cal);

        fn post_fail_teardown(
            env: &mut HostRuntime,
            run: BenchRun<'_, '_, '_, '_>,
        ) -> FinishedBench {
            let pending = run.measure_batched(env, |_env, iters| {
                host_spin_loop(iters.saturating_mul(8));
                BatchOutcome::ok(iters)
            });
            pending.finish_with(Err(FailReason::Timeout))
        }

        let specs = [
            BenchSpec {
                meta: BenchMeta {
                    id: "dbcn/write.16b",
                    group: BenchGroup::Dbcn,
                    unit: "write16",
                    required_ext: None,
                    min_harts: 1,
                    flags: BenchFlags::IO_BOUND,
                    max_batch_iters: Some(8),
                },
                run: host_batched_work,
            },
            BenchSpec {
                meta: BenchMeta {
                    id: "rfnc/teardown_fail",
                    group: BenchGroup::Rfnc,
                    unit: "call",
                    required_ext: None,
                    min_harts: 1,
                    flags: BenchFlags::empty(),
                    max_batch_iters: Some(16),
                },
                run: post_fail_teardown,
            },
        ];

        let mut out = String::new();
        execute_benches(
            &specs,
            &mut env,
            &mut state,
            &mut out,
            OrderMode::Fixed,
            0,
            |_| 0,
        );
        assert_eq!(state.summary.benches_passed, 1);
        assert_eq!(state.summary.benches_failed, 1);
        assert!(out.contains("\"iters_per_trial\":8"));
        assert!(out.contains("\"raw_batch_totals\":["));
        assert!(out.contains("\"net_samples_x100\":["));
        assert!(out.contains("\"id\":\"rfnc/teardown_fail\""));
        assert!(out.contains("\"status\":\"FAIL\",\"fail_reason\":\"timeout\""));

        fn no_operations(env: &mut HostRuntime, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
            run.measure_batched(env, |_, _| BatchOutcome::ok(0))
                .commit()
        }
        let no_op_specs = [BenchSpec {
            meta: specs[0].meta,
            run: no_operations,
        }];
        let mut zero_out = String::new();
        execute_benches(
            &no_op_specs,
            &mut env,
            &mut state,
            &mut zero_out,
            OrderMode::Fixed,
            0,
            |_| 0,
        );
        assert!(zero_out.contains("\"fail_reason\":\"hardware_inconsistent\""));
    }

    #[test]
    fn calibrates_and_runs_capped_parallel_sweep() {
        fn worker(_slot: usize, _parallel: usize, iters: u64) -> ParallelSample {
            let start = Instant::now();
            host_spin_loop(iters.saturating_mul(64));
            let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
            ParallelSample {
                delta: CounterSnap {
                    cycles: 0,
                    instret: 0,
                    ticks: elapsed,
                },
                error_bits: 0,
            }
        }

        fn sweep_runner(env: &mut HostRuntime, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
            run.measure_parallel_sweep(env, worker).commit()
        }

        fn sweep_fail_runner(
            env: &mut HostRuntime,
            run: BenchRun<'_, '_, '_, '_>,
        ) -> FinishedBench {
            let pending = run.measure_parallel_sweep(env, worker);
            pending.finish_with(Err(FailReason::HardwareInconsistent))
        }

        let mut env = HostRuntime::new();
        let cal = calibrate(&env, Profile::Normal, host_spin_loop);
        let mut state = RunState::new(
            RunConfig::parse_bootargs("profile=normal max_harts=3"),
            SbiCapMask::BASE,
        );
        state.set_calibration(cal);

        let specs = [BenchSpec {
            meta: BenchMeta {
                id: "scale/base_ecall",
                group: BenchGroup::Scale,
                unit: "call",
                required_ext: Some(SbiExtensionId::Base),
                min_harts: 1,
                flags: BenchFlags::empty(),
                max_batch_iters: Some(8),
            },
            run: sweep_runner,
        }];

        let mut out = String::new();
        execute_benches(
            &specs,
            &mut env,
            &mut state,
            &mut out,
            OrderMode::Fixed,
            0,
            |_| 0,
        );

        assert_eq!(env.observed_sweep_iters.get(), 8);
        let parallelism = env.harts.min(3);
        assert_eq!(state.summary.benches_passed, parallelism);
        assert!(out.contains("\"parallel\":1"));
        for parallel in 1..=parallelism {
            assert!(out.contains(&format!("\"parallel\":{parallel}")));
        }
        assert!(out.contains("\"throughput_ops_per_sec\":"));

        let fail_specs = [BenchSpec {
            meta: BenchMeta {
                id: "scale/sfence_vma",
                group: BenchGroup::Scale,
                unit: "call",
                required_ext: Some(SbiExtensionId::Base),
                min_harts: 1,
                flags: BenchFlags::empty(),
                max_batch_iters: Some(8),
            },
            run: sweep_fail_runner,
        }];
        let mut fail_state = RunState::new(
            RunConfig::parse_bootargs("profile=normal max_harts=3"),
            SbiCapMask::BASE,
        );
        fail_state.set_calibration(cal);
        let mut fail_out = String::new();
        execute_benches(
            &fail_specs,
            &mut env,
            &mut fail_state,
            &mut fail_out,
            OrderMode::Fixed,
            0,
            |_| 0,
        );
        assert_eq!(fail_state.summary.benches_passed, 0);
        assert_eq!(fail_state.summary.benches_failed, parallelism);
        assert!(!fail_out.contains("\"status\":\"PASS\""));
    }

    #[test]
    fn executes_host_checks_and_emits_gated_benchmark_failures() {
        use crate::check::{
            CheckCase, CheckCtx, CheckGroup, CheckMeta, CheckOutcome, execute_check_groups,
        };

        fn check_clock(env: &mut HostRuntime) -> CheckOutcome {
            let before = env.read_ticks();
            thread::yield_now();
            let mut ctx = CheckCtx::new();
            ctx.expect(env.read_ticks() >= before, "host_monotonic_time");
            ctx.finish()
        }

        let mut env = HostRuntime::new();
        let cases = [CheckCase {
            meta: CheckMeta::new("host/time", None, 1, BenchFlags::empty()),
            run: check_clock,
        }];
        let groups = [CheckGroup {
            name: "host",
            cases: &cases,
        }];
        let mut state = RunState::new(RunConfig::default(), SbiCapMask::BASE);
        let mut out = String::new();
        let mut quarantines = 0;
        execute_check_groups(&groups, &mut env, &mut state, &mut out, |_| {
            quarantines += 1;
            0
        });
        assert_eq!(state.summary.checks_passed, 1);
        assert_eq!(state.summary.check_assertions_passed, 1);
        assert_eq!(quarantines, 1);

        let meta = BenchMeta {
            id: "host/time",
            group: BenchGroup::Baseline,
            unit: "iteration",
            required_ext: None,
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: Some(8),
        };
        let specs = [
            BenchSpec {
                meta,
                run: host_batched_work,
            },
            BenchSpec {
                meta: BenchMeta {
                    id: "filtered/time",
                    ..meta
                },
                run: host_batched_work,
            },
        ];
        let mut state = RunState::new(RunConfig::parse_bootargs("filter=host/"), SbiCapMask::BASE);
        let mut out = String::new();
        emit_failed_benches(
            &specs,
            &env,
            &mut state,
            &mut out,
            FailReason::Timeout,
            "bringup-failed",
        );
        assert_eq!(state.summary.benches_failed, 1);
        assert_eq!(state.summary.benches_skipped, 1);
        assert!(out.contains("\"fail_reason\":\"timeout\""));
        assert!(out.contains("\"skip_reason\":\"filtered_out\""));
    }
}
