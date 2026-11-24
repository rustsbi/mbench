//! LMbench-style performance measurement engine: calibration, adaptive batching, paired events, and parallel sweeps.

use core::fmt::Write;

use crate::{
    config::{self, OrderMode, Profile},
    protocol,
    record::{
        BenchGroup, BenchResult, BenchStatus, CalibrationRecord, CaseFlags, CaseGate,
        CounterAvailability, FailReason, HartTopology, MeasureMode, RunState, SbiExtensionId,
        SkipReason, StartKind,
    },
    stats::{self, CounterStats, DerivedNsStats},
};

/// Maximum number of harts collected per trial in [`MeasureMode::ParallelSweep`].
pub const MAX_SWEEP_HARTS: usize = 64;

/// Maximum number of distinct parallelism points (`1, 2, 4, 8, 16, 32, 64` + arbitrary `max_harts`).
pub const MAX_SWEEP_POINTS: usize = 8;

/// Maximum number of benchmarks permitted in one execution phase slice.
pub const MAX_PHASE_BENCHES: usize = 64;

/// Cycle threshold above which `rdtime` is classified as M-mode emulated rather than direct hardware CSR.
pub const RDTIME_EMULATED_THRESHOLD_CYCLES: u64 = 80;

/// Snapshot of available RISC-V hardware/SBI counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CounterSnap {
    pub cycles: u64,
    pub instret: u64,
    pub ticks: u64,
}

impl CounterSnap {
    /// Computes counter deltas `after - before` with wrapping semantics.
    pub const fn delta(after: Self, before: Self) -> Self {
        Self {
            cycles: after.cycles.wrapping_sub(before.cycles),
            instret: after.instret.wrapping_sub(before.instret),
            ticks: after.ticks.wrapping_sub(before.ticks),
        }
    }
}

/// Hardware or test counter source consumed by [`calibrate`] and [`execute_benches`].
pub trait Clock {
    /// Samples counters ordered for the start of a timed region (`time`, `instret`, `cycle`).
    fn snap_begin(&self) -> CounterSnap;

    /// Samples counters ordered for the end of a timed region (`cycle`, `instret`, `time`).
    fn snap_end(&self) -> CounterSnap;

    /// Samples the `cycle` counter alone for lightweight `rdtime` cost estimation.
    fn read_cycles(&self) -> u64;

    /// Samples the `time` counter alone for lightweight `rdtime` cost estimation.
    fn read_ticks(&self) -> u64;

    /// Returns which counters are readable in S-mode.
    fn availability(&self) -> CounterAvailability;

    /// Returns the platform timer frequency in Hz (`timebase-frequency`).
    fn timebase_hz(&self) -> u64;
}

/// Per-hart measurement sample produced by a parallel worker callback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ParallelSample {
    pub delta: CounterSnap,
    pub error_bits: usize,
}

/// Worker function invoked simultaneously across `parallel` harts (`slot_idx`, `parallel`, `iters`).
pub type ParallelWorkFn = fn(usize, usize, u64) -> ParallelSample;

/// Multi-hart coordinator seam used by [`MeasureMode::ParallelSweep`].
pub trait HartCoordinator: HartTopology {
    /// Returns the number of online harts available for parallel execution (at least 1).
    fn online_harts(&self) -> usize;

    /// Runs `work_fn(slot_idx, parallel, iters)` concurrently across `parallel` harts starting together.
    ///
    /// Implementations must fill `out_samples[..parallel]` in hart slot order.
    fn run_parallel(
        &mut self,
        parallel: usize,
        iters: u64,
        work_fn: ParallelWorkFn,
        out_samples: &mut [ParallelSample],
    ) -> Result<(), FailReason>;
}

/// Capability and safety flags attached to a performance benchmark case.
pub type BenchFlags = CaseFlags;

/// Static descriptor for a performance benchmark case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BenchMeta {
    pub id: &'static str,
    pub group: BenchGroup,
    pub unit: &'static str,
    pub required_ext: Option<SbiExtensionId>,
    pub min_harts: usize,
    pub flags: BenchFlags,
    pub max_batch_iters: Option<u64>,
}

impl BenchMeta {
    /// Returns the shared [`CaseGate`] for this benchmark specification.
    pub const fn gate(&self) -> CaseGate {
        CaseGate::new(self.required_ext, self.min_harts, self.flags)
    }
}

/// Result of a batched execution hook.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BatchOutcome {
    pub error_bits: usize,
    pub ops_completed: u64,
}

impl BatchOutcome {
    /// Creates a successful outcome with `ops_completed` completed operations.
    pub const fn ok(ops_completed: u64) -> Self {
        Self {
            error_bits: 0,
            ops_completed,
        }
    }

    /// Creates an outcome from accumulated branchless error bits and operation count.
    pub const fn from_errors(error_bits: usize, ops_completed: u64) -> Self {
        Self {
            error_bits,
            ops_completed,
        }
    }
}

/// Proof token returned once a [`BenchSpec::run`] invocation has emitted its wire frame(s).
#[derive(Debug)]
pub struct FinishedBench {
    _sealed: (),
}

/// Declarative performance benchmark specification executed by [`execute_benches`].
pub struct BenchSpec<Env> {
    pub meta: BenchMeta,
    pub run: fn(&mut Env, BenchRun<'_, '_, '_, '_>) -> FinishedBench,
}

impl<Env> Clone for BenchSpec<Env> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Env> Copy for BenchSpec<Env> {}

/// Single-result measurement buffer awaiting teardown verification before emission.
#[must_use = "pending benchmark results must be finished or committed"]
pub struct PendingBench<'meta, 'state, 'cfg, 'out> {
    state: &'state mut RunState<'cfg>,
    out: &'out mut dyn Write,
    result: BenchResult<'meta>,
}

impl<'meta, 'state, 'cfg, 'out> PendingBench<'meta, 'state, 'cfg, 'out> {
    /// Attaches an informational note to the pending frame.
    pub fn set_note(&mut self, note: &'static str) {
        self.result.note = Some(note);
    }

    /// Commits the measured or early-failed result to summary counters and the wire stream.
    pub fn commit(self) -> FinishedBench {
        record_and_emit(&self.result, self.state, self.out);
        FinishedBench { _sealed: () }
    }

    /// Applies post-measurement teardown verification before emitting the result.
    ///
    /// If the measurement succeeded and `teardown` returned `Err(reason)`, upgrades the frame
    /// to `FAIL` and clears statistical fields so teardown failures cannot emit a false `PASS`.
    pub fn finish_with(mut self, teardown: Result<(), FailReason>) -> FinishedBench {
        if let Err(reason) = teardown
            && !matches!(self.result.status, BenchStatus::Failed(_))
        {
            self.mark_failed(reason);
        }
        self.commit()
    }

    /// Replaces the pending outcome with `Failed(reason)` (unless already failed) and emits it.
    pub fn fail(mut self, reason: FailReason) -> FinishedBench {
        if !matches!(self.result.status, BenchStatus::Failed(_)) {
            self.mark_failed(reason);
        }
        self.commit()
    }

    fn mark_failed(&mut self, reason: FailReason) {
        fail_bench_result(&mut self.result, reason);
    }
}

/// Multi-point parallel sweep buffer awaiting teardown verification before emission.
#[must_use = "pending sweep results must be finished or committed"]
pub struct PendingSweep<'meta, 'state, 'cfg, 'out> {
    state: &'state mut RunState<'cfg>,
    out: &'out mut dyn Write,
    results: [Option<BenchResult<'meta>>; MAX_SWEEP_POINTS],
    count: usize,
}

impl<'meta, 'state, 'cfg, 'out> PendingSweep<'meta, 'state, 'cfg, 'out> {
    /// Commits all buffered sweep results to summary counters and the wire stream.
    pub fn commit(self) -> FinishedBench {
        for slot in self.results.into_iter().take(self.count).flatten() {
            record_and_emit(&slot, self.state, self.out);
        }
        FinishedBench { _sealed: () }
    }

    /// Applies post-sweep teardown verification across every buffered point before emitting.
    ///
    /// If `teardown` fails, any non-failed point is converted to `FAIL` with cleared stats.
    pub fn finish_with(mut self, teardown: Result<(), FailReason>) -> FinishedBench {
        if let Err(reason) = teardown {
            for slot in self.results.iter_mut().take(self.count).flatten() {
                if !matches!(slot.status, BenchStatus::Failed(_)) {
                    fail_bench_result(slot, reason);
                }
            }
        }
        self.commit()
    }
}

fn fail_bench_result(res: &mut BenchResult<'_>, reason: FailReason) {
    res.status = BenchStatus::Failed(reason);
    res.cycles = None;
    res.instret = None;
    res.ticks = None;
    res.ns = None;
    res.throughput_ops_per_sec = None;
}

/// Linear measurement handle passed by value to each [`BenchSpec::run`] invocation.
#[must_use = "BenchRun must conclude with skip, fail, hw_native, delegated_to_s, or measure_*"]
pub struct BenchRun<'meta, 'state, 'cfg, 'out> {
    meta: &'meta BenchMeta,
    state: &'state mut RunState<'cfg>,
    out: &'out mut dyn Write,
    note: Option<&'static str>,
}

impl<'meta, 'state, 'cfg, 'out> BenchRun<'meta, 'state, 'cfg, 'out> {
    /// Attaches an informational note emitted in the benchmark's `@@MBENCH:BENCH` frame.
    pub fn set_note(&mut self, note: &'static str) {
        self.note = Some(note);
    }

    /// Concludes the benchmark cleanly without executing timing loops.
    pub fn skip(self, reason: SkipReason) -> FinishedBench {
        emit_simple_bench(
            self.meta,
            1,
            BenchStatus::Skipped(reason),
            self.note,
            self.state,
            self.out,
        );
        FinishedBench { _sealed: () }
    }

    /// Concludes the benchmark with an upfront failure before measurement.
    pub fn fail(self, reason: FailReason) -> FinishedBench {
        emit_simple_bench(
            self.meta,
            1,
            BenchStatus::Failed(reason),
            self.note,
            self.state,
            self.out,
        );
        FinishedBench { _sealed: () }
    }

    /// Reports that the probed operation executes natively in S-mode without M-mode trapping.
    pub fn hw_native(self, clock: &impl Clock, sample: CounterSnap) -> FinishedBench {
        let res =
            build_single_sample_result(self.meta, BenchStatus::HwNative, sample, clock, self.note);
        record_and_emit(&res, self.state, self.out);
        FinishedBench { _sealed: () }
    }

    /// Reports that the trap was delegated to S-mode rather than emulated in M-mode.
    pub fn delegated_to_s(self) -> FinishedBench {
        emit_simple_bench(
            self.meta,
            1,
            BenchStatus::DelegatedToS,
            self.note,
            self.state,
            self.out,
        );
        FinishedBench { _sealed: () }
    }

    /// Executes a standard LMbench batched tight-loop benchmark with calibration overhead subtraction.
    pub fn measure_batched<Env: Clock>(
        self,
        env: &mut Env,
        body: impl FnMut(&mut Env, u64) -> BatchOutcome,
    ) -> PendingBench<'meta, 'state, 'cfg, 'out> {
        self.measure_batched_impl(env, None::<fn(&mut Env, u64)>, body)
    }

    /// Executes a batched benchmark subtracting an explicit preamble batch (such as I-cache thrashing).
    pub fn measure_batched_with_preamble<Env: Clock>(
        self,
        env: &mut Env,
        preamble: impl FnMut(&mut Env, u64),
        body: impl FnMut(&mut Env, u64) -> BatchOutcome,
    ) -> PendingBench<'meta, 'state, 'cfg, 'out> {
        self.measure_batched_impl(env, Some(preamble), body)
    }

    /// Executes a causal paired-event benchmark collecting `samples_per_trial` deltas per outer trial.
    pub fn measure_paired<Env: Clock>(
        self,
        env: &mut Env,
        mut sample_fn: impl FnMut(&mut Env) -> Result<CounterSnap, FailReason>,
    ) -> PendingBench<'meta, 'state, 'cfg, 'out> {
        let cal = self.state.calibration();
        let trials = cal.trials.clamp(1, stats::MAX_TRIALS);
        let samples_per_trial = self.state.config.profile.paired_samples().min(64);
        let avail = env.availability();

        if let Err(reason) = sample_fn(env) {
            return self.pending_failed(
                Some(MeasureMode::PairedEvent),
                1,
                samples_per_trial as u64,
                0,
                reason,
            );
        }

        let mut trial_cyc = [0u64; stats::MAX_TRIALS];
        let mut trial_ins = [0u64; stats::MAX_TRIALS];
        let mut trial_tck = [0u64; stats::MAX_TRIALS];

        for t in 0..trials {
            let mut inner_cyc = [0u64; 64];
            let mut inner_ins = [0u64; 64];
            let mut inner_tck = [0u64; 64];
            for s in 0..samples_per_trial {
                match sample_fn(env) {
                    Ok(delta) => {
                        inner_cyc[s] = delta.cycles;
                        inner_ins[s] = delta.instret;
                        inner_tck[s] = delta.ticks;
                    }
                    Err(reason) => {
                        return self.pending_failed(
                            Some(MeasureMode::PairedEvent),
                            1,
                            samples_per_trial as u64,
                            t,
                            reason,
                        );
                    }
                }
            }
            inner_cyc[..samples_per_trial].sort_unstable();
            inner_ins[..samples_per_trial].sort_unstable();
            inner_tck[..samples_per_trial].sort_unstable();
            trial_cyc[t] = inner_cyc[samples_per_trial / 2];
            trial_ins[t] = inner_ins[samples_per_trial / 2];
            trial_tck[t] = inner_tck[samples_per_trial / 2];
        }

        let cycles = avail.has_cycle.then(|| {
            stats::compute_stats(&trial_cyc[..trials], 1, 0, cal.timer_overhead_cycles_x100)
        });
        let instret = avail.has_instret.then(|| {
            stats::compute_stats(&trial_ins[..trials], 1, 0, cal.timer_overhead_instret_x100)
        });
        let ticks = avail.has_time.then(|| {
            stats::compute_stats(&trial_tck[..trials], 1, 0, cal.timer_overhead_ticks_x100)
        });
        let ns = ticks
            .as_ref()
            .map(|t| stats::scale_stats_to_ns(t, env.timebase_hz()));

        PendingBench {
            state: self.state,
            out: self.out,
            result: BenchResult {
                id: self.meta.id,
                group: self.meta.group,
                mode: Some(MeasureMode::PairedEvent),
                parallel: 1,
                unit: self.meta.unit,
                iters_per_trial: samples_per_trial as u64,
                trials,
                status: BenchStatus::Pass,
                cycles,
                instret,
                ticks,
                ns,
                throughput_ops_per_sec: None,
                note: self.note,
            },
        }
    }

    /// Executes a multi-hart scalability sweep across `1, 2, 4, ..., online_harts`, buffering
    /// per-point results into [`PendingSweep`] so resource teardown checks run before emission.
    pub fn measure_parallel_sweep<Env: Clock + HartCoordinator>(
        self,
        env: &mut Env,
        work_fn: ParallelWorkFn,
    ) -> PendingSweep<'meta, 'state, 'cfg, 'out> {
        let profile = self.state.config.profile;
        let cal = self.state.calibration();
        let trials = cal.trials.clamp(1, stats::MAX_TRIALS);
        let avail = env.availability();

        let max_harts =
            config::effective_max_harts(env.online_harts(), self.state.config.max_harts)
                .clamp(1, MAX_SWEEP_HARTS);
        let mut sweep = [0usize; MAX_SWEEP_POINTS];
        let sweep_len = build_parallel_sweep(max_harts, &mut sweep);

        let mut results: [Option<BenchResult<'meta>>; MAX_SWEEP_POINTS] =
            [const { None }; MAX_SWEEP_POINTS];
        let mut count = 0usize;

        let cap = self.effective_max_iters();
        let sweep_cap = if self.meta.max_batch_iters.is_some() {
            cap
        } else {
            (cap / 4).max(profile.initial_batch_iters()).min(cap)
        };
        let mut samples = [ParallelSample::default(); MAX_SWEEP_HARTS];

        let mut iters = profile.initial_batch_iters().min(sweep_cap);
        loop {
            if let Err(reason) = env.run_parallel(1, iters, work_fn, &mut samples) {
                results[0] = Some(build_failed_bench(
                    self.meta,
                    Some(MeasureMode::ParallelSweep),
                    1,
                    iters,
                    0,
                    reason,
                    self.note,
                ));
                return PendingSweep {
                    state: self.state,
                    out: self.out,
                    results,
                    count: 1,
                };
            }
            if samples[0].error_bits != 0 {
                results[0] = Some(build_failed_bench(
                    self.meta,
                    Some(MeasureMode::ParallelSweep),
                    1,
                    iters,
                    0,
                    FailReason::SecondaryHartError(samples[0].error_bits as isize),
                    self.note,
                ));
                return PendingSweep {
                    state: self.state,
                    out: self.out,
                    results,
                    count: 1,
                };
            }
            if enough_reached(samples[0].delta, iters, avail, profile, sweep_cap) {
                break;
            }
            iters = iters.saturating_mul(2).min(sweep_cap);
        }

        let warmup = profile.warmup_iters().min(sweep_cap);
        for (idx, &parallel) in sweep[..sweep_len].iter().enumerate() {
            if idx > 0 {
                let _ =
                    protocol::write_start_line(StartKind::Bench, self.meta.id, parallel, self.out);
            }

            if let Err(reason) = env.run_parallel(parallel, warmup, work_fn, &mut samples) {
                results[count] = Some(build_failed_bench(
                    self.meta,
                    Some(MeasureMode::ParallelSweep),
                    parallel,
                    warmup,
                    0,
                    reason,
                    self.note,
                ));
                count += 1;
                continue;
            }
            if let Some(err) = samples.iter().take(parallel).find(|s| s.error_bits != 0) {
                results[count] = Some(build_failed_bench(
                    self.meta,
                    Some(MeasureMode::ParallelSweep),
                    parallel,
                    warmup,
                    0,
                    FailReason::SecondaryHartError(err.error_bits as isize),
                    self.note,
                ));
                count += 1;
                continue;
            }

            let mut cyc = [0u64; stats::MAX_TRIALS];
            let mut ins = [0u64; stats::MAX_TRIALS];
            let mut tck = [0u64; stats::MAX_TRIALS];
            let mut wall_tck = [0u64; stats::MAX_TRIALS];
            let mut failed: Option<(usize, FailReason)> = None;

            for t in 0..trials {
                if let Err(reason) = env.run_parallel(parallel, iters, work_fn, &mut samples) {
                    failed = Some((t, reason));
                    break;
                }
                let mut h_cyc = [0u64; MAX_SWEEP_HARTS];
                let mut h_ins = [0u64; MAX_SWEEP_HARTS];
                let mut h_tck = [0u64; MAX_SWEEP_HARTS];
                let mut max_tick = 0u64;
                for h in 0..parallel {
                    if samples[h].error_bits != 0 {
                        failed = Some((
                            t,
                            FailReason::SecondaryHartError(samples[h].error_bits as isize),
                        ));
                        break;
                    }
                    h_cyc[h] = samples[h].delta.cycles;
                    h_ins[h] = samples[h].delta.instret;
                    h_tck[h] = samples[h].delta.ticks;
                    if h_tck[h] > max_tick {
                        max_tick = h_tck[h];
                    }
                }
                if failed.is_some() {
                    break;
                }
                h_cyc[..parallel].sort_unstable();
                h_ins[..parallel].sort_unstable();
                h_tck[..parallel].sort_unstable();
                cyc[t] = h_cyc[parallel / 2];
                ins[t] = h_ins[parallel / 2];
                tck[t] = h_tck[parallel / 2];
                wall_tck[t] = max_tick;
            }

            if let Some((completed_trials, reason)) = failed {
                results[count] = Some(build_failed_bench(
                    self.meta,
                    Some(MeasureMode::ParallelSweep),
                    parallel,
                    iters,
                    completed_trials,
                    reason,
                    self.note,
                ));
                count += 1;
                continue;
            }

            let (cycles, instret, ticks, ns) = summarize_batched_trials(
                &cyc[..trials],
                &ins[..trials],
                &tck[..trials],
                iters,
                &cal,
                avail,
                env.timebase_hz(),
            );
            let throughput = if avail.has_time {
                wall_tck[..trials].sort_unstable();
                let med_wall = wall_tck[trials / 2];
                compute_throughput_ops(parallel, iters, med_wall, env.timebase_hz())
            } else {
                None
            };

            results[count] = Some(BenchResult {
                id: self.meta.id,
                group: self.meta.group,
                mode: Some(MeasureMode::ParallelSweep),
                parallel,
                unit: self.meta.unit,
                iters_per_trial: iters,
                trials,
                status: BenchStatus::Pass,
                cycles,
                instret,
                ticks,
                ns,
                throughput_ops_per_sec: throughput,
                note: self.note,
            });
            count += 1;
        }
        PendingSweep {
            state: self.state,
            out: self.out,
            results,
            count,
        }
    }

    fn effective_max_iters(&self) -> u64 {
        let profile_max = self.state.config.profile.max_batch_iters();
        match self.meta.max_batch_iters {
            Some(cap) => profile_max.min(cap).max(1),
            None => profile_max,
        }
    }

    fn measure_batched_impl<Env: Clock>(
        self,
        env: &mut Env,
        mut preamble: Option<impl FnMut(&mut Env, u64)>,
        mut body: impl FnMut(&mut Env, u64) -> BatchOutcome,
    ) -> PendingBench<'meta, 'state, 'cfg, 'out> {
        let mode = if preamble.is_some() {
            MeasureMode::BatchedWithPreamble
        } else {
            MeasureMode::Batched
        };
        let profile = self.state.config.profile;
        let cal = self.state.calibration();
        let trials = cal.trials.clamp(1, stats::MAX_TRIALS);
        let avail = env.availability();
        let cap = self.effective_max_iters();

        let warmup = profile.warmup_iters().min(cap);
        if let Some(ref mut pre) = preamble {
            pre(env, warmup);
        }
        let warm_out = body(env, warmup);
        if warm_out.error_bits != 0 {
            return self.pending_failed(
                Some(mode),
                1,
                warmup,
                0,
                FailReason::UnexpectedSbiError(warm_out.error_bits as isize),
            );
        }
        if warm_out.ops_completed == 0 {
            return self.pending_failed(Some(mode), 1, warmup, 0, FailReason::HardwareInconsistent);
        }

        let mut iters = profile.initial_batch_iters().min(cap);
        loop {
            let b = env.snap_begin();
            let batch = body(env, iters);
            let a = env.snap_end();
            if batch.error_bits != 0 {
                return self.pending_failed(
                    Some(mode),
                    1,
                    iters,
                    0,
                    FailReason::UnexpectedSbiError(batch.error_bits as isize),
                );
            }
            if batch.ops_completed == 0 {
                return self.pending_failed(
                    Some(mode),
                    1,
                    iters,
                    0,
                    FailReason::HardwareInconsistent,
                );
            }
            let d = CounterSnap::delta(a, b);
            if enough_reached(d, iters, avail, profile, cap) {
                break;
            }
            iters = iters.saturating_mul(2).min(cap);
        }

        let mut pre_cyc_med = 0u64;
        let mut pre_ins_med = 0u64;
        let mut pre_tck_med = 0u64;
        if let Some(ref mut pre) = preamble {
            let mut p_cyc = [0u64; stats::MAX_TRIALS];
            let mut p_ins = [0u64; stats::MAX_TRIALS];
            let mut p_tck = [0u64; stats::MAX_TRIALS];
            for i in 0..trials {
                let b = env.snap_begin();
                pre(env, iters);
                let a = env.snap_end();
                let d = CounterSnap::delta(a, b);
                p_cyc[i] = d.cycles;
                p_ins[i] = d.instret;
                p_tck[i] = d.ticks;
            }
            p_cyc[..trials].sort_unstable();
            p_ins[..trials].sort_unstable();
            p_tck[..trials].sort_unstable();
            pre_cyc_med = p_cyc[trials / 2];
            pre_ins_med = p_ins[trials / 2];
            pre_tck_med = p_tck[trials / 2];
        }

        let mut cyc = [0u64; stats::MAX_TRIALS];
        let mut ins = [0u64; stats::MAX_TRIALS];
        let mut tck = [0u64; stats::MAX_TRIALS];
        let mut expected_ops: Option<u64> = None;
        for i in 0..trials {
            let b = env.snap_begin();
            let batch = body(env, iters);
            let a = env.snap_end();
            if batch.error_bits != 0 {
                return self.pending_failed(
                    Some(mode),
                    1,
                    iters,
                    i,
                    FailReason::UnexpectedSbiError(batch.error_bits as isize),
                );
            }
            if batch.ops_completed == 0 {
                return self.pending_failed(
                    Some(mode),
                    1,
                    iters,
                    i,
                    FailReason::HardwareInconsistent,
                );
            }
            match expected_ops {
                None => expected_ops = Some(batch.ops_completed),
                Some(prev) if prev != batch.ops_completed => {
                    return self.pending_failed(
                        Some(mode),
                        1,
                        iters,
                        i,
                        FailReason::HardwareInconsistent,
                    );
                }
                Some(_) => {}
            }
            let d = CounterSnap::delta(a, b);
            cyc[i] = d.cycles;
            ins[i] = d.instret;
            tck[i] = d.ticks;
        }
        let ops_divisor = expected_ops.unwrap_or(iters);

        let (cycles, instret, ticks, ns) = if preamble.is_some() {
            let c = avail.has_cycle.then(|| {
                stats::compute_stats(
                    &cyc[..trials],
                    ops_divisor,
                    0,
                    pre_cyc_med.saturating_mul(stats::STATS_SCALE),
                )
            });
            let ins_s = avail.has_instret.then(|| {
                stats::compute_stats(
                    &ins[..trials],
                    ops_divisor,
                    0,
                    pre_ins_med.saturating_mul(stats::STATS_SCALE),
                )
            });
            let t_s = avail.has_time.then(|| {
                stats::compute_stats(
                    &tck[..trials],
                    ops_divisor,
                    0,
                    pre_tck_med.saturating_mul(stats::STATS_SCALE),
                )
            });
            let ns_s = t_s
                .as_ref()
                .map(|t| stats::scale_stats_to_ns(t, env.timebase_hz()));
            (c, ins_s, t_s, ns_s)
        } else {
            summarize_batched_trials(
                &cyc[..trials],
                &ins[..trials],
                &tck[..trials],
                ops_divisor,
                &cal,
                avail,
                env.timebase_hz(),
            )
        };

        PendingBench {
            state: self.state,
            out: self.out,
            result: BenchResult {
                id: self.meta.id,
                group: self.meta.group,
                mode: Some(mode),
                parallel: 1,
                unit: self.meta.unit,
                iters_per_trial: ops_divisor,
                trials,
                status: BenchStatus::Pass,
                cycles,
                instret,
                ticks,
                ns,
                throughput_ops_per_sec: None,
                note: self.note,
            },
        }
    }

    fn pending_failed(
        self,
        mode: Option<MeasureMode>,
        parallel: usize,
        iters_per_trial: u64,
        trials: usize,
        reason: FailReason,
    ) -> PendingBench<'meta, 'state, 'cfg, 'out> {
        PendingBench {
            state: self.state,
            out: self.out,
            result: BenchResult {
                id: self.meta.id,
                group: self.meta.group,
                mode,
                parallel,
                unit: self.meta.unit,
                iters_per_trial,
                trials,
                status: BenchStatus::Failed(reason),
                cycles: None,
                instret: None,
                ticks: None,
                ns: None,
                throughput_ops_per_sec: None,
                note: self.note,
            },
        }
    }
}

/// Calibrates timer overhead (`t_overhead`), empty loop overhead (`l_overhead`), and `enough`.
pub fn calibrate(
    clock: &impl Clock,
    profile: Profile,
    empty_loop_fn: fn(u64),
) -> CalibrationRecord {
    let avail = clock.availability();
    let trials = profile.trials().min(stats::MAX_TRIALS);

    let mut t_cyc = [0u64; stats::MAX_TRIALS];
    let mut t_ins = [0u64; stats::MAX_TRIALS];
    let mut t_tck = [0u64; stats::MAX_TRIALS];
    for _ in 0..4 {
        let _ = clock.snap_begin();
        let _ = clock.snap_end();
    }
    for i in 0..trials {
        let b = clock.snap_begin();
        let a = clock.snap_end();
        let d = CounterSnap::delta(a, b);
        t_cyc[i] = d.cycles;
        t_ins[i] = d.instret;
        t_tck[i] = d.ticks;
    }
    let t_cyc_stats = stats::compute_stats(&t_cyc[..trials], 1, 0, 0);
    let t_ins_stats = stats::compute_stats(&t_ins[..trials], 1, 0, 0);
    let t_tck_stats = stats::compute_stats(&t_tck[..trials], 1, 0, 0);

    let mut rdtime_cyc_x100 = 0u64;
    if avail.has_cycle && avail.has_time {
        let mut rt_samples = [0u64; stats::MAX_TRIALS];
        let iters = 64u64;
        let _ = clock.read_ticks();
        for sample in rt_samples.iter_mut().take(trials) {
            let c0 = clock.read_cycles();
            let mut acc = 0u64;
            for _ in 0..iters {
                acc = acc.wrapping_add(clock.read_ticks());
            }
            core::hint::black_box(acc);
            let c1 = clock.read_cycles();
            *sample = c1.wrapping_sub(c0);
        }
        rdtime_cyc_x100 = stats::compute_stats(&rt_samples[..trials], iters, 0, 0).median_x100;
    }
    let is_rdtime_emulated = avail.is_rdtime_emulated
        || rdtime_cyc_x100 > (RDTIME_EMULATED_THRESHOLD_CYCLES * stats::STATS_SCALE);

    let cap = profile.max_batch_iters();
    let mut enough = profile.initial_batch_iters().min(cap);
    loop {
        let b = clock.snap_begin();
        empty_loop_fn(enough);
        let a = clock.snap_end();
        let d = CounterSnap::delta(a, b);
        if enough_reached(d, enough, avail, profile, cap) {
            break;
        }
        enough = enough.saturating_mul(2).min(cap);
    }

    let mut l_cyc = [0u64; stats::MAX_TRIALS];
    let mut l_ins = [0u64; stats::MAX_TRIALS];
    let mut l_tck = [0u64; stats::MAX_TRIALS];
    empty_loop_fn(profile.warmup_iters());
    for i in 0..trials {
        let b = clock.snap_begin();
        empty_loop_fn(enough);
        let a = clock.snap_end();
        let d = CounterSnap::delta(a, b);
        l_cyc[i] = d.cycles;
        l_ins[i] = d.instret;
        l_tck[i] = d.ticks;
    }

    let l_cyc_stats = stats::compute_stats(&l_cyc[..trials], enough, 0, t_cyc_stats.median_x100);
    let l_ins_stats = stats::compute_stats(&l_ins[..trials], enough, 0, t_ins_stats.median_x100);
    let l_tck_stats = stats::compute_stats(&l_tck[..trials], enough, 0, t_tck_stats.median_x100);

    CalibrationRecord {
        profile,
        trials,
        enough_iters: enough,
        loop_overhead_cycles_x100: l_cyc_stats.median_x100,
        loop_overhead_instret_x100: l_ins_stats.median_x100,
        loop_overhead_ticks_x100: l_tck_stats.median_x100,
        timer_overhead_cycles_x100: t_cyc_stats.median_x100,
        timer_overhead_instret_x100: t_ins_stats.median_x100,
        timer_overhead_ticks_x100: t_tck_stats.median_x100,
        rdtime_read_cycles_x100: rdtime_cyc_x100,
        is_rdtime_emulated,
    }
}

/// Executes a slice of performance benchmark specs in fixed or deterministically shuffled order.
pub fn execute_benches<Env: Clock + HartTopology>(
    specs: &[BenchSpec<Env>],
    env: &mut Env,
    state: &mut RunState<'_>,
    out: &mut impl Write,
    order: OrderMode,
    seed: u64,
    mut quarantine_fn: impl FnMut(&mut Env) -> usize,
) {
    assert!(
        specs.len() <= MAX_PHASE_BENCHES,
        "phase benchmark count exceeds MAX_PHASE_BENCHES"
    );
    let mut indices = [0usize; MAX_PHASE_BENCHES];
    for (i, slot) in indices.iter_mut().take(specs.len()).enumerate() {
        *slot = i;
    }
    order_indices(&mut indices[..specs.len()], order, seed);

    for &idx in &indices[..specs.len()] {
        run_single_bench(&specs[idx], env, state, out, &mut quarantine_fn);
    }
}

/// Permutes `indices` deterministically in place when [`OrderMode::Shuffle`] is configured.
pub fn order_indices(indices: &mut [usize], order: OrderMode, mut seed: u64) {
    if order == OrderMode::Fixed || indices.len() < 2 {
        return;
    }
    if seed == 0 {
        seed = 0x9E37_79B9_7F4A_7C15;
    }
    for i in (1..indices.len()).rev() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let j = (seed as usize) % (i + 1);
        indices.swap(i, j);
    }
}

fn run_single_bench<Env: Clock + HartTopology>(
    spec: &BenchSpec<Env>,
    env: &mut Env,
    state: &mut RunState<'_>,
    out: &mut impl Write,
    quarantine_fn: &mut impl FnMut(&mut Env) -> usize,
) {
    let meta = &spec.meta;
    if let Some(skip_reason) = check_bench_gates(meta, env, state) {
        emit_simple_bench(meta, 1, BenchStatus::Skipped(skip_reason), None, state, out);
        return;
    }

    let _ = protocol::write_start_line(StartKind::Bench, meta.id, 1, out);

    let run = BenchRun {
        meta,
        state,
        out,
        note: None,
    };
    let _finished = (spec.run)(env, run);

    let warns = quarantine_fn(env);
    state.summary.quarantine_warnings = state.summary.quarantine_warnings.saturating_add(warns);
}

fn check_bench_gates<Env: HartTopology>(
    meta: &BenchMeta,
    env: &Env,
    state: &mut RunState<'_>,
) -> Option<SkipReason> {
    state.check_common_gates(meta.id, meta.gate(), env.total_harts())
}

fn summarize_batched_trials(
    cyc: &[u64],
    ins: &[u64],
    tck: &[u64],
    iters: u64,
    cal: &CalibrationRecord,
    avail: CounterAvailability,
    timebase_hz: u64,
) -> (
    Option<CounterStats>,
    Option<CounterStats>,
    Option<CounterStats>,
    Option<DerivedNsStats>,
) {
    let cycles = avail.has_cycle.then(|| {
        stats::compute_stats(
            cyc,
            iters,
            cal.loop_overhead_cycles_x100,
            cal.timer_overhead_cycles_x100,
        )
    });
    let instret = avail.has_instret.then(|| {
        stats::compute_stats(
            ins,
            iters,
            cal.loop_overhead_instret_x100,
            cal.timer_overhead_instret_x100,
        )
    });
    let ticks = avail.has_time.then(|| {
        stats::compute_stats(
            tck,
            iters,
            cal.loop_overhead_ticks_x100,
            cal.timer_overhead_ticks_x100,
        )
    });
    let ns = ticks
        .as_ref()
        .map(|t| stats::scale_stats_to_ns(t, timebase_hz));
    (cycles, instret, ticks, ns)
}

fn compute_throughput_ops(
    parallel: usize,
    iters: u64,
    wall_ticks: u64,
    timebase_hz: u64,
) -> Option<u64> {
    if wall_ticks == 0 || timebase_hz == 0 {
        return None;
    }
    let total_ops = (parallel as u128).saturating_mul(iters as u128);
    let ops_per_sec = total_ops.saturating_mul(timebase_hz as u128) / (wall_ticks as u128);
    Some(u64::try_from(ops_per_sec).unwrap_or(u64::MAX))
}

fn enough_reached(
    d: CounterSnap,
    iters: u64,
    avail: CounterAvailability,
    profile: Profile,
    cap: u64,
) -> bool {
    if iters >= cap {
        return true;
    }
    if avail.has_cycle && d.cycles >= profile.min_batch_cycles() {
        return true;
    }
    if !avail.has_cycle && avail.has_instret && d.instret >= profile.min_batch_instret() {
        return true;
    }
    if !avail.has_cycle && !avail.has_instret && avail.has_time && d.ticks >= 100 {
        return true;
    }
    false
}

fn build_parallel_sweep(max_harts: usize, out: &mut [usize; MAX_SWEEP_POINTS]) -> usize {
    let mut len = 0usize;
    let mut p = 1usize;
    while p <= max_harts && len < out.len() {
        out[len] = p;
        len += 1;
        p = p.saturating_mul(2);
    }
    if len > 0 && out[len - 1] != max_harts && len < out.len() {
        out[len] = max_harts;
        len += 1;
    }
    len
}

fn build_single_sample_result<'a>(
    meta: &'a BenchMeta,
    status: BenchStatus,
    sample: CounterSnap,
    clock: &impl Clock,
    note: Option<&'a str>,
) -> BenchResult<'a> {
    let avail = clock.availability();
    let cycles = avail
        .has_cycle
        .then(|| stats::compute_stats(&[sample.cycles], 1, 0, 0));
    let instret = avail
        .has_instret
        .then(|| stats::compute_stats(&[sample.instret], 1, 0, 0));
    let ticks = avail
        .has_time
        .then(|| stats::compute_stats(&[sample.ticks], 1, 0, 0));
    let ns = ticks
        .as_ref()
        .map(|t| stats::scale_stats_to_ns(t, clock.timebase_hz()));
    BenchResult {
        id: meta.id,
        group: meta.group,
        mode: None,
        parallel: 1,
        unit: meta.unit,
        iters_per_trial: 1,
        trials: 1,
        status,
        cycles,
        instret,
        ticks,
        ns,
        throughput_ops_per_sec: None,
        note,
    }
}

fn emit_simple_bench(
    meta: &BenchMeta,
    parallel: usize,
    status: BenchStatus,
    note: Option<&str>,
    state: &mut RunState<'_>,
    out: &mut (impl Write + ?Sized),
) {
    let res = BenchResult {
        id: meta.id,
        group: meta.group,
        mode: None,
        parallel,
        unit: meta.unit,
        iters_per_trial: 0,
        trials: 0,
        status,
        cycles: None,
        instret: None,
        ticks: None,
        ns: None,
        throughput_ops_per_sec: None,
        note,
    };
    record_and_emit(&res, state, out);
}

/// Emits gated `Skipped` or synthetic `Failed` bench frames when multi-hart bringup fails.
pub fn emit_failed_benches<Env: HartTopology>(
    specs: &[BenchSpec<Env>],
    env: &Env,
    state: &mut RunState<'_>,
    out: &mut (impl Write + ?Sized),
    reason: FailReason,
    note: &'static str,
) {
    for spec in specs {
        let meta = &spec.meta;
        if let Some(skip_reason) = check_bench_gates(meta, env, state) {
            emit_simple_bench(meta, 1, BenchStatus::Skipped(skip_reason), None, state, out);
            continue;
        }
        let _ = protocol::write_start_line(StartKind::Bench, meta.id, 1, out);
        emit_simple_bench(meta, 1, BenchStatus::Failed(reason), Some(note), state, out);
    }
}

fn build_failed_bench<'a>(
    meta: &'a BenchMeta,
    mode: Option<MeasureMode>,
    parallel: usize,
    iters_per_trial: u64,
    trials: usize,
    reason: FailReason,
    note: Option<&'a str>,
) -> BenchResult<'a> {
    BenchResult {
        id: meta.id,
        group: meta.group,
        mode,
        parallel,
        unit: meta.unit,
        iters_per_trial,
        trials,
        status: BenchStatus::Failed(reason),
        cycles: None,
        instret: None,
        ticks: None,
        ns: None,
        throughput_ops_per_sec: None,
        note,
    }
}

fn record_and_emit(
    res: &BenchResult<'_>,
    state: &mut RunState<'_>,
    out: &mut (impl Write + ?Sized),
) {
    state.summary.benches_total = state.summary.benches_total.saturating_add(1);
    match res.status {
        BenchStatus::Pass => state.summary.benches_passed += 1,
        BenchStatus::Skipped(_) => state.summary.benches_skipped += 1,
        BenchStatus::HwNative => state.summary.benches_hw_native += 1,
        BenchStatus::DelegatedToS => state.summary.benches_delegated += 1,
        BenchStatus::Failed(_) => state.summary.benches_failed += 1,
    }
    let _ = protocol::write_bench_progress(res, out);
    let _ = protocol::write_bench_line(res, out);
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    extern crate std;

    #[cfg(not(feature = "std"))]
    use std::string::String;

    use super::*;
    use crate::{
        config::RunConfig,
        record::{MetaRecord, SbiCapMask},
    };

    struct StaticTopology {
        total_harts: usize,
    }

    impl HartTopology for StaticTopology {
        fn total_harts(&self) -> usize {
            self.total_harts
        }
    }

    #[test]
    fn emit_failed_benches_respects_gates_and_marks_eligible_cases_failed() {
        fn noop_run(_env: &mut StaticTopology, _run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
            unreachable!("noop_run should not be called by emit_failed_benches")
        }

        let specs = [
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
                run: noop_run,
            },
            BenchSpec {
                meta: BenchMeta {
                    id: "rfnc/sfence_vma.all",
                    group: BenchGroup::Rfnc,
                    unit: "call",
                    required_ext: Some(SbiExtensionId::Rfnc),
                    min_harts: 2,
                    flags: BenchFlags::empty(),
                    max_batch_iters: None,
                },
                run: noop_run,
            },
        ];

        let env = StaticTopology { total_harts: 4 };
        let mut state = RunState::new(
            RunConfig::parse_bootargs("mode=bench filter=rfnc/"),
            SbiCapMask::BASE | SbiCapMask::RFNC,
        );
        let mut out = String::new();
        emit_failed_benches(
            &specs,
            &env,
            &mut state,
            &mut out,
            FailReason::Timeout,
            "secondary-hart-bringup-failed",
        );

        assert_eq!(state.summary.benches_total, 2);
        assert_eq!(state.summary.benches_skipped, 1);
        assert_eq!(state.summary.benches_failed, 1);
        assert!(out.contains("\"id\":\"spi/send_ipi.one\",\"group\":\"spi\""));
        assert!(out.contains("\"status\":\"SKIPPED\",\"skip_reason\":\"filtered_out\""));
        assert!(out.contains("\"id\":\"rfnc/sfence_vma.all\",\"group\":\"rfnc\""));
        assert!(out.contains("\"status\":\"FAIL\",\"fail_reason\":\"timeout\""));
    }

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
}

#[cfg(all(test, feature = "std"))]
mod std_tests {
    extern crate std;

    use core::cell::Cell;
    use std::{
        sync::{Arc, Barrier},
        thread,
        time::Instant,
    };

    use super::*;
    use crate::{config::RunConfig, record::SbiCapMask};

    struct HostRuntime {
        origin: Instant,
        harts: usize,
        total_harts: usize,
        fail_batch: bool,
        zero_ops: bool,
        observed_sweep_iters: Cell<u64>,
    }

    impl HostRuntime {
        fn new(harts: usize) -> Self {
            Self {
                origin: Instant::now(),
                harts,
                total_harts: harts,
                fail_batch: false,
                zero_ops: false,
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
            self.total_harts
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
        let pending = run.measure_batched(env, |env, iters| {
            host_spin_loop(iters.saturating_mul(16));
            if env.fail_batch {
                BatchOutcome::from_errors(0x1, iters)
            } else if env.zero_ops {
                BatchOutcome::ok(0)
            } else {
                BatchOutcome::ok(iters)
            }
        });
        pending.commit()
    }

    #[test]
    fn honors_per_case_caps_teardown_failure_and_zero_ops_rejection() {
        let mut env = HostRuntime::new(1);
        env.total_harts = 4;
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

        env.zero_ops = true;
        let mut zero_out = String::new();
        execute_benches(
            &specs[..1],
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

        let mut env = HostRuntime::new(3);
        let cal = calibrate(&env, Profile::Normal, host_spin_loop);
        let mut state = RunState::new(
            RunConfig::parse_bootargs("profile=normal"),
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
        assert_eq!(state.summary.benches_passed, 3);
        assert!(out.contains("\"parallel\":1"));
        assert!(out.contains("\"parallel\":2"));
        assert!(out.contains("\"parallel\":3"));
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
            RunConfig::parse_bootargs("profile=normal"),
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
        assert_eq!(fail_state.summary.benches_failed, 3);
        assert!(!fail_out.contains("\"status\":\"PASS\""));
    }
}
