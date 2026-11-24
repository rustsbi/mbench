use core::fmt::Write;

use super::{BatchOutcome, BenchMeta, Clock, CounterSnap, MAX_SWEEP_POINTS, enough_reached};
use crate::{
    protocol,
    record::{
        BenchResult, BenchStatus, CounterAvailability, FailReason, MeasureMode, RunState,
        SkipReason,
    },
    stats::{self, CounterStats, DerivedNsStats},
};

mod parallel;

/// Proof token returned once a [`super::BenchSpec::run`] invocation has emitted its wire frame(s).
#[derive(Debug)]
pub struct FinishedBench {
    _sealed: (),
}
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
            fail_bench_result(&mut self.result, reason);
        }
        self.commit()
    }

    /// Replaces the pending outcome with `Failed(reason)` (unless already failed) and emits it.
    pub fn fail(mut self, reason: FailReason) -> FinishedBench {
        if !matches!(self.result.status, BenchStatus::Failed(_)) {
            fail_bench_result(&mut self.result, reason);
        }
        self.commit()
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
/// Linear measurement handle passed by value to each [`super::BenchSpec::run`] invocation.
#[must_use = "BenchRun must conclude with skip, fail, hw_native, delegated_to_s, or measure_*"]
pub struct BenchRun<'meta, 'state, 'cfg, 'out> {
    meta: &'meta BenchMeta,
    state: &'state mut RunState<'cfg>,
    out: &'out mut dyn Write,
    note: Option<&'static str>,
}

impl<'meta, 'state, 'cfg, 'out> BenchRun<'meta, 'state, 'cfg, 'out> {
    pub(super) fn new(
        meta: &'meta BenchMeta,
        state: &'state mut RunState<'cfg>,
        out: &'out mut dyn Write,
    ) -> Self {
        Self {
            meta,
            state,
            out,
            note: None,
        }
    }

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
    fn measured_result(
        &self,
        mode: MeasureMode,
        parallel: usize,
        iters_per_trial: u64,
        trials: usize,
        counters: CounterSummaries,
    ) -> BenchResult<'meta> {
        BenchResult {
            id: self.meta.id,
            group: self.meta.group,
            mode: Some(mode),
            parallel,
            unit: self.meta.unit,
            iters_per_trial,
            trials,
            status: BenchStatus::Pass,
            cycles: counters.cycles,
            instret: counters.instret,
            ticks: counters.ticks,
            ns: counters.ns,
            throughput_ops_per_sec: None,
            note: self.note,
        }
    }
    fn effective_max_iters(&self) -> u64 {
        let profile_max = self.state.config.profile.max_batch_iters();
        match self.meta.max_batch_iters {
            Some(cap) => profile_max.min(cap).max(1),
            None => profile_max,
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
            result: build_failed_bench(
                self.meta,
                mode,
                parallel,
                iters_per_trial,
                trials,
                reason,
                self.note,
            ),
        }
    }
}

struct CounterSummaries {
    cycles: Option<CounterStats>,
    instret: Option<CounterStats>,
    ticks: Option<CounterStats>,
    ns: Option<DerivedNsStats>,
}

// Each overhead pair contains scaled per-operation and per-batch costs.
fn summarize_trials(
    raw: [&[u64]; 3],
    iters: u64,
    overheads: [(u64, u64); 3],
    avail: CounterAvailability,
    timebase_hz: u64,
) -> CounterSummaries {
    let enabled = [avail.has_cycle, avail.has_instret, avail.has_time];
    let [cycles, instret, ticks] = core::array::from_fn(|i| {
        enabled[i].then(|| stats::compute_stats(raw[i], iters, overheads[i].0, overheads[i].1))
    });
    let ns = ticks
        .as_ref()
        .map(|t| stats::scale_stats_to_ns(t, timebase_hz));
    CounterSummaries {
        cycles,
        instret,
        ticks,
        ns,
    }
}

fn build_single_sample_result<'a>(
    meta: &'a BenchMeta,
    status: BenchStatus,
    sample: CounterSnap,
    clock: &impl Clock,
    note: Option<&'a str>,
) -> BenchResult<'a> {
    let avail = clock.availability();
    let CounterSummaries {
        cycles,
        instret,
        ticks,
        ns,
    } = summarize_trials(
        [&[sample.cycles], &[sample.instret], &[sample.ticks]],
        1,
        [(0, 0); 3],
        avail,
        if avail.has_time {
            clock.timebase_hz()
        } else {
            0
        },
    );
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

pub(in crate::engine) fn emit_simple_bench(
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
fn fail_bench_result(res: &mut BenchResult<'_>, reason: FailReason) {
    res.status = BenchStatus::Failed(reason);
    res.cycles = None;
    res.instret = None;
    res.ticks = None;
    res.ns = None;
    res.throughput_ops_per_sec = None;
}

impl<'meta, 'state, 'cfg, 'out> BenchRun<'meta, 'state, 'cfg, 'out> {
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

        let overheads = if preamble.is_some() {
            [
                (0, pre_cyc_med.saturating_mul(stats::STATS_SCALE)),
                (0, pre_ins_med.saturating_mul(stats::STATS_SCALE)),
                (0, pre_tck_med.saturating_mul(stats::STATS_SCALE)),
            ]
        } else {
            [
                (
                    cal.loop_overhead_cycles_x100,
                    cal.timer_overhead_cycles_x100,
                ),
                (
                    cal.loop_overhead_instret_x100,
                    cal.timer_overhead_instret_x100,
                ),
                (cal.loop_overhead_ticks_x100, cal.timer_overhead_ticks_x100),
            ]
        };
        let counters = summarize_trials(
            [&cyc[..trials], &ins[..trials], &tck[..trials]],
            ops_divisor,
            overheads,
            avail,
            if preamble.is_none() || avail.has_time {
                env.timebase_hz()
            } else {
                0
            },
        );
        let result = self.measured_result(mode, 1, ops_divisor, trials, counters);

        PendingBench {
            state: self.state,
            out: self.out,
            result,
        }
    }
}

impl<'meta, 'state, 'cfg, 'out> BenchRun<'meta, 'state, 'cfg, 'out> {
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

        let counters = summarize_trials(
            [
                &trial_cyc[..trials],
                &trial_ins[..trials],
                &trial_tck[..trials],
            ],
            1,
            [
                (0, cal.timer_overhead_cycles_x100),
                (0, cal.timer_overhead_instret_x100),
                (0, cal.timer_overhead_ticks_x100),
            ],
            avail,
            if avail.has_time { env.timebase_hz() } else { 0 },
        );
        let result = self.measured_result(
            MeasureMode::PairedEvent,
            1,
            samples_per_trial as u64,
            trials,
            counters,
        );

        PendingBench {
            state: self.state,
            out: self.out,
            result,
        }
    }
}
