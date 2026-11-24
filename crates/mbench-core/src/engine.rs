//! Calibration, benchmark dispatch, and counter coordination.

use core::fmt::Write;

use crate::{
    config::{OrderMode, Profile},
    protocol,
    record::{
        BenchGroup, BenchStatus, CalibrationRecord, CaseFlags, CaseGate, CounterAvailability,
        FailReason, HartTopology, RunState, SbiExtensionId, SkipReason, StartKind,
    },
    stats,
};

mod run;
use run::emit_simple_bench;
pub use run::{BenchRun, FinishedBench, PendingBench, PendingSweep};

/// Maximum number of harts collected per trial in [`crate::record::MeasureMode::ParallelSweep`].
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
    /// Raw cycle counter value.
    pub cycles: u64,
    /// Raw retired-instruction counter value.
    pub instret: u64,
    /// Raw timer counter value.
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

/// Counter source used for calibration and benchmark measurement.
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
    /// Elapsed counter values for this worker.
    pub delta: CounterSnap,
    /// Accumulated error bits; zero indicates successful execution.
    pub error_bits: usize,
}

/// Worker function invoked simultaneously across `parallel` harts (`slot_idx`, `parallel`, `iters`).
pub type ParallelWorkFn = fn(usize, usize, u64) -> ParallelSample;

/// Multi-hart coordinator seam used by [`crate::record::MeasureMode::ParallelSweep`].
pub trait HartCoordinator: HartTopology {
    /// Returns the number of online harts available for parallel execution (at least 1).
    fn online_harts(&self) -> usize;

    /// Runs `work_fn(slot_idx, parallel, iters)` concurrently across `parallel` harts starting together.
    ///
    /// Implementations must fill `out_samples[..parallel]` in hart slot order.
    ///
    /// # Errors
    ///
    /// Returns a failure when worker dispatch or collection fails. Callers must discard
    /// the sample buffer on error.
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
    /// SBI extension required to execute the case, if any.
    pub required_ext: Option<SbiExtensionId>,
    /// Minimum hart count after applying the configured limit.
    pub min_harts: usize,
    /// Execution permissions required by the case.
    pub flags: BenchFlags,
    /// Optional per-case cap on batch iterations, including warmup.
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
    /// Accumulated error bits; zero indicates successful execution.
    pub error_bits: usize,
    /// Number of operations actually completed by the batch.
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
/// Benchmark specification executed by [`execute_benches`].
pub struct BenchSpec<Env> {
    /// Static benchmark metadata and measurement limits.
    pub meta: BenchMeta,
    /// Callback that consumes the run handle and finishes all result emissions.
    pub run: fn(&mut Env, BenchRun<'_, '_, '_, '_>) -> FinishedBench,
}

impl<Env> Clone for BenchSpec<Env> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Env> Copy for BenchSpec<Env> {}

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

/// Executes a slice of performance benchmark specs in fixed or deterministically shuffled order.
///
/// # Panics
///
/// Panics if `specs` contains more than [`MAX_PHASE_BENCHES`] entries.
/// Panics from environment callbacks, benchmark callbacks, or the output writer propagate.
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

    let run = BenchRun::new(meta, state, out);
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

#[cfg(test)]
mod tests;
