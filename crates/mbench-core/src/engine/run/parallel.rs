use super::{
    super::{
        Clock, HartCoordinator, MAX_SWEEP_HARTS, MAX_SWEEP_POINTS, ParallelSample, ParallelWorkFn,
        enough_reached,
    },
    BenchRun, PendingSweep, build_failed_bench, summarize_trials,
};
use crate::{
    config, protocol,
    record::{BenchResult, FailReason, MeasureMode, StartKind},
    stats,
};

impl<'meta, 'state, 'cfg, 'out> BenchRun<'meta, 'state, 'cfg, 'out> {
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

            let counters = summarize_trials(
                [&cyc[..trials], &ins[..trials], &tck[..trials]],
                iters,
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
                ],
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

            let mut result = self.measured_result(
                MeasureMode::ParallelSweep,
                parallel,
                iters,
                trials,
                counters,
            );
            result.throughput_ops_per_sec = throughput;
            results[count] = Some(result);
            count += 1;
        }
        PendingSweep {
            state: self.state,
            out: self.out,
            results,
            count,
        }
    }
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
