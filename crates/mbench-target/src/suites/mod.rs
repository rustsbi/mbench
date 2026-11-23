//! Safe (`#![forbid(unsafe_code)]`) benchmark and functional conformance suites.

#![forbid(unsafe_code)]

pub(crate) mod baseline;

use core::fmt::Write;

use mbench_core::{
    config::RunConfig,
    engine::{self, BenchSpec},
    protocol,
    record::RunState,
};

use crate::platform::Platform;

/// Executes `body` `iters` times with uniform loop overhead across calibration and suites.
#[macro_export]
macro_rules! mbench_loop {
    ($iters:expr, $body:block) => {{
        let mut _rem = $iters;
        while _rem > 0 {
            core::hint::black_box(_rem);
            $body
            _rem -= 1;
        }
    }};
}

/// Empty loop calibrated as LMbench `l_overhead`, matching [`mbench_loop!`] instruction-for-instruction.
pub(crate) fn empty_bench_loop(iters: u64) {
    mbench_loop!(iters, {});
}

/// Runs the `mbench` pipeline from metadata emission through mode-selected checks, benches, and shutdown.
pub(crate) fn run_all(platform: &mut Platform) -> ! {
    let cfg = RunConfig::parse_bootargs(platform.info().bootargs);
    let mut con = platform.console();
    let meta = platform.meta_record();
    let _ = protocol::write_meta_line(&meta, &mut con);
    let _ = writeln!(
        &mut con,
        "[mbench] boot: mode={} harts={} timebase={}Hz console={} sstc={} h={} sbi={:#x}",
        cfg.mode.as_str(),
        meta.hart_count,
        meta.timebase_hz,
        meta.console_backend,
        meta.has_sstc,
        meta.has_h_ext,
        meta.sbi_spec_version,
    );

    let mut state = RunState::new(cfg, platform.caps().extensions);
    let seed = cfg
        .seed
        .unwrap_or_else(|| platform.boot_ticks() ^ (platform.info().hart_count as u64));

    if cfg.mode.runs_benches() {
        let cal = engine::calibrate(platform, cfg.profile, empty_bench_loop);
        let _ = protocol::write_cal_line(&cal, &mut con);
        let _ = writeln!(
            &mut con,
            "[mbench] cal: profile={} trials={} enough={} l_cyc={}.{:02} t_cyc={}.{:02} rdtime_emul={}",
            cal.profile.as_str(),
            cal.trials,
            cal.enough_iters,
            cal.loop_overhead_cycles_x100 / 100,
            cal.loop_overhead_cycles_x100 % 100,
            cal.timer_overhead_cycles_x100 / 100,
            cal.timer_overhead_cycles_x100 % 100,
            cal.is_rdtime_emulated,
        );
        state.set_calibration(cal);

        // Phase 1: Calibration baselines.
        run_bench_slice(baseline::SPECS, platform, &mut state, seed ^ 1);
    }

    // Phase 6: Final summary frame and clean SRST shutdown.
    let _ = protocol::write_end_line(&state.summary, &mut con);
    let _ = writeln!(
        &mut con,
        "[mbench] done: checks={}/{}/{} (assert={}/{}) benches={}/{} (hw_nat={} deleg={} skip={} fail={}) warn={}",
        state.summary.checks_passed,
        state.summary.checks_skipped,
        state.summary.checks_failed,
        state.summary.check_assertions_passed,
        state.summary.check_assertions_total,
        state.summary.benches_passed,
        state.summary.benches_total,
        state.summary.benches_hw_native,
        state.summary.benches_delegated,
        state.summary.benches_skipped,
        state.summary.benches_failed,
        state.summary.quarantine_warnings,
    );

    platform.shutdown()
}

fn run_bench_slice(
    specs: &[BenchSpec<Platform>],
    platform: &mut Platform,
    state: &mut RunState<'_>,
    seed: u64,
) {
    let mut con = platform.console();
    engine::execute_benches(
        specs,
        platform,
        state,
        &mut con,
        state.config.order,
        seed,
        Platform::quarantine_reset,
    );
}
