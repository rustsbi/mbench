//! Safe (`#![forbid(unsafe_code)]`) benchmark and functional conformance suites.

#![forbid(unsafe_code)]

use core::fmt::Write;

use mbench_core::{config::RunConfig, protocol, record::RunState};

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

    let state = RunState::new(cfg, platform.caps().extensions);
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
