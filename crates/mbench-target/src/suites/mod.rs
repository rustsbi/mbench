//! Safe (`#![forbid(unsafe_code)]`) benchmark and functional conformance suites.

#![forbid(unsafe_code)]

pub(crate) mod baseline;
pub(crate) mod ext_base;
pub(crate) mod ext_hsm;
pub(crate) mod ext_rfnc;
pub(crate) mod ext_scale;
pub(crate) mod ext_spi;
pub(crate) mod ext_time;

use core::fmt::Write;

use mbench_core::{
    config::RunConfig,
    engine::{self, BenchSpec},
    protocol,
    record::{RunState, SbiExtensionId},
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

        // Phase 2: Single-hart SBI extensions.
        run_bench_slice(&SINGLE_HART_SPECS, platform, &mut state, seed ^ 2);
    }

    // Phase 3: Multi-hart worker pool (sPI, RFNC, ParallelSweep scaling).
    let mut smp_started = false;
    let mut smp_bringup_ok = true;
    if cfg.mode.runs_benches()
        && platform.info().hart_count > 1
        && platform.caps().extensions.contains_ext(SbiExtensionId::Hsm)
    {
        match platform.bringup_secondary_harts() {
            Ok(_) => {
                smp_started = true;
            }
            Err(err) => {
                smp_bringup_ok = false;
                let _ = writeln!(
                    &mut con,
                    "[mbench] warn: secondary hart bringup failed: {err:?}"
                );
            }
        }
    }

    if smp_bringup_ok && cfg.mode.runs_benches() {
        run_bench_slice(&MULTI_HART_SPECS, platform, &mut state, seed ^ 3);
    }

    if smp_started && let Err(err) = platform.stop_secondary_harts() {
        let _ = writeln!(
            &mut con,
            "[mbench] warn: secondary hart stop_all failed: {err:?}"
        );
    }

    // Phase 4: HSM lifecycle suite (secondary harts STOPPED).
    if cfg.mode.runs_benches() {
        run_bench_slice(ext_hsm::SPECS, platform, &mut state, seed ^ 4);
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

const SINGLE_HART_LEN: usize = ext_base::SPECS.len() + ext_time::SPECS.len();
const SINGLE_HART_SPECS: [BenchSpec<Platform>; SINGLE_HART_LEN] =
    concat_specs(&[ext_base::SPECS, ext_time::SPECS]);

const MULTI_HART_SPECS: [BenchSpec<Platform>; 19] =
    concat_specs(&[ext_spi::SPECS, ext_rfnc::SPECS, ext_scale::SPECS]);

const fn concat_specs<const N: usize>(
    groups: &[&[BenchSpec<Platform>]],
) -> [BenchSpec<Platform>; N] {
    assert!(N > 0, "empty benchmark group");
    let first = groups[0][0];
    let mut out = [first; N];
    let mut dst = 0usize;
    let mut g = 0usize;
    while g < groups.len() {
        let slice = groups[g];
        let mut i = 0usize;
        while i < slice.len() {
            out[dst] = slice[i];
            dst += 1;
            i += 1;
        }
        g += 1;
    }
    assert!(dst == N, "concat_specs length mismatch");
    out
}
