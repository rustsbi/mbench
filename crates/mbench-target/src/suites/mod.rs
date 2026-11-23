//! Safe (`#![forbid(unsafe_code)]`) benchmark and functional conformance suites.

#![forbid(unsafe_code)]

pub(crate) mod baseline;
pub(crate) mod conformance;
pub(crate) mod ext_base;
pub(crate) mod ext_dbtr;
pub(crate) mod ext_hsm;
pub(crate) mod ext_mpxy;
pub(crate) mod ext_pmu;
pub(crate) mod ext_rfnc;
pub(crate) mod ext_scale;
pub(crate) mod ext_spi;
pub(crate) mod ext_sse;
pub(crate) mod ext_sys;
pub(crate) mod ext_time;
pub(crate) mod traps_emul;

use core::fmt::Write;

use mbench_core::{
    check,
    config::{RunConfig, effective_max_harts},
    engine::{self, BenchSpec},
    protocol,
    record::{BenchGroup, RunState, SbiCapMask, SbiExtensionId},
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
    if let Some(mh) = cfg.max_harts {
        let _ = writeln!(
            &mut con,
            "[mbench] boot: mode={} harts={} max_harts={} timebase={}Hz console={} sstc={} h={} sbi={:#x}",
            cfg.mode.as_str(),
            meta.hart_count,
            mh,
            meta.timebase_hz,
            meta.console_backend,
            meta.has_sstc,
            meta.has_h_ext,
            meta.sbi_spec_version,
        );
    } else {
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
    }

    let mut state = RunState::new(cfg, platform.caps().extensions);
    let seed = cfg
        .seed
        .unwrap_or_else(|| platform.boot_ticks() ^ (platform.info().hart_count as u64));

    if cfg.mode.runs_checks() {
        run_check_groups(conformance::SINGLE_HART_GROUPS, platform, &mut state);
    }

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

        // Phase 2: Single-hart SBI extensions & implicit trap-and-emulate suite.
        run_bench_slice(&SINGLE_HART_SPECS, platform, &mut state, seed ^ 2);
    }

    // Phase 3: Multi-hart worker pool (SMP conformance checks, sPI, RFNC, ParallelSweep scaling).
    let effective_harts = effective_max_harts(platform.info().hart_count, cfg.max_harts);
    let mut smp_started = false;
    let mut smp_bringup_ok = true;
    if any_multi_hart_work(&cfg, platform.caps().extensions, effective_harts) {
        match platform.bringup_secondary_harts(effective_harts) {
            Ok(_) => {
                smp_started = true;
            }
            Err(err) => {
                smp_bringup_ok = false;
                let _ = writeln!(
                    &mut con,
                    "[mbench] warn: secondary hart bringup failed: {err:?}"
                );
                if cfg.mode.runs_checks() {
                    check::emit_synthetic_check_result(
                        "conformance/smp_bringup",
                        "smp_bringup_failed",
                        err,
                        Some("secondary-hart-bringup-failed"),
                        &mut state,
                        &mut con,
                    );
                }
                if cfg.mode.runs_benches() {
                    engine::emit_failed_benches(
                        &MULTI_HART_SPECS,
                        platform,
                        &mut state,
                        &mut con,
                        err,
                        "secondary-hart-bringup-failed",
                    );
                }
            }
        }
    }

    if smp_bringup_ok {
        if cfg.mode.runs_checks() {
            run_check_groups(conformance::MULTI_HART_GROUPS, platform, &mut state);
        }
        if cfg.mode.runs_benches() {
            run_bench_slice(&MULTI_HART_SPECS, platform, &mut state, seed ^ 3);
        }
    }

    if smp_started && let Err(err) = platform.stop_secondary_harts() {
        let _ = writeln!(
            &mut con,
            "[mbench] warn: secondary hart stop_all failed: {err:?}"
        );
        check::emit_synthetic_check_result(
            "conformance/smp_stop",
            "smp_stop_failed",
            err,
            Some("secondary-hart-stop-failed"),
            &mut state,
            &mut con,
        );
    }

    // Phase 4: HSM conformance & lifecycle suite (secondary harts STOPPED).
    if cfg.mode.runs_checks() {
        run_check_groups(conformance::HSM_GROUPS, platform, &mut state);
    }
    if cfg.mode.runs_benches() {
        run_bench_slice(ext_hsm::SPECS, platform, &mut state, seed ^ 4);

        // Phase 5: Opt-in I/O (DBCN) and destructive (SUSP) benchmarks.
        run_bench_slice(
            ext_sys::IO_DESTRUCTIVE_SPECS,
            platform,
            &mut state,
            seed ^ 5,
        );
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

fn any_multi_hart_work(cfg: &RunConfig<'_>, exts: SbiCapMask, effective_harts: usize) -> bool {
    if effective_harts <= 1 || !exts.contains_ext(SbiExtensionId::Hsm) {
        return false;
    }
    let matches_filter = |id: &str| cfg.filter.is_none_or(|flt| id.contains(flt));
    let has_ext = |req: Option<SbiExtensionId>| req.is_none_or(|ext| exts.contains_ext(ext));

    if cfg.mode.runs_checks() {
        for group in conformance::MULTI_HART_GROUPS {
            for case in group.cases {
                if case.meta.gate.min_harts >= 2
                    && has_ext(case.meta.gate.required_ext)
                    && matches_filter(case.meta.id)
                {
                    return true;
                }
            }
        }
    }
    if cfg.mode.runs_benches() {
        for spec in MULTI_HART_SPECS {
            if (spec.meta.min_harts >= 2 || spec.meta.group == BenchGroup::Scale)
                && has_ext(spec.meta.required_ext)
                && matches_filter(spec.meta.id)
            {
                return true;
            }
        }
    }
    false
}

fn run_check_groups(
    groups: &[check::CheckGroup<'_, Platform>],
    platform: &mut Platform,
    state: &mut RunState<'_>,
) {
    let mut con = platform.console();
    check::execute_check_groups(
        groups,
        platform,
        state,
        &mut con,
        Platform::quarantine_reset,
    );
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

const SINGLE_HART_SPECS: [BenchSpec<Platform>; 43] = concat_specs(&[
    ext_base::SPECS,
    ext_time::SPECS,
    ext_pmu::SPECS,
    ext_sys::SINGLE_HART_SPECS,
    ext_sse::SPECS,
    ext_dbtr::SPECS,
    ext_mpxy::SPECS,
    traps_emul::SPECS,
]);

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
