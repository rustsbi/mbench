//! Capture completeness, protocol integrity, and requirement-gating validator.

use std::collections::BTreeMap;

use crate::{
    record::{BenchGroup, SbiExtensionId, SkipReason, StartKind},
    wire::{
        BenchFrame, BenchStatusTag, CheckFrame, CheckStatusTag, StartFrame, WireFrame,
        parse_capture, parse_wire_line,
    },
};

/// Validation constraints enforced against a saved `.jsonl` capture or raw serial log.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidationPolicy {
    pub require_closed_starts: bool,
    pub expect_harts: Option<usize>,
    pub require_extensions: Vec<SbiExtensionId>,
    pub require_check_pass: Vec<String>,
    pub min_checks_passed: Option<usize>,
    pub min_effective_benches: Option<usize>,
    pub min_smp_effective_benches: Option<usize>,
    pub max_quarantine_warnings: Option<usize>,
    pub forbidden_patterns: Vec<String>,
}

/// Summary metrics extracted from a validated capture.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ValidationSummary {
    pub hart_count: usize,
    pub extensions_count: usize,
    pub checks_total: usize,
    pub checks_passed: usize,
    pub checks_skipped: usize,
    pub checks_failed: usize,
    pub benches_total: usize,
    pub benches_effective: usize,
    pub benches_smp_effective: usize,
    pub benches_skipped: usize,
    pub benches_failed: usize,
    pub quarantine_warnings: usize,
}

/// Returns `true` when a benchmark status represents a real measured or native/delegated outcome.
pub const fn is_effective_bench_status(status: BenchStatusTag) -> bool {
    matches!(
        status,
        BenchStatusTag::Pass | BenchStatusTag::HwNative | BenchStatusTag::DelegatedToS
    )
}

/// Returns `true` when a benchmark exercises multi-hart concurrency or scaling.
pub const fn is_smp_bench(bench: &BenchFrame) -> bool {
    bench.parallel >= 2
        || matches!(
            bench.group,
            BenchGroup::Spi | BenchGroup::Rfnc | BenchGroup::Scale
        )
}

/// Parses a forbidden-pattern file (one fixed substring per line, ignoring blank and `#` lines).
///
/// Fails closed when the file contains zero active patterns.
pub fn parse_forbidden_patterns(content: &str) -> Result<Vec<String>, String> {
    let patterns: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect();
    if patterns.is_empty() {
        return Err(String::from(
            "forbidden pattern file contains no active patterns",
        ));
    }
    Ok(patterns)
}

/// Validates wire integrity, END accounting, and policy requirements on a capture or serial log.
pub fn validate_capture(
    text: &str,
    policy: &ValidationPolicy,
) -> Result<ValidationSummary, Vec<String>> {
    let mut errors = Vec::new();

    check_forbidden_lines(text, &policy.forbidden_patterns, &mut errors);
    audit_stream_framing(text, policy.require_closed_starts, &mut errors);

    let cap = match parse_capture("capture", text) {
        Ok(c) => c,
        Err(err) => {
            errors.push(format!("capture parse failed: {err}"));
            return Err(errors);
        }
    };

    if let Some(panic) = &cap.panic {
        errors.push(format!(
            "target panicked during capture (reason={:?}, message={:?}, scause={:?}, sepc={:?})",
            panic.reason, panic.message, panic.scause, panic.sepc
        ));
    }

    let mut summary = ValidationSummary::default();

    let Some(meta) = &cap.meta else {
        errors.push(String::from("missing @@MBENCH:META frame"));
        return Err(errors);
    };
    summary.hart_count = meta.hart_count;
    summary.extensions_count = meta.extensions.len();

    let Some(end) = cap.end else {
        errors.push(String::from("missing @@MBENCH:END frame"));
        return Err(errors);
    };

    let check_counts = count_checks(&cap.checks, &mut errors);
    let bench_counts = count_benches(&cap.benches, &mut errors);

    summary.checks_total = check_counts.total;
    summary.checks_passed = check_counts.passed;
    summary.checks_skipped = check_counts.skipped;
    summary.checks_failed = check_counts.failed;
    summary.benches_total = bench_counts.total;
    summary.benches_effective = bench_counts.effective;
    summary.benches_smp_effective = bench_counts.smp_effective;
    summary.benches_skipped = bench_counts.skipped;
    summary.benches_failed = bench_counts.failed;
    summary.quarantine_warnings = end.quarantine_warnings;

    verify_end_consistency(&end, &check_counts, &bench_counts, &mut errors);

    if let Some(max_warn) = policy.max_quarantine_warnings
        && end.quarantine_warnings > max_warn
    {
        errors.push(format!(
            "quarantine_warnings ({}) exceeds maximum allowed ({max_warn})",
            end.quarantine_warnings
        ));
    }

    if let Some(expected_harts) = policy.expect_harts
        && meta.hart_count != expected_harts
    {
        errors.push(format!(
            "expected hart_count={expected_harts}, observed {}",
            meta.hart_count
        ));
    }

    for ext in &policy.require_extensions {
        if !meta.extensions.contains(ext) {
            errors.push(format!("missing required SBI extension '{}'", ext.name()));
        }
    }

    let check_map: BTreeMap<&str, &CheckFrame> =
        cap.checks.iter().map(|c| (c.id.as_str(), c)).collect();
    for id in &policy.require_check_pass {
        match check_map.get(id.as_str()) {
            None => errors.push(format!("missing required check '{id}'")),
            Some(chk) if chk.status != CheckStatusTag::Pass => errors.push(format!(
                "required check '{id}' did not PASS (status={:?}, skip_reason={:?}, fail_reason={:?})",
                chk.status, chk.skip_reason, chk.fail_reason
            )),
            Some(_) => {}
        }
    }

    if let Some(min_passed) = policy.min_checks_passed
        && check_counts.passed < min_passed
    {
        errors.push(format!(
            "checks_passed ({}) is below required minimum ({min_passed})",
            check_counts.passed
        ));
    }

    if let Some(min_eff) = policy.min_effective_benches
        && bench_counts.effective < min_eff
    {
        errors.push(format!(
            "effective benchmarks ({}) is below required minimum ({min_eff})",
            bench_counts.effective
        ));
    }

    if let Some(min_smp_eff) = policy.min_smp_effective_benches
        && bench_counts.smp_effective < min_smp_eff
    {
        errors.push(format!(
            "effective SMP benchmarks ({}) is below required minimum ({min_smp_eff})",
            bench_counts.smp_effective
        ));
    }

    if errors.is_empty() {
        Ok(summary)
    } else {
        Err(errors)
    }
}

fn check_forbidden_lines(text: &str, patterns: &[String], errors: &mut Vec<String>) {
    if patterns.is_empty() {
        return;
    }
    for (line_idx, line) in text.lines().enumerate() {
        for pat in patterns {
            if !pat.is_empty() && line.contains(pat.as_str()) {
                errors.push(format!(
                    "forbidden pattern '{pat}' matched at line {}: {}",
                    line_idx + 1,
                    line.trim()
                ));
            }
        }
    }
}

fn audit_stream_framing(text: &str, require_closed_starts: bool, errors: &mut Vec<String>) {
    let mut open_starts: Vec<StartFrame> = Vec::new();
    let mut end_count = 0usize;

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let has_wire_marker = raw_line.contains("@@MBENCH:");
        let parsed = match parse_wire_line(raw_line) {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                if has_wire_marker {
                    errors.push(format!(
                        "malformed or unrecognized @@MBENCH wire line at line {line_no}"
                    ));
                }
                continue;
            }
            Err(err) => {
                errors.push(format!("invalid wire frame at line {line_no}: {err}"));
                continue;
            }
        };

        if end_count > 0 && !matches!(parsed, WireFrame::Env(_) | WireFrame::Panic(_)) {
            errors.push(format!(
                "unexpected wire frame after @@MBENCH:END at line {line_no}"
            ));
        }

        match parsed {
            WireFrame::Start(start) => {
                let exists = open_starts.iter().any(|s| {
                    s.kind == start.kind && s.id == start.id && s.parallel == start.parallel
                });
                if !exists {
                    open_starts.push(start);
                }
            }
            WireFrame::Check(chk) => {
                if chk.skip_reason != Some(SkipReason::ResumedPast) {
                    open_starts.retain(|s| !(s.kind == StartKind::Check && s.id == chk.id));
                }
            }
            WireFrame::Bench(b) => {
                if b.skip_reason != Some(SkipReason::ResumedPast) {
                    open_starts.retain(|s| {
                        !(s.kind == StartKind::Bench && s.id == b.id && s.parallel == b.parallel)
                    });
                }
            }
            WireFrame::End(_) => {
                end_count += 1;
                if require_closed_starts && !open_starts.is_empty() {
                    for unclosed in open_starts.drain(..) {
                        errors.push(format!(
                            "unclosed @@MBENCH:START before END: {:?} '{}' (p={})",
                            unclosed.kind, unclosed.id, unclosed.parallel
                        ));
                    }
                }
            }
            WireFrame::Env(_) | WireFrame::Meta(_) | WireFrame::Cal(_) | WireFrame::Panic(_) => {}
        }
    }

    if require_closed_starts {
        for unclosed in open_starts {
            errors.push(format!(
                "unclosed @@MBENCH:START at end of log: {:?} '{}' (p={})",
                unclosed.kind, unclosed.id, unclosed.parallel
            ));
        }
    }

    if end_count > 1 {
        errors.push(format!(
            "expected a single @@MBENCH:END frame, found {end_count}"
        ));
    }
}

struct CheckCounts {
    total: usize,
    passed: usize,
    skipped: usize,
    failed: usize,
}

fn count_checks(checks: &[CheckFrame], errors: &mut Vec<String>) -> CheckCounts {
    let mut counts = CheckCounts {
        total: checks.len(),
        passed: 0,
        skipped: 0,
        failed: 0,
    };
    for chk in checks {
        match chk.status {
            CheckStatusTag::Pass => {
                if chk.checks_failed > 0 {
                    errors.push(format!(
                        "check '{}' reported PASS with checks_failed={}",
                        chk.id, chk.checks_failed
                    ));
                }
                counts.passed += 1;
            }
            CheckStatusTag::Skipped => counts.skipped += 1,
            CheckStatusTag::Fail => {
                counts.failed += 1;
                errors.push(format!(
                    "check '{}' FAILED ({}; passed={}/{})",
                    chk.id,
                    chk.fail_reason.as_deref().unwrap_or("unknown"),
                    chk.checks,
                    chk.checks_total
                ));
            }
        }
    }
    counts
}

struct BenchCounts {
    total: usize,
    passed: usize,
    skipped: usize,
    hw_native: usize,
    delegated: usize,
    failed: usize,
    effective: usize,
    smp_effective: usize,
}

fn count_benches(benches: &[BenchFrame], errors: &mut Vec<String>) -> BenchCounts {
    let mut counts = BenchCounts {
        total: benches.len(),
        passed: 0,
        skipped: 0,
        hw_native: 0,
        delegated: 0,
        failed: 0,
        effective: 0,
        smp_effective: 0,
    };
    for bench in benches {
        match bench.status {
            BenchStatusTag::Pass => counts.passed += 1,
            BenchStatusTag::Skipped => counts.skipped += 1,
            BenchStatusTag::HwNative => counts.hw_native += 1,
            BenchStatusTag::DelegatedToS => counts.delegated += 1,
            BenchStatusTag::Fail => {
                counts.failed += 1;
                errors.push(format!(
                    "benchmark '{}' (p={}) FAILED ({})",
                    bench.id,
                    bench.parallel,
                    bench.fail_reason.as_deref().unwrap_or("unknown")
                ));
            }
        }
        if is_effective_bench_status(bench.status) {
            counts.effective += 1;
            if is_smp_bench(bench) {
                counts.smp_effective += 1;
            }
        }
    }
    counts
}

fn verify_end_consistency(
    end: &crate::record::EndRecord,
    checks: &CheckCounts,
    benches: &BenchCounts,
    errors: &mut Vec<String>,
) {
    if end.checks_failed > 0 && checks.failed == 0 {
        errors.push(format!(
            "END reports checks_failed={}, though no failing check frames were captured",
            end.checks_failed
        ));
    }
    if end.benches_failed > 0 && benches.failed == 0 {
        errors.push(format!(
            "END reports benches_failed={}, though no failing benchmark frames were captured",
            end.benches_failed
        ));
    }
    if end.checks_total != checks.total
        || end.checks_passed != checks.passed
        || end.checks_skipped != checks.skipped
        || end.checks_failed != checks.failed
    {
        errors.push(format!(
            "END check counts ({}/{}/{}/{}) do not match captured check frames ({}/{}/{}/{})",
            end.checks_total,
            end.checks_passed,
            end.checks_skipped,
            end.checks_failed,
            checks.total,
            checks.passed,
            checks.skipped,
            checks.failed
        ));
    }
    if end.benches_total != benches.total
        || end.benches_passed != benches.passed
        || end.benches_skipped != benches.skipped
        || end.benches_hw_native != benches.hw_native
        || end.benches_delegated != benches.delegated
        || end.benches_failed != benches.failed
    {
        errors.push(format!(
            "END benchmark counts ({}/{}/{}/{}/{}/{}) do not match captured frames ({}/{}/{}/{}/{}/{})",
            end.benches_total,
            end.benches_passed,
            end.benches_skipped,
            end.benches_hw_native,
            end.benches_delegated,
            end.benches_failed,
            benches.total,
            benches.passed,
            benches.skipped,
            benches.hw_native,
            benches.delegated,
            benches.failed
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol,
        record::{
            BenchResult, BenchStatus, CheckIssues, CheckResult, CheckStatus, CounterAvailability,
            EndRecord, FailReason, MetaRecord, SbiCapMask,
        },
        stats,
    };

    fn sample_meta(harts: usize, extensions: SbiCapMask) -> String {
        let meta = MetaRecord {
            sbi_spec_version: 0x0300_0000,
            impl_id: 4,
            impl_version: 1,
            mvendorid: 0,
            marchid: 0,
            mimpid: 0,
            extensions,
            hart_count: harts,
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
            has_h_ext: true,
            boot_ticks: 100,
            reserved_mem_bytes: 0,
            console_backend: "dbcn",
            pmu_counter_count: 16,
            load_addr: 0x8020_0000,
        };
        let mut out = String::new();
        protocol::write_meta_line(&meta, &mut out).unwrap();
        out
    }

    fn check_line(id: &str, status: CheckStatus) -> String {
        let mut out = String::new();
        protocol::write_start_line(StartKind::Check, id, 1, &mut out).unwrap();
        protocol::write_check_line(
            &CheckResult {
                id,
                checks: if status == CheckStatus::Pass { 5 } else { 0 },
                checks_total: 5,
                checks_failed: if matches!(status, CheckStatus::Failed(_)) {
                    1
                } else {
                    0
                },
                status,
                issues: CheckIssues::new(),
                quirks: 0,
                note: None,
            },
            &mut out,
        )
        .unwrap();
        out
    }

    fn bench_line(id: &str, group: BenchGroup, parallel: usize, status: BenchStatus) -> String {
        let mut out = String::new();
        protocol::write_start_line(StartKind::Bench, id, parallel, &mut out).unwrap();
        let cyc = (status == BenchStatus::Pass)
            .then(|| stats::compute_stats(&[100, 101, 99, 100, 102], 1, 0, 0));
        protocol::write_bench_line(
            &BenchResult {
                id,
                group,
                mode: (status == BenchStatus::Pass).then_some(crate::record::MeasureMode::Batched),
                parallel,
                unit: "call",
                iters_per_trial: if status == BenchStatus::Pass { 16 } else { 0 },
                trials: match status {
                    BenchStatus::Pass => 5,
                    BenchStatus::HwNative => 1,
                    _ => 0,
                },
                status,
                cycles: cyc,
                instret: None,
                ticks: None,
                ns: None,
                throughput_ops_per_sec: None,
                note: None,
            },
            &mut out,
        )
        .unwrap();
        out
    }

    fn end_line(end: EndRecord) -> String {
        let mut out = String::new();
        protocol::write_end_line(&end, &mut out).unwrap();
        out
    }

    #[test]
    fn validates_pass_and_rejects_protocol_and_gating_failures() {
        let mut ok_log = sample_meta(4, SbiCapMask::BASE | SbiCapMask::HSM);
        ok_log.push_str(&check_line("conformance/base", CheckStatus::Pass));
        ok_log.push_str(&check_line("conformance/hsm", CheckStatus::Pass));
        ok_log.push_str(&bench_line(
            "scale/base_ecall",
            BenchGroup::Scale,
            4,
            BenchStatus::Pass,
        ));
        ok_log.push_str(&bench_line(
            "trap/misaligned_load",
            BenchGroup::TrapEmul,
            1,
            BenchStatus::HwNative,
        ));
        ok_log.push_str(&end_line(EndRecord {
            checks_total: 2,
            checks_passed: 2,
            check_assertions_total: 10,
            check_assertions_passed: 10,
            benches_total: 2,
            benches_passed: 1,
            benches_hw_native: 1,
            ..EndRecord::default()
        }));

        let policy = ValidationPolicy {
            require_closed_starts: true,
            expect_harts: Some(4),
            require_extensions: vec![SbiExtensionId::Base, SbiExtensionId::Hsm],
            require_check_pass: vec![
                String::from("conformance/base"),
                String::from("conformance/hsm"),
            ],
            min_checks_passed: Some(2),
            min_effective_benches: Some(2),
            min_smp_effective_benches: Some(1),
            max_quarantine_warnings: Some(0),
            forbidden_patterns: parse_forbidden_patterns("# comment\npanicked\nFAILED\n").unwrap(),
        };
        let summary = validate_capture(&ok_log, &policy).unwrap();
        assert_eq!(summary.hart_count, 4);
        assert_eq!(summary.checks_passed, 2);
        assert_eq!(summary.benches_effective, 2);
        assert_eq!(summary.benches_smp_effective, 1);

        // Missing extension & skipped required check must fail even if base passes.
        let mut skipped_hsm = sample_meta(4, SbiCapMask::BASE);
        skipped_hsm.push_str(&check_line("conformance/base", CheckStatus::Pass));
        skipped_hsm.push_str(&check_line(
            "conformance/hsm",
            CheckStatus::Skipped(SkipReason::ExtensionUnsupported),
        ));
        skipped_hsm.push_str(&end_line(EndRecord {
            checks_total: 2,
            checks_passed: 1,
            checks_skipped: 1,
            ..EndRecord::default()
        }));
        let errs = validate_capture(&skipped_hsm, &policy).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.contains("missing required SBI extension 'hsm'"))
        );
        assert!(
            errs.iter()
                .any(|e| e.contains("required check 'conformance/hsm' did not PASS"))
        );

        // All-skipped benchmarks must fail min_effective_benches even when benches_total > 0.
        let mut all_skipped_bench = sample_meta(4, SbiCapMask::BASE);
        all_skipped_bench.push_str(&bench_line(
            "base/get_spec_version",
            BenchGroup::Base,
            1,
            BenchStatus::Skipped(SkipReason::FilteredOut),
        ));
        all_skipped_bench.push_str(&end_line(EndRecord {
            benches_total: 1,
            benches_skipped: 1,
            ..EndRecord::default()
        }));
        let bench_policy = ValidationPolicy {
            min_effective_benches: Some(1),
            ..ValidationPolicy::default()
        };
        let errs = validate_capture(&all_skipped_bench, &bench_policy).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("effective benchmarks (0)")));

        // Unclosed START before END must fail when require_closed_starts is enabled.
        let mut unclosed = sample_meta(1, SbiCapMask::BASE);
        protocol::write_start_line(StartKind::Check, "conformance/base", 1, &mut unclosed).unwrap();
        unclosed.push_str(&end_line(EndRecord::default()));
        let strict_starts = ValidationPolicy {
            require_closed_starts: true,
            ..ValidationPolicy::default()
        };
        let errs = validate_capture(&unclosed, &strict_starts).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("unclosed @@MBENCH:START")));

        // Nonzero quarantine warnings, PANIC, forbidden pattern, and missing END must all fail.
        let mut bad_misc = ok_log.replace("\"quarantine_warnings\":0", "\"quarantine_warnings\":1");
        bad_misc = format!("Firmware panicked here!\n{bad_misc}");
        protocol::write_panic_line("boom", &mut bad_misc).unwrap();
        let errs = validate_capture(&bad_misc, &policy).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.contains("forbidden pattern 'panicked'"))
        );
        assert!(errs.iter().any(|e| e.contains("quarantine_warnings (1)")));
        assert!(errs.iter().any(|e| e.contains("target panicked")));

        let no_end = sample_meta(1, SbiCapMask::BASE);
        let errs = validate_capture(&no_end, &ValidationPolicy::default()).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("missing @@MBENCH:END")));

        let mut failed_cases = sample_meta(1, SbiCapMask::BASE);
        failed_cases.push_str(&check_line(
            "conformance/base",
            CheckStatus::Failed(FailReason::AssertionFailed("bad_spec")),
        ));
        failed_cases.push_str(&bench_line(
            "base/get_spec_version",
            BenchGroup::Base,
            1,
            BenchStatus::Failed(FailReason::VerificationMismatch),
        ));
        failed_cases.push_str(&end_line(EndRecord {
            checks_total: 1,
            checks_failed: 1,
            check_assertions_total: 5,
            check_assertions_failed: 1,
            benches_total: 1,
            benches_failed: 1,
            ..EndRecord::default()
        }));
        let errs = validate_capture(&failed_cases, &ValidationPolicy::default()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.contains("check 'conformance/base' FAILED"))
        );
        assert!(
            errs.iter()
                .any(|e| e.contains("benchmark 'base/get_spec_version' (p=1) FAILED"))
        );

        assert!(parse_forbidden_patterns("# only comments\n\n").is_err());
    }
}
