//! Protocol integrity auditing and structured capture summary reports.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    record::{BenchGroup, EndRecord, SkipReason, StartKind},
    wire::{
        AttemptRecord, BenchFrame, BenchStatusTag, CheckFrame, CheckStatusTag, EndFrame, EnvLine,
        MetaFrame, PanicFrame, StartFrame, WireFrame, parse_capture, parse_wire_line,
    },
};

const fn is_false(value: &bool) -> bool {
    !*value
}

/// Source format detected for an audited capture.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureFormat {
    RawSerial,
    MergedJsonl,
}

/// Aggregated counts extracted from parsed capture records.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaptureCounts {
    pub checks_total: usize,
    pub checks_passed: usize,
    pub checks_skipped: usize,
    pub checks_failed: usize,
    pub check_assertions_total: u64,
    pub check_assertions_passed: u64,
    pub check_assertions_failed: u64,
    pub benches_total: usize,
    pub benches_passed: usize,
    pub benches_hw_native: usize,
    pub benches_delegated: usize,
    pub benches_effective: usize,
    pub benches_skipped: usize,
    pub benches_failed: usize,
    pub quarantine_warnings: usize,
}

impl CaptureCounts {
    fn from_end(end: &EndRecord) -> Self {
        Self {
            checks_total: end.checks_total,
            checks_passed: end.checks_passed,
            checks_skipped: end.checks_skipped,
            checks_failed: end.checks_failed,
            check_assertions_total: end.check_assertions_total,
            check_assertions_passed: end.check_assertions_passed,
            check_assertions_failed: end.check_assertions_failed,
            benches_total: end.benches_total,
            benches_passed: end.benches_passed,
            benches_hw_native: end.benches_hw_native,
            benches_delegated: end.benches_delegated,
            benches_effective: end
                .benches_passed
                .saturating_add(end.benches_hw_native)
                .saturating_add(end.benches_delegated),
            benches_skipped: end.benches_skipped,
            benches_failed: end.benches_failed,
            quarantine_warnings: end.quarantine_warnings,
        }
    }
}

/// Per-check summary entry exposed inside [`CaptureReport`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckSummary {
    pub id: String,
    pub status: CheckStatusTag,
    pub checks: u64,
    pub checks_total: u64,
    pub checks_failed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<SkipReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_reason: Option<String>,
    pub quirks: u8,
    #[serde(default, skip_serializing_if = "is_false")]
    pub synthetic: bool,
}

/// Per-benchmark summary entry exposed inside [`CaptureReport`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchSummary {
    pub id: String,
    pub group: BenchGroup,
    pub parallel: usize,
    pub status: BenchStatusTag,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<SkipReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_reason: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub synthetic: bool,
}

/// Machine-readable protocol audit and experiment report exported for downstream consumers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaptureReport {
    pub source: String,
    pub format: CaptureFormat,
    pub protocol_valid: bool,
    pub completed: bool,
    pub recovered: bool,
    pub protocol_errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvLine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<MetaFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub panic: Option<PanicFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<EndFrame>,
    pub counts: CaptureCounts,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attempts: Vec<AttemptRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<CheckSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub benches: Vec<BenchSummary>,
}

/// Returns `true` when a benchmark status represents a non-skipped measured or native/delegated result.
pub const fn is_effective_bench_status(status: BenchStatusTag) -> bool {
    matches!(
        status,
        BenchStatusTag::Pass | BenchStatusTag::HwNative | BenchStatusTag::DelegatedToS
    )
}

/// Summarizes check and benchmark records into a matching [`EndRecord`].
pub fn summarize_records(
    checks: &[CheckFrame],
    benches: &[BenchFrame],
    quarantine_warnings: usize,
) -> EndRecord {
    let mut end = EndRecord {
        quarantine_warnings,
        ..EndRecord::default()
    };
    for chk in checks {
        end.checks_total = end.checks_total.saturating_add(1);
        match chk.status {
            CheckStatusTag::Pass => end.checks_passed += 1,
            CheckStatusTag::Skipped => end.checks_skipped += 1,
            CheckStatusTag::Fail => end.checks_failed += 1,
        }
        let case_total = chk
            .checks_total
            .max(chk.checks.saturating_add(chk.checks_failed));
        end.check_assertions_total = end.check_assertions_total.saturating_add(case_total);
        end.check_assertions_passed = end.check_assertions_passed.saturating_add(chk.checks);
        end.check_assertions_failed = end
            .check_assertions_failed
            .saturating_add(chk.checks_failed);
    }
    for bench in benches {
        end.benches_total = end.benches_total.saturating_add(1);
        match bench.status {
            BenchStatusTag::Pass => end.benches_passed += 1,
            BenchStatusTag::Skipped => end.benches_skipped += 1,
            BenchStatusTag::HwNative => end.benches_hw_native += 1,
            BenchStatusTag::DelegatedToS => end.benches_delegated += 1,
            BenchStatusTag::Fail => end.benches_failed += 1,
        }
    }
    end
}

/// Audits a single raw serial execution attempt for framing, START/result closure, and END integrity.
pub fn audit_raw_attempt(raw_lines: &[String], expect_end: bool) -> Vec<String> {
    let lines: Vec<&str> = raw_lines.iter().map(String::as_str).collect();
    audit_stream_lines(&lines, true, expect_end)
}

/// Audits a saved `.jsonl` capture or raw serial log and exports a structured [`CaptureReport`].
pub fn audit_capture(source: &str, text: &str) -> CaptureReport {
    let lines: Vec<&str> = text.lines().collect();
    let is_merged = lines
        .iter()
        .any(|line| line.starts_with("# MBENCH_ENV ") || line.starts_with("# MBENCH_ATTEMPT "));
    let format = if is_merged {
        CaptureFormat::MergedJsonl
    } else {
        CaptureFormat::RawSerial
    };

    let mut protocol_errors = match format {
        CaptureFormat::RawSerial => audit_stream_lines(&lines, true, true),
        CaptureFormat::MergedJsonl => audit_stream_lines(&lines, false, true),
    };

    let parsed = match parse_capture(source, text) {
        Ok(cap) => cap,
        Err(err) => {
            if protocol_errors.is_empty() {
                protocol_errors.push(format!("capture parse failed: {err}"));
            }
            return CaptureReport {
                source: source.to_string(),
                format,
                protocol_valid: false,
                completed: false,
                recovered: false,
                protocol_errors,
                env: None,
                meta: None,
                panic: None,
                end: None,
                counts: CaptureCounts::default(),
                attempts: Vec::new(),
                checks: Vec::new(),
                benches: Vec::new(),
            };
        }
    };

    for attempt in &parsed.attempts {
        for err in &attempt.protocol_errors {
            protocol_errors.push(format!("attempt {}: {err}", attempt.attempt));
        }
    }

    if let Some(end) = &parsed.end {
        let computed = summarize_records(&parsed.checks, &parsed.benches, end.quarantine_warnings);
        if format == CaptureFormat::MergedJsonl {
            compare_end_counts("merged capture", &computed, end, &mut protocol_errors);
        }
    }

    let computed_counts = summarize_records(
        &parsed.checks,
        &parsed.benches,
        parsed.end.map_or(0, |e| e.quarantine_warnings),
    );
    let recovered = parsed.attempts.len() > 1
        || parsed.checks.iter().any(|c| c.synthetic)
        || parsed.benches.iter().any(|b| b.synthetic);
    let last_attempt_complete = parsed.attempts.last().is_none_or(|attempt| attempt.saw_end);
    let completed = match format {
        CaptureFormat::RawSerial => parsed.end.is_some() && parsed.panic.is_none(),
        CaptureFormat::MergedJsonl => parsed.end.is_some() && last_attempt_complete,
    };

    let checks = parsed
        .checks
        .into_iter()
        .map(|chk| CheckSummary {
            id: chk.id,
            status: chk.status,
            checks: chk.checks,
            checks_total: chk.checks_total,
            checks_failed: chk.checks_failed,
            skip_reason: chk.skip_reason,
            fail_reason: chk.fail_reason,
            quirks: chk.quirks,
            synthetic: chk.synthetic,
        })
        .collect();
    let benches = parsed
        .benches
        .into_iter()
        .map(|bench| BenchSummary {
            id: bench.id,
            group: bench.group,
            parallel: bench.parallel,
            status: bench.status,
            skip_reason: bench.skip_reason,
            fail_reason: bench.fail_reason,
            synthetic: bench.synthetic,
        })
        .collect();

    CaptureReport {
        source: parsed.label,
        format,
        protocol_valid: protocol_errors.is_empty(),
        completed,
        recovered,
        protocol_errors,
        env: parsed.env,
        meta: parsed.meta,
        panic: parsed.panic,
        end: parsed.end,
        counts: CaptureCounts::from_end(&computed_counts),
        attempts: parsed.attempts,
        checks,
        benches,
    }
}

fn audit_stream_lines(lines: &[&str], raw_single_attempt: bool, expect_end: bool) -> Vec<String> {
    let mut errors = Vec::new();
    let mut open_starts: Vec<StartFrame> = Vec::new();
    let mut raw_checks: Vec<CheckFrame> = Vec::new();
    let mut raw_benches: Vec<BenchFrame> = Vec::new();
    let mut seen_check_keys: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_bench_keys: BTreeMap<(String, usize), usize> = BTreeMap::new();
    let mut meta_count = 0usize;
    let mut saw_end = false;
    let mut saw_panic = false;

    for (idx, raw_line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let has_mbench_prefix = raw_line.contains("@@MBENCH:");
        let frame = match parse_wire_line(raw_line) {
            Ok(Some(f)) => f,
            Ok(None) => {
                if has_mbench_prefix {
                    errors.push(format!(
                        "line {line_no}: malformed or unknown @@MBENCH directive"
                    ));
                }
                continue;
            }
            Err(err) => {
                errors.push(format!("line {line_no}: {err}"));
                continue;
            }
        };

        match frame {
            WireFrame::Env(_) | WireFrame::Attempt(_) => {}
            WireFrame::Meta(_) => {
                if saw_end {
                    errors.push(format!(
                        "line {line_no}: unexpected @@MBENCH:META frame after END"
                    ));
                } else {
                    meta_count += 1;
                    if raw_single_attempt && meta_count > 1 {
                        errors.push(format!(
                            "line {line_no}: duplicate @@MBENCH:META frame in single attempt"
                        ));
                    }
                }
            }
            WireFrame::Cal(_) => {
                if saw_end {
                    errors.push(format!(
                        "line {line_no}: unexpected @@MBENCH:CAL frame after END"
                    ));
                }
            }
            WireFrame::Start(start) => {
                if saw_end {
                    errors.push(format!(
                        "line {line_no}: unexpected @@MBENCH:START frame after END ('{}')",
                        start.id
                    ));
                } else {
                    open_starts.push(start);
                }
            }
            WireFrame::Check(chk) => {
                if saw_end {
                    errors.push(format!(
                        "line {line_no}: unexpected @@MBENCH:CHECK frame after END ('{}')",
                        chk.id
                    ));
                } else {
                    if let Some(pos) = open_starts
                        .iter()
                        .position(|s| s.kind == StartKind::Check && s.id == chk.id)
                    {
                        open_starts.remove(pos);
                    }
                    if raw_single_attempt {
                        if let Some(prev_line) = seen_check_keys.insert(chk.id.clone(), line_no) {
                            errors.push(format!(
                                "line {line_no}: duplicate CHECK frame for '{}' (first seen at line {prev_line})",
                                chk.id
                            ));
                        }
                        raw_checks.push(chk);
                    }
                }
            }
            WireFrame::Bench(bench) => {
                if saw_end {
                    errors.push(format!(
                        "line {line_no}: unexpected @@MBENCH:BENCH frame after END ('{}')",
                        bench.id
                    ));
                } else {
                    if let Some(pos) = open_starts.iter().position(|s| {
                        s.kind == StartKind::Bench
                            && s.id == bench.id
                            && s.parallel == bench.parallel
                    }) {
                        open_starts.remove(pos);
                    }
                    if raw_single_attempt {
                        let key = (bench.id.clone(), bench.parallel);
                        if let Some(prev_line) = seen_bench_keys.insert(key, line_no) {
                            errors.push(format!(
                                "line {line_no}: duplicate BENCH frame for '{}' (parallel={}, first seen at line {prev_line})",
                                bench.id, bench.parallel
                            ));
                        }
                        raw_benches.push(*bench);
                    }
                }
            }
            WireFrame::End(end) => {
                if saw_end {
                    errors.push(format!("line {line_no}: duplicate @@MBENCH:END frame"));
                } else {
                    saw_end = true;
                    for unclosed in open_starts.drain(..) {
                        errors.push(format!(
                            "line {line_no}: unclosed @@MBENCH:START frame before END ({:?} '{}', parallel={})",
                            unclosed.kind, unclosed.id, unclosed.parallel
                        ));
                    }
                    if raw_single_attempt {
                        let computed =
                            summarize_records(&raw_checks, &raw_benches, end.quarantine_warnings);
                        compare_end_counts(
                            &format!("line {line_no}"),
                            &computed,
                            &end,
                            &mut errors,
                        );
                    }
                }
            }
            WireFrame::Panic(_) => {
                if saw_end {
                    errors.push(format!(
                        "line {line_no}: unexpected @@MBENCH:PANIC frame after END"
                    ));
                }
                saw_panic = true;
            }
        }
    }

    if expect_end {
        if meta_count == 0 && !saw_panic {
            errors.push(String::from("missing @@MBENCH:META frame"));
        }
        if !saw_end {
            errors.push(String::from("missing @@MBENCH:END frame"));
        }
        for unclosed in open_starts {
            errors.push(format!(
                "unclosed @@MBENCH:START frame at EOF ({:?} '{}', parallel={})",
                unclosed.kind, unclosed.id, unclosed.parallel
            ));
        }
    }

    errors
}

fn compare_end_counts(
    context: &str,
    computed: &EndRecord,
    recorded: &EndRecord,
    errors: &mut Vec<String>,
) {
    let fields = [
        (
            "checks_total",
            computed.checks_total as u64,
            recorded.checks_total as u64,
        ),
        (
            "checks_passed",
            computed.checks_passed as u64,
            recorded.checks_passed as u64,
        ),
        (
            "checks_skipped",
            computed.checks_skipped as u64,
            recorded.checks_skipped as u64,
        ),
        (
            "checks_failed",
            computed.checks_failed as u64,
            recorded.checks_failed as u64,
        ),
        (
            "check_assertions_total",
            computed.check_assertions_total,
            recorded.check_assertions_total,
        ),
        (
            "check_assertions_passed",
            computed.check_assertions_passed,
            recorded.check_assertions_passed,
        ),
        (
            "check_assertions_failed",
            computed.check_assertions_failed,
            recorded.check_assertions_failed,
        ),
        (
            "benches_total",
            computed.benches_total as u64,
            recorded.benches_total as u64,
        ),
        (
            "benches_passed",
            computed.benches_passed as u64,
            recorded.benches_passed as u64,
        ),
        (
            "benches_skipped",
            computed.benches_skipped as u64,
            recorded.benches_skipped as u64,
        ),
        (
            "benches_hw_native",
            computed.benches_hw_native as u64,
            recorded.benches_hw_native as u64,
        ),
        (
            "benches_delegated",
            computed.benches_delegated as u64,
            recorded.benches_delegated as u64,
        ),
        (
            "benches_failed",
            computed.benches_failed as u64,
            recorded.benches_failed as u64,
        ),
    ];
    for (name, got, want) in fields {
        if got != want {
            errors.push(format!(
                "{context}: END {name}={want} does not match emitted records ({got})"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::RunConfig,
        protocol,
        record::{
            BenchResult, BenchStatus, CalibrationRecord, CheckIssues, CheckResult, CheckStatus,
            CounterAvailability, FailReason, MetaRecord, SbiCapMask, SbiExtensionId,
        },
        stats,
        wire::ShutdownStatus,
    };

    fn sample_meta(harts: usize, extensions: SbiCapMask) -> String {
        let mut out = String::new();
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
            config: RunConfig::default(),
        };
        protocol::write_meta_line(&meta, &mut out).unwrap();
        out
    }

    fn check_line(id: &str, status: CheckStatus) -> String {
        let mut out = String::new();
        protocol::write_start_line(StartKind::Check, id, 1, &mut out).unwrap();
        let failed = matches!(status, CheckStatus::Failed(_)) as u64;
        protocol::write_check_line(
            &CheckResult {
                id,
                checks: if status == CheckStatus::Pass { 5 } else { 0 },
                checks_total: 5,
                checks_failed: failed,
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
    fn audits_raw_captures_and_detects_protocol_defects() {
        let mut cal = String::new();
        protocol::write_cal_line(&CalibrationRecord::default(), &mut cal).unwrap();

        let mut ok_log = sample_meta(4, SbiCapMask::BASE | SbiCapMask::HSM);
        ok_log.push_str(&cal);
        ok_log.push_str(&check_line("conformance/base", CheckStatus::Pass));
        ok_log.push_str(&check_line(
            "conformance/rfnc",
            CheckStatus::Failed(FailReason::UnexpectedSbiError(-2)),
        ));
        ok_log.push_str(&bench_line(
            "base/get_spec_version",
            BenchGroup::Base,
            1,
            BenchStatus::Pass,
        ));
        ok_log.push_str(&bench_line(
            "rfnc/sfence_vma.all",
            BenchGroup::Rfnc,
            4,
            BenchStatus::Failed(FailReason::Timeout),
        ));
        ok_log.push_str(&end_line(EndRecord {
            checks_total: 2,
            checks_passed: 1,
            checks_skipped: 0,
            checks_failed: 1,
            check_assertions_total: 10,
            check_assertions_passed: 5,
            check_assertions_failed: 1,
            benches_total: 2,
            benches_passed: 1,
            benches_skipped: 0,
            benches_hw_native: 0,
            benches_delegated: 0,
            benches_failed: 1,
            quarantine_warnings: 0,
        }));

        // Valid wire protocol with failing cases still produces a clean, complete report.
        let report = audit_capture("ok", &ok_log);
        assert_eq!(report.format, CaptureFormat::RawSerial);
        assert!(report.protocol_valid, "{:?}", report.protocol_errors);
        assert!(report.completed);
        assert!(!report.recovered);
        assert_eq!(report.counts.checks_failed, 1);
        assert_eq!(report.counts.benches_failed, 1);
        assert_eq!(report.counts.benches_effective, 1);
        assert_eq!(
            report.meta.as_ref().unwrap().extensions,
            vec![SbiExtensionId::Base, SbiExtensionId::Hsm]
        );

        // Unclosed START before END fails protocol validation.
        let mut unclosed = sample_meta(1, SbiCapMask::BASE);
        protocol::write_start_line(StartKind::Check, "conformance/base", 1, &mut unclosed).unwrap();
        unclosed.push_str(&end_line(EndRecord::default()));
        let unclosed_report = audit_capture("unclosed", &unclosed);
        assert!(!unclosed_report.protocol_valid);
        assert!(
            unclosed_report
                .protocol_errors
                .iter()
                .any(|e| e.contains("unclosed @@MBENCH:START"))
        );

        // Trailing frame after END and duplicate END must be caught.
        let mut trailing = ok_log.clone();
        trailing.push_str(&check_line("conformance/extra", CheckStatus::Pass));
        trailing.push_str(&end_line(EndRecord::default()));
        let trailing_report = audit_capture("trailing", &trailing);
        assert!(!trailing_report.protocol_valid);
        assert!(
            trailing_report
                .protocol_errors
                .iter()
                .any(|e| e.contains("after END"))
        );
        assert!(
            trailing_report
                .protocol_errors
                .iter()
                .any(|e| e.contains("duplicate @@MBENCH:END"))
        );

        // Malformed or truncated @@MBENCH lines must be flagged.
        let malformed = format!("{}\n@@MBENCH:BOGUS\n", sample_meta(1, SbiCapMask::BASE));
        let malformed_report = audit_capture("malformed", &malformed);
        assert!(!malformed_report.protocol_valid);
        assert!(!malformed_report.completed);

        // Mismatched raw END count must be flagged even when JSON parses cleanly.
        let mut mismatch = sample_meta(1, SbiCapMask::BASE);
        mismatch.push_str(&check_line("conformance/base", CheckStatus::Pass));
        mismatch.push_str(&end_line(EndRecord::default()));
        let mismatch_report = audit_capture("mismatch", &mismatch);
        assert!(!mismatch_report.protocol_valid);
        assert!(
            mismatch_report
                .protocol_errors
                .iter()
                .any(|e| e.contains("checks_total"))
        );
    }

    #[test]
    fn merged_report_preserves_attempt_errors_and_recovery_markers() {
        let mut merged_bad = String::from(
            "# MBENCH_ENV {\"clock_regime\":\"qemu-tcg-non-cycle-accurate\",\"label\":\"fw\",\"smp\":4}\n",
        );
        merged_bad.push_str(&sample_meta(4, SbiCapMask::BASE));
        merged_bad.push_str(&check_line("conformance/base", CheckStatus::Pass));
        let bad_attempt = AttemptRecord {
            attempt: 0,
            resume_after: None,
            saw_end: true,
            shutdown: ShutdownStatus::CleanExit,
            protocol_errors: vec![String::from("line 3: malformed wire frame")],
            synthesized_failures: Vec::new(),
        };
        merged_bad.push_str(&format!(
            "# MBENCH_ATTEMPT {}\n",
            serde_json::to_string(&bad_attempt).unwrap()
        ));
        merged_bad.push_str(&end_line(EndRecord {
            checks_total: 1,
            checks_passed: 1,
            check_assertions_total: 5,
            check_assertions_passed: 5,
            ..EndRecord::default()
        }));

        let bad_report = audit_capture("merged-bad", &merged_bad);
        assert_eq!(bad_report.format, CaptureFormat::MergedJsonl);
        assert!(!bad_report.protocol_valid);
        assert!(
            bad_report
                .protocol_errors
                .iter()
                .any(|e| e.contains("attempt 0: line 3: malformed wire frame"))
        );

        let mut merged_recovered = String::from(
            "# MBENCH_ENV {\"clock_regime\":\"qemu-tcg-non-cycle-accurate\",\"label\":\"fw\",\"smp\":4}\n",
        );
        merged_recovered.push_str(&sample_meta(4, SbiCapMask::BASE));
        merged_recovered.push_str(
            "@@MBENCH:CHECK {\"id\":\"conformance/time\",\"checks\":0,\"checks_total\":1,\"checks_failed\":1,\"status\":\"FAIL\",\"fail_reason\":\"timeout\",\"synthetic\":true}\n",
        );
        let a0 = AttemptRecord {
            attempt: 0,
            resume_after: None,
            saw_end: false,
            shutdown: ShutdownStatus::TimedOutDuringRun,
            protocol_errors: Vec::new(),
            synthesized_failures: vec![String::from("conformance/time")],
        };
        merged_recovered.push_str(&format!(
            "# MBENCH_ATTEMPT {}\n",
            serde_json::to_string(&a0).unwrap()
        ));
        merged_recovered.push_str(&check_line("conformance/base", CheckStatus::Pass));
        let a1 = AttemptRecord {
            attempt: 1,
            resume_after: Some(String::from("conformance/time")),
            saw_end: true,
            shutdown: ShutdownStatus::HostTerminatedAfterEnd,
            protocol_errors: Vec::new(),
            synthesized_failures: Vec::new(),
        };
        merged_recovered.push_str(&format!(
            "# MBENCH_ATTEMPT {}\n",
            serde_json::to_string(&a1).unwrap()
        ));
        merged_recovered.push_str(&end_line(EndRecord {
            checks_total: 2,
            checks_passed: 1,
            checks_failed: 1,
            check_assertions_total: 6,
            check_assertions_passed: 5,
            check_assertions_failed: 1,
            ..EndRecord::default()
        }));

        let rec_report = audit_capture("merged-rec", &merged_recovered);
        assert!(
            rec_report.protocol_valid,
            "{:?}",
            rec_report.protocol_errors
        );
        assert!(rec_report.completed);
        assert!(rec_report.recovered);
        assert!(rec_report.checks[0].synthetic);
        assert!(!rec_report.checks[1].synthetic);
        assert_eq!(rec_report.attempts.len(), 2);
        assert_eq!(
            rec_report.attempts[1].shutdown,
            ShutdownStatus::HostTerminatedAfterEnd
        );
    }
}
