//! Protocol integrity auditing and structured capture summary reports.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    record::{BenchGroup, EndRecord, SkipReason, StartKind},
    wire::{
        AttemptRecord, BenchFrame, BenchStatusTag, CheckFrame, CheckStatusTag, EndFrame, EnvLine,
        MetaFrame, PanicFrame, StartFrame, WireFrame, parse_wire_line, shutdown_fail_reason,
        synthesize_fail_bench, synthesize_fail_check,
    },
};

const fn is_false(value: &bool) -> bool {
    !*value
}

/// Shared `@@MBENCH:START` to result matcher used by both live monitoring and offline auditing.
#[derive(Clone, Debug, Default)]
pub struct CaseTracker {
    active: Vec<StartFrame>,
}

impl CaseTracker {
    /// Creates an empty tracker.
    pub const fn new() -> Self {
        Self { active: Vec::new() }
    }

    /// Records a started case, returning `false` when an identical active start already exists.
    pub fn record_start(&mut self, start: StartFrame) -> bool {
        let already_open = self
            .active
            .iter()
            .any(|s| s.kind == start.kind && s.id == start.id && s.parallel == start.parallel);
        if already_open {
            false
        } else {
            self.active.push(start);
            true
        }
    }

    /// Closes the active `CHECK` start entry for `id`, returning `true` when found.
    pub fn close_check(&mut self, id: &str) -> bool {
        if let Some(pos) = self
            .active
            .iter()
            .position(|s| s.kind == StartKind::Check && s.id == id)
        {
            self.active.remove(pos);
            true
        } else {
            false
        }
    }

    /// Closes the active `BENCH` start entry for `(id, parallel)`, returning `true` when found.
    pub fn close_bench(&mut self, id: &str, parallel: usize) -> bool {
        if let Some(pos) = self
            .active
            .iter()
            .position(|s| s.kind == StartKind::Bench && s.id == id && s.parallel == parallel)
        {
            self.active.remove(pos);
            true
        } else {
            false
        }
    }

    /// Returns `true` when no started case is currently open.
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    /// Drains all remaining open start frames in insertion order.
    pub fn drain_all(&mut self) -> Vec<StartFrame> {
        std::mem::take(&mut self.active)
    }
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

/// Audits a single raw serial execution attempt for framing, ordering, START closure, and END integrity.
pub fn audit_raw_attempt(raw_lines: &[String], expect_end: bool) -> Vec<String> {
    let lines: Vec<&str> = raw_lines.iter().map(String::as_str).collect();
    audit_stream_lines(&lines, 0, true, expect_end).errors
}

/// Audits a saved `.jsonl` capture or raw serial log and exports a structured [`CaptureReport`].
///
/// Always retains all validly parsed facts even when malformed lines or truncated attempts occur.
pub fn audit_capture(source: &str, text: &str) -> CaptureReport {
    let lines: Vec<&str> = text.lines().collect();
    let has_raw_attempt_markers = lines
        .iter()
        .any(|line| line.starts_with("# MBENCH_RAW_ATTEMPT "));
    if has_raw_attempt_markers {
        return audit_multi_attempt_raw(source, &lines);
    }

    let is_merged = lines
        .iter()
        .any(|line| line.starts_with("# MBENCH_ENV ") || line.starts_with("# MBENCH_ATTEMPT "));
    if is_merged {
        return audit_merged_jsonl(source, &lines);
    }

    audit_single_attempt_raw(source, &lines)
}

fn audit_single_attempt_raw(source: &str, lines: &[&str]) -> CaptureReport {
    let parsed = audit_stream_lines(lines, 0, true, true);
    let mut protocol_errors = parsed.errors;
    if !parsed.any_frame_seen && protocol_errors.is_empty() {
        protocol_errors.push(format!("no @@MBENCH frames found in '{source}'"));
    }

    let mut check_order = Vec::new();
    let mut check_map = BTreeMap::new();
    let mut bench_order = Vec::new();
    let mut bench_map = BTreeMap::new();
    for chk in parsed.checks {
        merge_check_into(&mut check_order, &mut check_map, chk);
    }
    for bench in parsed.benches {
        merge_bench_into(&mut bench_order, &mut bench_map, bench);
    }
    merge_synthesized_unclosed(
        &mut check_order,
        &mut check_map,
        &mut bench_order,
        &mut bench_map,
        &parsed.unclosed_at_end,
        "protocol_error",
    );
    let eof_reason = if parsed.saw_panic {
        "crash"
    } else {
        "incomplete"
    };
    merge_synthesized_unclosed(
        &mut check_order,
        &mut check_map,
        &mut bench_order,
        &mut bench_map,
        &parsed.unclosed_at_eof,
        eof_reason,
    );
    let checks = finalize_check_order(check_order, &mut check_map);
    let benches = finalize_bench_order(bench_order, &mut bench_map);

    let completed = parsed.any_frame_seen && parsed.end.is_some() && parsed.panic.is_none();
    let quarantine = parsed.end.map_or(0, |e| e.quarantine_warnings);
    let counts = CaptureCounts::from_end(&summarize_records(&checks, &benches, quarantine));

    build_report(
        source.to_string(),
        CaptureFormat::RawSerial,
        completed,
        false,
        protocol_errors,
        parsed.env,
        parsed.meta,
        parsed.panic,
        parsed.end,
        counts,
        Vec::new(),
        checks,
        benches,
    )
}

fn audit_multi_attempt_raw(source: &str, lines: &[&str]) -> CaptureReport {
    let mut protocol_errors = Vec::new();
    let mut sections: Vec<(Option<usize>, usize, &[&str])> = Vec::new();
    let mut marker_indices = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        if line.starts_with("# MBENCH_RAW_ATTEMPT ") {
            marker_indices.push(idx);
        }
    }

    let first_marker = marker_indices[0];
    for (idx, raw_line) in lines[..first_marker].iter().enumerate() {
        let line_no = idx + 1;
        let has_prefix = raw_line.contains("@@MBENCH:");
        match parse_wire_line(raw_line) {
            Ok(Some(_)) => protocol_errors.push(format!(
                "line {line_no}: unexpected @@MBENCH frame before first # MBENCH_RAW_ATTEMPT marker"
            )),
            Ok(None) if has_prefix => protocol_errors.push(format!(
                "line {line_no}: malformed or unknown @@MBENCH directive before first # MBENCH_RAW_ATTEMPT marker"
            )),
            Ok(None) => {}
            Err(err) => protocol_errors.push(format!("line {line_no}: {err}")),
        }
    }

    for (pos, &marker_idx) in marker_indices.iter().enumerate() {
        let marker_line_no = marker_idx + 1;
        let attempt_num = match parse_wire_line(lines[marker_idx]) {
            Ok(Some(WireFrame::RawAttemptStart(boundary))) => {
                if boundary.attempt != pos {
                    protocol_errors.push(format!(
                        "line {marker_line_no}: unexpected attempt index {} (expected {pos})",
                        boundary.attempt
                    ));
                }
                Some(boundary.attempt)
            }
            Ok(_) => {
                protocol_errors.push(format!(
                    "line {marker_line_no}: malformed # MBENCH_RAW_ATTEMPT marker"
                ));
                None
            }
            Err(err) => {
                protocol_errors.push(format!("line {marker_line_no}: {err}"));
                None
            }
        };
        let end_idx = marker_indices.get(pos + 1).copied().unwrap_or(lines.len());
        sections.push((attempt_num, marker_idx + 1, &lines[marker_idx + 1..end_idx]));
    }

    let total_sections = sections.len();
    let mut any_frame_seen = false;
    let mut latest_env = None;
    let mut all_attempts = Vec::new();
    let mut latest_meta = None;
    let mut latest_panic = None;
    let mut last_end = None;
    let mut total_quarantine = 0usize;
    let mut last_saw_end = false;
    let mut last_saw_panic = false;
    let mut last_footer_saw_end: Option<bool> = None;
    let mut check_order = Vec::new();
    let mut check_map = BTreeMap::new();
    let mut bench_order = Vec::new();
    let mut bench_map = BTreeMap::new();

    for (sec_idx, (attempt_num, start_offset, sec_lines)) in sections.into_iter().enumerate() {
        let is_last = sec_idx + 1 == total_sections;
        let sec = audit_stream_lines(sec_lines, start_offset, true, is_last);
        let prefix = match attempt_num {
            Some(n) => format!("attempt {n}"),
            None => format!("section {sec_idx}"),
        };
        for err in sec.errors {
            protocol_errors.push(format!("{prefix}: {err}"));
        }

        if sec.attempts.len() > 1 {
            protocol_errors.push(format!(
                "{prefix}: multiple # MBENCH_ATTEMPT records inside single attempt"
            ));
        }
        if let (Some(expected), Some(rec)) = (attempt_num, sec.attempts.first())
            && rec.attempt != expected
        {
            protocol_errors.push(format!(
                "{prefix}: mismatched # MBENCH_ATTEMPT index {} (expected {expected})",
                rec.attempt
            ));
        }

        any_frame_seen |= sec.any_frame_seen;
        if let Some(env) = sec.env {
            latest_env = Some(env);
        }
        if let Some(meta) = sec.meta {
            latest_meta = Some(meta);
        }
        if let Some(panic) = sec.panic {
            latest_panic = Some(panic);
        }
        if let Some(end) = sec.end {
            total_quarantine = total_quarantine.saturating_add(end.quarantine_warnings);
            last_end = Some(end);
        } else if is_last {
            last_end = None;
        }
        for chk in sec.checks {
            merge_check_into(&mut check_order, &mut check_map, chk);
        }
        for bench in sec.benches {
            merge_bench_into(&mut bench_order, &mut bench_map, bench);
        }
        merge_synthesized_unclosed(
            &mut check_order,
            &mut check_map,
            &mut bench_order,
            &mut bench_map,
            &sec.unclosed_at_end,
            "protocol_error",
        );
        let eof_reason = sec
            .attempts
            .last()
            .map_or(if sec.saw_panic { "crash" } else { "incomplete" }, |rec| {
                shutdown_fail_reason(&rec.shutdown)
            });
        merge_synthesized_unclosed(
            &mut check_order,
            &mut check_map,
            &mut bench_order,
            &mut bench_map,
            &sec.unclosed_at_eof,
            eof_reason,
        );
        if is_last {
            last_saw_end = sec.end.is_some();
            last_saw_panic = sec.saw_panic;
            last_footer_saw_end = sec.attempts.last().map(|attempt| attempt.saw_end);
        }
        all_attempts.extend(sec.attempts);
    }

    if !any_frame_seen && protocol_errors.is_empty() {
        protocol_errors.push(format!("no @@MBENCH frames found in '{source}'"));
    }

    let checks = finalize_check_order(check_order, &mut check_map);
    let benches = finalize_bench_order(bench_order, &mut bench_map);
    let counts = CaptureCounts::from_end(&summarize_records(&checks, &benches, total_quarantine));
    let last_attempt_complete = last_footer_saw_end.unwrap_or(true);
    let completed = any_frame_seen && last_saw_end && !last_saw_panic && last_attempt_complete;
    let recovered = total_sections > 1;

    build_report(
        source.to_string(),
        CaptureFormat::RawSerial,
        completed,
        recovered,
        protocol_errors,
        latest_env,
        latest_meta,
        latest_panic,
        last_end,
        counts,
        all_attempts,
        checks,
        benches,
    )
}

fn audit_merged_jsonl(source: &str, lines: &[&str]) -> CaptureReport {
    let parsed = audit_stream_lines(lines, 0, false, true);
    let mut protocol_errors = parsed.errors;

    for attempt in &parsed.attempts {
        for err in &attempt.protocol_errors {
            protocol_errors.push(format!("attempt {}: {err}", attempt.attempt));
        }
    }

    if !parsed.any_frame_seen && protocol_errors.is_empty() {
        protocol_errors.push(format!("no @@MBENCH frames found in '{source}'"));
    }

    if let Some(end) = &parsed.end {
        let computed = summarize_records(&parsed.checks, &parsed.benches, end.quarantine_warnings);
        compare_end_counts("merged capture", &computed, end, &mut protocol_errors);
    }

    let quarantine = parsed.end.map_or(0, |e| e.quarantine_warnings);
    let counts = CaptureCounts::from_end(&summarize_records(
        &parsed.checks,
        &parsed.benches,
        quarantine,
    ));
    let recovered = parsed.attempts.len() > 1
        || parsed.checks.iter().any(|c| c.synthetic)
        || parsed.benches.iter().any(|b| b.synthetic);
    let last_attempt_complete = parsed.attempts.last().is_none_or(|attempt| attempt.saw_end);
    let completed = parsed.any_frame_seen && parsed.end.is_some() && last_attempt_complete;
    let label = parsed
        .env
        .as_ref()
        .and_then(|e| e.label.clone())
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| source.to_string());

    build_report(
        label,
        CaptureFormat::MergedJsonl,
        completed,
        recovered,
        protocol_errors,
        parsed.env,
        parsed.meta,
        parsed.panic,
        parsed.end,
        counts,
        parsed.attempts,
        parsed.checks,
        parsed.benches,
    )
}

#[expect(clippy::too_many_arguments)]
fn build_report(
    source: String,
    format: CaptureFormat,
    completed: bool,
    recovered: bool,
    protocol_errors: Vec<String>,
    env: Option<EnvLine>,
    meta: Option<MetaFrame>,
    panic: Option<PanicFrame>,
    end: Option<EndFrame>,
    counts: CaptureCounts,
    attempts: Vec<AttemptRecord>,
    checks: Vec<CheckFrame>,
    benches: Vec<BenchFrame>,
) -> CaptureReport {
    let check_summaries = checks
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
    let bench_summaries = benches
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
        source,
        format,
        protocol_valid: protocol_errors.is_empty(),
        completed,
        recovered,
        protocol_errors,
        env,
        meta,
        panic,
        end,
        counts,
        attempts,
        checks: check_summaries,
        benches: bench_summaries,
    }
}

struct StreamAuditResult {
    errors: Vec<String>,
    any_frame_seen: bool,
    env: Option<EnvLine>,
    attempts: Vec<AttemptRecord>,
    meta: Option<MetaFrame>,
    panic: Option<PanicFrame>,
    end: Option<EndFrame>,
    saw_panic: bool,
    unclosed_at_end: Vec<StartFrame>,
    unclosed_at_eof: Vec<StartFrame>,
    checks: Vec<CheckFrame>,
    benches: Vec<BenchFrame>,
}

fn audit_stream_lines(
    lines: &[&str],
    line_offset: usize,
    raw_single_attempt: bool,
    expect_end: bool,
) -> StreamAuditResult {
    let mut errors = Vec::new();
    let mut any_frame_seen = false;
    let mut env = None;
    let mut attempts = Vec::new();
    let mut meta = None;
    let mut panic = None;
    let mut end = None;

    let mut tracker = CaseTracker::new();
    let mut unclosed_at_end = Vec::new();
    let mut raw_checks: Vec<CheckFrame> = Vec::new();
    let mut raw_benches: Vec<BenchFrame> = Vec::new();
    let mut seen_check_keys: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_bench_keys: BTreeMap<(String, usize), usize> = BTreeMap::new();
    let mut check_order: Vec<String> = Vec::new();
    let mut check_map: BTreeMap<String, CheckFrame> = BTreeMap::new();
    let mut bench_order: Vec<(String, usize)> = Vec::new();
    let mut bench_map: BTreeMap<(String, usize), BenchFrame> = BTreeMap::new();

    let mut meta_count = 0usize;
    let mut saw_end = false;
    let mut saw_panic = false;

    for (idx, raw_line) in lines.iter().enumerate() {
        let line_no = line_offset + idx + 1;
        let has_mbench_prefix = raw_line.contains("@@MBENCH:");
        let frame = match parse_wire_line(raw_line) {
            Ok(Some(f)) => {
                any_frame_seen = true;
                f
            }
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
            WireFrame::Env(e) => env = Some(e),
            WireFrame::Attempt(a) => attempts.push(a),
            WireFrame::RawAttemptStart(_) => {
                if raw_single_attempt {
                    errors.push(format!(
                        "line {line_no}: unexpected # MBENCH_RAW_ATTEMPT boundary inside attempt"
                    ));
                }
            }
            WireFrame::Meta(m) => {
                if saw_end {
                    errors.push(format!(
                        "line {line_no}: unexpected @@MBENCH:META frame after END"
                    ));
                } else {
                    meta = Some(m);
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
                } else if meta_count == 0 {
                    errors.push(format!(
                        "line {line_no}: @@MBENCH:CAL frame appeared before @@MBENCH:META"
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
                    if meta_count == 0 {
                        errors.push(format!(
                            "line {line_no}: @@MBENCH:START frame appeared before @@MBENCH:META ('{}')",
                            start.id
                        ));
                    }
                    let id = start.id.clone();
                    if !tracker.record_start(start) {
                        errors.push(format!(
                            "line {line_no}: duplicate open @@MBENCH:START frame for '{id}'"
                        ));
                    }
                }
            }
            WireFrame::Check(chk) => {
                if saw_end {
                    errors.push(format!(
                        "line {line_no}: unexpected @@MBENCH:CHECK frame after END ('{}')",
                        chk.id
                    ));
                } else {
                    if meta_count == 0 && !chk.synthetic {
                        errors.push(format!(
                            "line {line_no}: @@MBENCH:CHECK frame appeared before @@MBENCH:META ('{}')",
                            chk.id
                        ));
                    }
                    let had_start = tracker.close_check(&chk.id);
                    if raw_single_attempt
                        && !had_start
                        && chk.status != CheckStatusTag::Skipped
                        && !chk.synthetic
                    {
                        errors.push(format!(
                            "line {line_no}: CHECK frame '{}' ({:?}) without matching @@MBENCH:START",
                            chk.id, chk.status
                        ));
                    }
                    if raw_single_attempt {
                        if let Some(prev_line) = seen_check_keys.insert(chk.id.clone(), line_no) {
                            errors.push(format!(
                                "line {line_no}: duplicate CHECK frame for '{}' (first seen at line {prev_line})",
                                chk.id
                            ));
                        }
                        raw_checks.push(chk.clone());
                    }
                    merge_check_into(&mut check_order, &mut check_map, chk);
                }
            }
            WireFrame::Bench(bench) => {
                if saw_end {
                    errors.push(format!(
                        "line {line_no}: unexpected @@MBENCH:BENCH frame after END ('{}')",
                        bench.id
                    ));
                } else {
                    if meta_count == 0 && !bench.synthetic {
                        errors.push(format!(
                            "line {line_no}: @@MBENCH:BENCH frame appeared before @@MBENCH:META ('{}')",
                            bench.id
                        ));
                    }
                    let had_start = tracker.close_bench(&bench.id, bench.parallel);
                    if raw_single_attempt
                        && !had_start
                        && bench.status != BenchStatusTag::Skipped
                        && !bench.synthetic
                    {
                        errors.push(format!(
                            "line {line_no}: BENCH frame '{}' (parallel={}, {:?}) without matching @@MBENCH:START",
                            bench.id, bench.parallel, bench.status
                        ));
                    }
                    if raw_single_attempt {
                        let key = (bench.id.clone(), bench.parallel);
                        if let Some(prev_line) = seen_bench_keys.insert(key, line_no) {
                            errors.push(format!(
                                "line {line_no}: duplicate BENCH frame for '{}' (parallel={}, first seen at line {prev_line})",
                                bench.id, bench.parallel
                            ));
                        }
                        raw_benches.push((*bench).clone());
                    }
                    merge_bench_into(&mut bench_order, &mut bench_map, *bench);
                }
            }
            WireFrame::End(end_rec) => {
                if saw_end {
                    errors.push(format!("line {line_no}: duplicate @@MBENCH:END frame"));
                } else {
                    saw_end = true;
                    end = Some(end_rec);
                    for unclosed in tracker.drain_all() {
                        errors.push(format!(
                            "line {line_no}: unclosed @@MBENCH:START frame before END ({:?} '{}', parallel={})",
                            unclosed.kind, unclosed.id, unclosed.parallel
                        ));
                        unclosed_at_end.push(unclosed);
                    }
                    if raw_single_attempt {
                        let computed = summarize_records(
                            &raw_checks,
                            &raw_benches,
                            end_rec.quarantine_warnings,
                        );
                        compare_end_counts(
                            &format!("line {line_no}"),
                            &computed,
                            &end_rec,
                            &mut errors,
                        );
                    }
                }
            }
            WireFrame::Panic(p) => {
                if saw_end {
                    errors.push(format!(
                        "line {line_no}: unexpected @@MBENCH:PANIC frame after END"
                    ));
                }
                saw_panic = true;
                panic = Some(p);
            }
        }
    }

    let unclosed_at_eof = tracker.drain_all();
    if expect_end {
        if meta_count == 0 && !saw_panic {
            errors.push(String::from("missing @@MBENCH:META frame"));
        }
        if !saw_end {
            errors.push(String::from("missing @@MBENCH:END frame"));
        }
        for unclosed in &unclosed_at_eof {
            errors.push(format!(
                "unclosed @@MBENCH:START frame at EOF ({:?} '{}', parallel={})",
                unclosed.kind, unclosed.id, unclosed.parallel
            ));
        }
    }

    StreamAuditResult {
        errors,
        any_frame_seen,
        env,
        attempts,
        meta,
        panic,
        end,
        saw_panic,
        unclosed_at_end,
        unclosed_at_eof,
        checks: finalize_check_order(check_order, &mut check_map),
        benches: finalize_bench_order(bench_order, &mut bench_map),
    }
}

pub(crate) fn merge_synthesized_unclosed(
    check_order: &mut Vec<String>,
    check_map: &mut BTreeMap<String, CheckFrame>,
    bench_order: &mut Vec<(String, usize)>,
    bench_map: &mut BTreeMap<(String, usize), BenchFrame>,
    unclosed: &[StartFrame],
    reason: &str,
) {
    for start in unclosed {
        match start.kind {
            StartKind::Check => {
                if !check_map
                    .get(&start.id)
                    .is_some_and(|existing| existing.skip_reason != Some(SkipReason::ResumedPast))
                {
                    merge_check_into(
                        check_order,
                        check_map,
                        synthesize_fail_check(&start.id, reason),
                    );
                }
            }
            StartKind::Bench => {
                let key = (start.id.clone(), start.parallel);
                if !bench_map
                    .get(&key)
                    .is_some_and(|existing| existing.skip_reason != Some(SkipReason::ResumedPast))
                {
                    merge_bench_into(
                        bench_order,
                        bench_map,
                        synthesize_fail_bench(&start.id, start.parallel, reason),
                    );
                }
            }
        }
    }
}

pub(crate) fn merge_check_into(
    order: &mut Vec<String>,
    map: &mut BTreeMap<String, CheckFrame>,
    chk: CheckFrame,
) {
    if chk.skip_reason == Some(SkipReason::ResumedPast) && map.contains_key(&chk.id) {
        return;
    }
    if !map.contains_key(&chk.id) {
        order.push(chk.id.clone());
    }
    map.insert(chk.id.clone(), chk);
}

pub(crate) fn merge_bench_into(
    order: &mut Vec<(String, usize)>,
    map: &mut BTreeMap<(String, usize), BenchFrame>,
    bench: BenchFrame,
) {
    let key = (bench.id.clone(), bench.parallel);
    if bench.skip_reason == Some(SkipReason::ResumedPast) && map.contains_key(&key) {
        return;
    }
    if !map.contains_key(&key) {
        order.push(key.clone());
    }
    map.insert(key, bench);
}

pub(crate) fn finalize_check_order(
    order: Vec<String>,
    map: &mut BTreeMap<String, CheckFrame>,
) -> Vec<CheckFrame> {
    order.into_iter().filter_map(|id| map.remove(&id)).collect()
}

pub(crate) fn finalize_bench_order(
    order: Vec<(String, usize)>,
    map: &mut BTreeMap<(String, usize), BenchFrame>,
) -> Vec<BenchFrame> {
    order
        .into_iter()
        .filter_map(|key| map.remove(&key))
        .collect()
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
        if !matches!(status, CheckStatus::Skipped(_)) {
            protocol::write_start_line(StartKind::Check, id, 1, &mut out).unwrap();
        }
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
        if !matches!(status, BenchStatus::Skipped(_)) {
            protocol::write_start_line(StartKind::Bench, id, parallel, &mut out).unwrap();
        }
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
    fn audits_raw_captures_and_retains_valid_facts_on_parse_errors() {
        let mut cal = String::new();
        protocol::write_cal_line(&CalibrationRecord::default(), &mut cal).unwrap();

        let mut ok_log = sample_meta(4, SbiCapMask::BASE | SbiCapMask::HSM);
        ok_log.push_str(&cal);
        ok_log.push_str(&check_line("conformance/base", CheckStatus::Pass));
        ok_log.push_str(&check_line(
            "conformance/time",
            CheckStatus::Skipped(SkipReason::FilteredOut),
        ));
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
            checks_total: 3,
            checks_passed: 1,
            checks_skipped: 1,
            checks_failed: 1,
            check_assertions_total: 15,
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

        let report = audit_capture("ok", &ok_log);
        assert_eq!(report.format, CaptureFormat::RawSerial);
        assert!(report.protocol_valid, "{:?}", report.protocol_errors);
        assert!(report.completed);
        assert!(!report.recovered);
        assert_eq!(report.counts.checks_failed, 1);
        assert_eq!(report.counts.checks_skipped, 1);
        assert_eq!(report.counts.benches_failed, 1);
        assert_eq!(report.counts.benches_effective, 1);
        assert_eq!(
            report.meta.as_ref().unwrap().extensions,
            vec![SbiExtensionId::Base, SbiExtensionId::Hsm]
        );

        // One truncated frame mid-stream must NOT discard meta, surviving checks/benches, or end.
        let mut partial_corrupt = sample_meta(4, SbiCapMask::BASE);
        partial_corrupt.push_str(&check_line("conformance/base", CheckStatus::Pass));
        partial_corrupt
            .push_str("@@MBENCH:START {\"kind\":\"bench\",\"id\":\"base/probe\",\"parallel\":1}\n");
        partial_corrupt.push_str("@@MBENCH:BENCH {\"id\":\"base/probe\",\"group\":\"base\"\n");
        partial_corrupt.push_str(&end_line(EndRecord {
            checks_total: 1,
            checks_passed: 1,
            check_assertions_total: 5,
            check_assertions_passed: 5,
            ..EndRecord::default()
        }));
        let corrupt_report = audit_capture("corrupt-mid", &partial_corrupt);
        assert!(!corrupt_report.protocol_valid);
        assert!(corrupt_report.meta.is_some());
        assert_eq!(corrupt_report.checks.len(), 1);
        assert_eq!(corrupt_report.checks[0].id, "conformance/base");
        assert_eq!(corrupt_report.counts.checks_passed, 1);
        assert_eq!(corrupt_report.benches.len(), 1);
        assert_eq!(corrupt_report.benches[0].id, "base/probe");
        assert_eq!(corrupt_report.benches[0].status, BenchStatusTag::Fail);
        assert_eq!(
            corrupt_report.benches[0].fail_reason.as_deref(),
            Some("protocol_error")
        );
        assert!(corrupt_report.benches[0].synthetic);
        assert_eq!(corrupt_report.counts.benches_failed, 1);
        assert!(corrupt_report.end.is_some());
        assert!(corrupt_report.completed);

        // Non-SKIPPED CHECK or BENCH without matching START must fail protocol audit.
        let mut missing_start = sample_meta(1, SbiCapMask::BASE);
        missing_start.push_str("@@MBENCH:CHECK {\"id\":\"conformance/base\",\"checks\":1,\"checks_total\":1,\"status\":\"PASS\"}\n");
        missing_start.push_str("@@MBENCH:BENCH {\"id\":\"base/get_spec_version\",\"group\":\"base\",\"mode\":\"batched\",\"parallel\":1,\"unit\":\"call\",\"iters_per_trial\":16,\"trials\":5,\"status\":\"PASS\"}\n");
        missing_start.push_str(&end_line(EndRecord {
            checks_total: 1,
            checks_passed: 1,
            check_assertions_total: 1,
            check_assertions_passed: 1,
            benches_total: 1,
            benches_passed: 1,
            ..EndRecord::default()
        }));
        let missing_start_report = audit_capture("missing-start", &missing_start);
        assert!(!missing_start_report.protocol_valid);
        assert!(
            missing_start_report
                .protocol_errors
                .iter()
                .any(|e| e.contains("CHECK frame") && e.contains("without matching @@MBENCH:START"))
        );
        assert!(
            missing_start_report
                .protocol_errors
                .iter()
                .any(|e| e.contains("BENCH frame") && e.contains("without matching @@MBENCH:START"))
        );

        // Records emitted before META must fail ordering checks.
        let mut before_meta = String::new();
        before_meta.push_str(&check_line("conformance/base", CheckStatus::Pass));
        before_meta.push_str(&sample_meta(1, SbiCapMask::BASE));
        before_meta.push_str(&end_line(EndRecord {
            checks_total: 1,
            checks_passed: 1,
            check_assertions_total: 5,
            check_assertions_passed: 5,
            ..EndRecord::default()
        }));
        let before_meta_report = audit_capture("before-meta", &before_meta);
        assert!(!before_meta_report.protocol_valid);
        assert!(
            before_meta_report
                .protocol_errors
                .iter()
                .any(|e| e.contains("before @@MBENCH:META"))
        );
    }

    #[test]
    fn audits_multi_attempt_raw_log_with_boundaries_and_retains_errors() {
        let mut multi_raw = String::from("# MBENCH_RAW_ATTEMPT {\"attempt\":0}\n");
        multi_raw.push_str(&sample_meta(1, SbiCapMask::BASE));
        multi_raw.push_str(&bench_line(
            "baseline/loop",
            BenchGroup::Baseline,
            1,
            BenchStatus::Pass,
        ));
        multi_raw.push_str(
            "@@MBENCH:START {\"kind\":\"bench\",\"id\":\"baseline/counter\",\"parallel\":1}\n",
        );
        multi_raw.push_str("@@MBENCH:BENCH {\"id\":\"baseline/counter\",\"group\":\"baseline\"\n");

        multi_raw.push_str(
            "# MBENCH_RAW_ATTEMPT {\"attempt\":1,\"resume_after\":\"baseline/counter\"}\n",
        );
        multi_raw.push_str(&sample_meta(1, SbiCapMask::BASE));
        multi_raw.push_str(&bench_line(
            "baseline/loop",
            BenchGroup::Baseline,
            1,
            BenchStatus::Skipped(SkipReason::ResumedPast),
        ));
        multi_raw.push_str(&bench_line(
            "baseline/counter",
            BenchGroup::Baseline,
            1,
            BenchStatus::Skipped(SkipReason::ResumedPast),
        ));
        multi_raw.push_str(&bench_line(
            "baseline/s_trap",
            BenchGroup::Baseline,
            1,
            BenchStatus::Pass,
        ));
        multi_raw.push_str(&end_line(EndRecord {
            benches_total: 3,
            benches_passed: 1,
            benches_skipped: 2,
            ..EndRecord::default()
        }));

        let rep = audit_capture("multi-raw", &multi_raw);
        assert_eq!(rep.format, CaptureFormat::RawSerial);
        assert!(!rep.protocol_valid);
        assert!(rep.completed);
        assert!(rep.recovered);
        assert!(rep.meta.is_some());
        assert_eq!(rep.counts.benches_passed, 2);
        assert_eq!(rep.counts.benches_failed, 1);
        assert_eq!(rep.counts.benches_skipped, 0);
        let counter = rep
            .benches
            .iter()
            .find(|b| b.id == "baseline/counter")
            .expect("baseline/counter retained");
        assert_eq!(counter.status, BenchStatusTag::Fail);
        assert_eq!(counter.fail_reason.as_deref(), Some("incomplete"));
        assert!(counter.synthetic);
        assert!(
            rep.protocol_errors
                .iter()
                .any(|e| e.starts_with("attempt 0:"))
        );
        assert!(
            !rep.protocol_errors
                .iter()
                .any(|e| e.contains("duplicate @@MBENCH:META")),
            "second attempt META must not be flagged as duplicate META: {:?}",
            rep.protocol_errors
        );

        // Clean crash recovery with # MBENCH_ATTEMPT footers must remain protocol_valid,
        // preserve attempt closure records, and retain the crashed case as synthetic FAIL("crash").
        let mut clean_crash_raw = String::from("# MBENCH_RAW_ATTEMPT {\"attempt\":0}\n");
        clean_crash_raw.push_str(&sample_meta(1, SbiCapMask::BASE));
        clean_crash_raw.push_str(
            "@@MBENCH:START {\"kind\":\"bench\",\"id\":\"baseline/loop\",\"parallel\":1}\n",
        );
        let att0 = AttemptRecord {
            attempt: 0,
            resume_after: None,
            saw_end: false,
            shutdown: ShutdownStatus::Signaled,
            protocol_errors: vec![String::from("missing @@MBENCH:END frame")],
            synthesized_failures: vec![String::from("baseline/loop")],
        };
        clean_crash_raw.push_str(&format!(
            "# MBENCH_ATTEMPT {}\n",
            serde_json::to_string(&att0).unwrap()
        ));
        clean_crash_raw
            .push_str("# MBENCH_RAW_ATTEMPT {\"attempt\":1,\"resume_after\":\"baseline/loop\"}\n");
        clean_crash_raw.push_str(&sample_meta(1, SbiCapMask::BASE));
        clean_crash_raw.push_str(&bench_line(
            "baseline/loop",
            BenchGroup::Baseline,
            1,
            BenchStatus::Skipped(SkipReason::ResumedPast),
        ));
        clean_crash_raw.push_str(&bench_line(
            "baseline/counter",
            BenchGroup::Baseline,
            1,
            BenchStatus::Pass,
        ));
        clean_crash_raw.push_str(&end_line(EndRecord {
            benches_total: 2,
            benches_passed: 1,
            benches_skipped: 1,
            ..EndRecord::default()
        }));
        let att1 = AttemptRecord {
            attempt: 1,
            resume_after: Some(String::from("baseline/loop")),
            saw_end: true,
            shutdown: ShutdownStatus::CleanExit,
            protocol_errors: Vec::new(),
            synthesized_failures: Vec::new(),
        };
        clean_crash_raw.push_str(&format!(
            "# MBENCH_ATTEMPT {}\n",
            serde_json::to_string(&att1).unwrap()
        ));

        let crash_rep = audit_capture("clean-crash-raw", &clean_crash_raw);
        assert_eq!(crash_rep.format, CaptureFormat::RawSerial);
        assert!(crash_rep.protocol_valid, "{:?}", crash_rep.protocol_errors);
        assert!(crash_rep.completed);
        assert!(crash_rep.recovered);
        assert_eq!(crash_rep.attempts.len(), 2);
        assert_eq!(crash_rep.attempts[0].shutdown, ShutdownStatus::Signaled);
        assert_eq!(crash_rep.attempts[1].shutdown, ShutdownStatus::CleanExit);
        assert_eq!(crash_rep.counts.benches_passed, 1);
        assert_eq!(crash_rep.counts.benches_failed, 1);
        assert_eq!(crash_rep.counts.benches_skipped, 0);
        let loop_res = crash_rep
            .benches
            .iter()
            .find(|b| b.id == "baseline/loop")
            .expect("baseline/loop retained");
        assert_eq!(loop_res.status, BenchStatusTag::Fail);
        assert_eq!(loop_res.fail_reason.as_deref(), Some("crash"));
        assert!(loop_res.synthetic);

        // If attempt 1 reaches END cleanly without its own # MBENCH_ATTEMPT footer,
        // completed must still be true rather than inheriting attempt 0's saw_end=false.
        let att1_footer_prefix = "# MBENCH_ATTEMPT {\"attempt\":1,";
        let missing_last_footer: String = clean_crash_raw
            .lines()
            .filter(|line| !line.starts_with(att1_footer_prefix))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let missing_footer_rep = audit_capture("missing-last-footer", &missing_last_footer);
        assert!(
            missing_footer_rep.protocol_valid,
            "{:?}",
            missing_footer_rep.protocol_errors
        );
        assert!(missing_footer_rep.completed);
        assert!(missing_footer_rep.recovered);
        assert_eq!(missing_footer_rep.attempts.len(), 1);
        assert!(!missing_footer_rep.attempts[0].saw_end);
        assert_eq!(missing_footer_rep.counts.benches_passed, 1);
        assert_eq!(missing_footer_rep.counts.benches_failed, 1);
        assert_eq!(missing_footer_rep.counts.benches_skipped, 0);

        // When the final attempt explicitly records saw_end=false, completed stays false.
        let mut att1_incomplete = att1;
        att1_incomplete.saw_end = false;
        let explicit_incomplete = format!(
            "{missing_last_footer}# MBENCH_ATTEMPT {}\n",
            serde_json::to_string(&att1_incomplete).unwrap()
        );
        let explicit_incomplete_rep = audit_capture("explicit-incomplete", &explicit_incomplete);
        assert!(!explicit_incomplete_rep.completed);

        // Two META frames inside the same attempt boundary still fail.
        let mut dup_meta_raw = String::from("# MBENCH_RAW_ATTEMPT {\"attempt\":0}\n");
        dup_meta_raw.push_str(&sample_meta(1, SbiCapMask::BASE));
        dup_meta_raw.push_str(&sample_meta(1, SbiCapMask::BASE));
        dup_meta_raw.push_str(&end_line(EndRecord::default()));
        let dup_rep = audit_capture("dup-meta", &dup_meta_raw);
        assert!(!dup_rep.protocol_valid);
        assert!(
            dup_rep
                .protocol_errors
                .iter()
                .any(|e| e.contains("duplicate @@MBENCH:META frame"))
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
            shutdown: ShutdownStatus::Interrupted,
            protocol_errors: Vec::new(),
            synthesized_failures: vec![String::from("conformance/time")],
        };
        merged_recovered.push_str(&format!(
            "# MBENCH_ATTEMPT {}\n",
            serde_json::to_string(&a0).unwrap()
        ));
        let rec_report = audit_capture("interrupted", &merged_recovered);
        assert!(
            rec_report
                .protocol_errors
                .iter()
                .any(|e| e.contains("missing @@MBENCH:END"))
        );
        assert!(!rec_report.protocol_valid);
        assert!(!rec_report.completed);
        assert!(rec_report.recovered);
        assert!(rec_report.meta.is_some());
        assert_eq!(rec_report.checks.len(), 1);
        assert_eq!(rec_report.attempts[0].shutdown, ShutdownStatus::Interrupted);
    }
}
