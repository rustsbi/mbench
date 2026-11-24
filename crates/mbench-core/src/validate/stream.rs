use std::collections::BTreeMap;

use super::{AuditReport, CaptureFormat, CaptureReport, compare_end_counts, summarize_records};
use crate::{
    capture::{CaseTracker, RecordMerger},
    wire::{
        AttemptRecord, BenchFrame, BenchStatusTag, CheckFrame, CheckStatusTag, EndFrame, EnvLine,
        MetaFrame, PanicFrame, StartFrame, WireFrame, parse_wire_line, shutdown_fail_reason,
    },
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum AuditMode {
    RawAttempt,
    Merged,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EndRequirement {
    Required,
    Optional,
}

impl EndRequirement {
    const fn from_expected(expected: bool) -> Self {
        if expected {
            Self::Required
        } else {
            Self::Optional
        }
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
    mode: AuditMode,
    end_requirement: EndRequirement,
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
    let mut records = RecordMerger::default();

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
                if mode == AuditMode::RawAttempt {
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
                    if mode == AuditMode::RawAttempt && meta_count > 1 {
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
                    if mode == AuditMode::RawAttempt
                        && !had_start
                        && chk.status != CheckStatusTag::Skipped
                        && !chk.synthetic
                    {
                        errors.push(format!(
                            "line {line_no}: CHECK frame '{}' ({:?}) without matching @@MBENCH:START",
                            chk.id, chk.status
                        ));
                    }
                    if mode == AuditMode::RawAttempt {
                        if let Some(prev_line) = seen_check_keys.insert(chk.id.clone(), line_no) {
                            errors.push(format!(
                                "line {line_no}: duplicate CHECK frame for '{}' (first seen at line {prev_line})",
                                chk.id
                            ));
                        }
                        raw_checks.push(chk.clone());
                    }
                    records.insert_check(chk);
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
                    if mode == AuditMode::RawAttempt
                        && !had_start
                        && bench.status != BenchStatusTag::Skipped
                        && !bench.synthetic
                    {
                        errors.push(format!(
                            "line {line_no}: BENCH frame '{}' (parallel={}, {:?}) without matching @@MBENCH:START",
                            bench.id, bench.parallel, bench.status
                        ));
                    }
                    if mode == AuditMode::RawAttempt {
                        let key = (bench.id.clone(), bench.parallel);
                        if let Some(prev_line) = seen_bench_keys.insert(key, line_no) {
                            errors.push(format!(
                                "line {line_no}: duplicate BENCH frame for '{}' (parallel={}, first seen at line {prev_line})",
                                bench.id, bench.parallel
                            ));
                        }
                        raw_benches.push((*bench).clone());
                    }
                    records.insert_bench(*bench);
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
                    if mode == AuditMode::RawAttempt {
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
    if end_requirement == EndRequirement::Required {
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

    let (checks, benches) = records.finish();
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
        checks,
        benches,
    }
}

struct RawSection<'lines, 'text> {
    attempt_num: Option<usize>,
    start_offset: usize,
    lines: &'lines [&'text str],
}

/// Audits a single raw serial execution attempt for framing, ordering, START closure, and END integrity.
pub fn audit_raw_attempt(raw_lines: &[String], expect_end: bool) -> Vec<String> {
    let lines: Vec<&str> = raw_lines.iter().map(String::as_str).collect();
    audit_stream_lines(
        &lines,
        0,
        AuditMode::RawAttempt,
        EndRequirement::from_expected(expect_end),
    )
    .errors
}
pub(super) fn audit_single_attempt_raw(source: &str, lines: &[&str]) -> CaptureReport {
    let parsed = audit_stream_lines(lines, 0, AuditMode::RawAttempt, EndRequirement::Required);
    let mut report = AuditReport::new(source.to_string(), CaptureFormat::RawSerial);
    report.errors = parsed.errors;
    if !parsed.any_frame_seen && report.errors.is_empty() {
        report
            .errors
            .push(format!("no @@MBENCH frames found in '{source}'"));
    }

    report.records.extend(parsed.checks, parsed.benches);
    report
        .records
        .synthesize_unclosed(&parsed.unclosed_at_end, "protocol_error");
    let eof_reason = if parsed.saw_panic {
        "crash"
    } else {
        "incomplete"
    };
    report
        .records
        .synthesize_unclosed(&parsed.unclosed_at_eof, eof_reason);

    let completed = parsed.any_frame_seen && parsed.end.is_some() && parsed.panic.is_none();
    let quarantine = parsed.end.map_or(0, |e| e.quarantine_warnings);

    report.env = parsed.env;
    report.meta = parsed.meta;
    report.panic = parsed.panic;
    report.end = parsed.end;
    report.quarantine = quarantine;
    report.finish(completed, false)
}
pub(super) fn audit_multi_attempt_raw(source: &str, lines: &[&str]) -> CaptureReport {
    let mut report = AuditReport::new(source.to_string(), CaptureFormat::RawSerial);
    let mut sections: Vec<RawSection<'_, '_>> = Vec::new();
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
            Ok(Some(_)) => report.errors.push(format!(
                "line {line_no}: unexpected @@MBENCH frame before first # MBENCH_RAW_ATTEMPT marker"
            )),
            Ok(None) if has_prefix => report.errors.push(format!(
                "line {line_no}: malformed or unknown @@MBENCH directive before first # MBENCH_RAW_ATTEMPT marker"
            )),
            Ok(None) => {}
            Err(err) => report.errors.push(format!("line {line_no}: {err}")),
        }
    }

    for (pos, &marker_idx) in marker_indices.iter().enumerate() {
        let marker_line_no = marker_idx + 1;
        let attempt_num = match parse_wire_line(lines[marker_idx]) {
            Ok(Some(WireFrame::RawAttemptStart(boundary))) => {
                if boundary.attempt != pos {
                    report.errors.push(format!(
                        "line {marker_line_no}: unexpected attempt index {} (expected {pos})",
                        boundary.attempt
                    ));
                }
                Some(boundary.attempt)
            }
            Ok(_) => {
                report.errors.push(format!(
                    "line {marker_line_no}: malformed # MBENCH_RAW_ATTEMPT marker"
                ));
                None
            }
            Err(err) => {
                report.errors.push(format!("line {marker_line_no}: {err}"));
                None
            }
        };
        let end_idx = marker_indices.get(pos + 1).copied().unwrap_or(lines.len());
        sections.push(RawSection {
            attempt_num,
            start_offset: marker_idx + 1,
            lines: &lines[marker_idx + 1..end_idx],
        });
    }

    let total_sections = sections.len();
    let mut any_frame_seen = false;
    let mut last_saw_end = false;
    let mut last_saw_panic = false;
    let mut last_footer_saw_end: Option<bool> = None;

    for (
        sec_idx,
        RawSection {
            attempt_num,
            start_offset,
            lines: sec_lines,
        },
    ) in sections.into_iter().enumerate()
    {
        let is_last = sec_idx + 1 == total_sections;
        let sec = audit_stream_lines(
            sec_lines,
            start_offset,
            AuditMode::RawAttempt,
            EndRequirement::from_expected(is_last),
        );
        let prefix = match attempt_num {
            Some(n) => format!("attempt {n}"),
            None => format!("section {sec_idx}"),
        };
        for err in sec.errors {
            report.errors.push(format!("{prefix}: {err}"));
        }

        if sec.attempts.len() > 1 {
            report.errors.push(format!(
                "{prefix}: multiple # MBENCH_ATTEMPT records inside single attempt"
            ));
        }
        if let (Some(expected), Some(rec)) = (attempt_num, sec.attempts.first())
            && rec.attempt != expected
        {
            report.errors.push(format!(
                "{prefix}: mismatched # MBENCH_ATTEMPT index {} (expected {expected})",
                rec.attempt
            ));
        }

        any_frame_seen |= sec.any_frame_seen;
        if let Some(env) = sec.env {
            report.env = Some(env);
        }
        if let Some(meta) = sec.meta {
            report.meta = Some(meta);
        }
        if let Some(panic) = sec.panic {
            report.panic = Some(panic);
        }
        if let Some(end) = sec.end {
            report.quarantine = report.quarantine.saturating_add(end.quarantine_warnings);
            report.end = Some(end);
        } else if is_last {
            report.end = None;
        }
        report.records.extend(sec.checks, sec.benches);
        report
            .records
            .synthesize_unclosed(&sec.unclosed_at_end, "protocol_error");
        let eof_reason = sec
            .attempts
            .last()
            .map_or(if sec.saw_panic { "crash" } else { "incomplete" }, |rec| {
                shutdown_fail_reason(&rec.shutdown)
            });
        report
            .records
            .synthesize_unclosed(&sec.unclosed_at_eof, eof_reason);
        if is_last {
            last_saw_end = sec.end.is_some();
            last_saw_panic = sec.saw_panic;
            last_footer_saw_end = sec.attempts.last().map(|attempt| attempt.saw_end);
        }
        report.attempts.extend(sec.attempts);
    }

    if !any_frame_seen && report.errors.is_empty() {
        report
            .errors
            .push(format!("no @@MBENCH frames found in '{source}'"));
    }

    let last_attempt_complete = last_footer_saw_end.unwrap_or(true);
    let completed = any_frame_seen && last_saw_end && !last_saw_panic && last_attempt_complete;
    let recovered = total_sections > 1;

    report.finish(completed, recovered)
}

pub(super) fn audit_merged_jsonl(source: &str, lines: &[&str]) -> CaptureReport {
    let parsed = audit_stream_lines(lines, 0, AuditMode::Merged, EndRequirement::Required);
    let label = parsed
        .env
        .as_ref()
        .and_then(|e| e.label.clone())
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| source.to_string());
    let mut report = AuditReport::new(label, CaptureFormat::MergedJsonl);
    report.errors = parsed.errors;

    for attempt in &parsed.attempts {
        for err in &attempt.protocol_errors {
            report
                .errors
                .push(format!("attempt {}: {err}", attempt.attempt));
        }
    }

    if !parsed.any_frame_seen && report.errors.is_empty() {
        report
            .errors
            .push(format!("no @@MBENCH frames found in '{source}'"));
    }

    if let Some(end) = &parsed.end {
        let computed = summarize_records(&parsed.checks, &parsed.benches, end.quarantine_warnings);
        compare_end_counts("merged capture", &computed, end, &mut report.errors);
    }

    let quarantine = parsed.end.map_or(0, |e| e.quarantine_warnings);
    let recovered = parsed.attempts.len() > 1
        || parsed.checks.iter().any(|c| c.synthetic)
        || parsed.benches.iter().any(|b| b.synthetic);
    let last_attempt_complete = parsed.attempts.last().is_none_or(|attempt| attempt.saw_end);
    let completed = parsed.any_frame_seen && parsed.end.is_some() && last_attempt_complete;

    report.env = parsed.env;
    report.meta = parsed.meta;
    report.panic = parsed.panic;
    report.end = parsed.end;
    report.attempts = parsed.attempts;
    report.quarantine = quarantine;
    report.records.extend(parsed.checks, parsed.benches);
    report.finish(completed, recovered)
}
