use serde::de::DeserializeOwned;

use super::*;
use crate::capture::{CaseTracker, RecordMerger};

/// Parses one line from either a saved `.jsonl` capture or noisy raw serial output.
///
/// Dispatches strictly on the first `@@MBENCH:<TAG>` prefix on the line and validates semantic invariants.
///
/// # Errors
///
/// Returns an error for invalid JSON in a recognized frame or inconsistent CHECK/BENCH
/// payloads. Unrecognized lines and tags return `Ok(None)`.
pub fn parse_wire_line(raw_line: &str) -> Result<Option<WireFrame>, String> {
    let line = raw_line.trim_end_matches(['\r', '\n']);
    if let Some(json) = line.strip_prefix("# MBENCH_ENV ") {
        return decode_frame("MBENCH_ENV", json).map(|frame| Some(WireFrame::Env(frame)));
    }
    if let Some(json) = line.strip_prefix("# MBENCH_ATTEMPT ") {
        return decode_frame("MBENCH_ATTEMPT", json).map(|frame| Some(WireFrame::Attempt(frame)));
    }
    if let Some(json) = line.strip_prefix("# MBENCH_RAW_ATTEMPT ") {
        return decode_frame("MBENCH_RAW_ATTEMPT", json)
            .map(|frame| Some(WireFrame::RawAttemptStart(frame)));
    }

    let Some(pos) = line.find("@@MBENCH:") else {
        return Ok(None);
    };
    let after_prefix = &line[pos + "@@MBENCH:".len()..];
    let Some((tag, payload)) = after_prefix.split_once(' ') else {
        return Ok(None);
    };
    let json = payload.trim();

    let frame = match tag {
        "META" => WireFrame::Meta(decode_frame(tag, json)?),
        "CAL" => WireFrame::Cal(decode_frame(tag, json)?),
        "START" => WireFrame::Start(decode_frame(tag, json)?),
        "CHECK" => {
            let parsed = decode_frame(tag, json)?;
            validate_check_frame(&parsed)?;
            WireFrame::Check(parsed)
        }
        "BENCH" => {
            let parsed = decode_frame(tag, json)?;
            validate_bench_frame(&parsed)?;
            WireFrame::Bench(Box::new(parsed))
        }
        "END" => WireFrame::End(decode_frame(tag, json)?),
        "PANIC" => WireFrame::Panic(decode_frame(tag, json)?),
        _ => return Ok(None),
    };
    Ok(Some(frame))
}

fn decode_frame<T: DeserializeOwned>(tag: &str, json: &str) -> Result<T, String> {
    serde_json::from_str(json).map_err(|e| format!("invalid {tag} frame: {e}"))
}
fn validate_check_frame(frame: &CheckFrame) -> Result<(), String> {
    let has_failure_issue = frame.issues.iter().any(|i| i.class.is_failure());
    match frame.status {
        CheckStatusTag::Pass => {
            if frame.skip_reason.is_some()
                || frame.fail_reason.is_some()
                || frame.checks_failed > 0
                || frame.quirks > 0
                || has_failure_issue
            {
                return Err(format!(
                    "CHECK PASS frame '{}' carries skip/fail reason, quirks, or failure issue",
                    frame.id
                ));
            }
        }
        CheckStatusTag::Skipped => {
            if frame.skip_reason.is_none()
                || frame.fail_reason.is_some()
                || frame.checks_failed > 0
                || frame.quirks > 0
                || has_failure_issue
            {
                return Err(format!(
                    "CHECK SKIPPED frame '{}' has invalid reason, quirks, or failure fields",
                    frame.id
                ));
            }
        }
        CheckStatusTag::Fail => {
            if frame.fail_reason.is_none() || frame.skip_reason.is_some() {
                return Err(format!(
                    "CHECK FAIL frame '{}' has invalid reason fields",
                    frame.id
                ));
            }
        }
    }
    Ok(())
}

fn validate_bench_frame(frame: &BenchFrame) -> Result<(), String> {
    let has_any_stats = frame.cycles.is_some()
        || frame.instret.is_some()
        || frame.ticks.is_some()
        || frame.ns.is_some()
        || frame.throughput_ops_per_sec.is_some();

    match frame.status {
        BenchStatusTag::Pass => {
            if frame.skip_reason.is_some() || frame.fail_reason.is_some() {
                return Err(format!(
                    "BENCH PASS frame '{}' carries skip/fail reason",
                    frame.id
                ));
            }
            if frame.mode.is_none() || frame.trials == 0 {
                return Err(format!(
                    "BENCH PASS frame '{}' missing mode or zero trials",
                    frame.id
                ));
            }
        }
        BenchStatusTag::HwNative => {
            if frame.skip_reason.is_some() || frame.fail_reason.is_some() || frame.trials != 1 {
                return Err(format!(
                    "BENCH HW_NATIVE frame '{}' violates invariants",
                    frame.id
                ));
            }
        }
        BenchStatusTag::Skipped => {
            if frame.skip_reason.is_none() || frame.fail_reason.is_some() || has_any_stats {
                return Err(format!(
                    "BENCH SKIPPED frame '{}' carries invalid fields",
                    frame.id
                ));
            }
        }
        BenchStatusTag::DelegatedToS => {
            if frame.skip_reason.is_some() || frame.fail_reason.is_some() || has_any_stats {
                return Err(format!(
                    "BENCH DELEGATED_TO_S frame '{}' carries invalid fields",
                    frame.id
                ));
            }
        }
        BenchStatusTag::Fail => {
            if frame.fail_reason.is_none() || frame.skip_reason.is_some() || has_any_stats {
                return Err(format!(
                    "BENCH FAIL frame '{}' carries invalid fields",
                    frame.id
                ));
            }
        }
    }

    for stats in [&frame.cycles, &frame.instret, &frame.ticks]
        .into_iter()
        .flatten()
    {
        if stats.net_samples_x100.len() != frame.trials
            || stats.raw_batch_totals.len() != frame.trials
        {
            return Err(format!(
                "BENCH frame '{}' sample array length does not match trials={}",
                frame.id, frame.trials
            ));
        }
    }
    if let Some(ns) = &frame.ns
        && ns.net_samples_x100.len() != frame.trials
    {
        return Err(format!(
            "BENCH frame '{}' ns sample length does not match trials={}",
            frame.id, frame.trials
        ));
    }
    Ok(())
}

/// Extracts `@@MBENCH:*` records from either saved `.jsonl` captures or noisy raw serial output.
///
/// # Errors
///
/// Returns the first recognized-frame decoding error, or an error when the capture has
/// no metadata, check, benchmark, panic, or attempt-footer records.
pub fn parse_capture(default_label: &str, text: &str) -> Result<ParsedCapture, String> {
    let mut label = default_label.to_string();
    let mut env_hdr = None;
    let mut clock_regime = ClockRegime::Unknown;
    let mut max_harts = None;
    let mut attempts: Vec<AttemptRecord> = Vec::new();
    let mut meta = None;
    let mut cal = None;
    let mut cals: Vec<CalFrame> = Vec::new();
    let mut active_cal_index: Option<usize> = None;
    let mut end = None;
    let mut panic = None;
    let mut tracker = CaseTracker::new();
    let mut attempt_saw_panic = false;

    let mut records = RecordMerger::default();

    for raw_line in text.lines() {
        let Some(frame) = parse_wire_line(raw_line)? else {
            continue;
        };
        match frame {
            WireFrame::Env(env) => {
                clock_regime = env.clock_regime;
                if env.max_harts.is_some() {
                    max_harts = env.max_harts;
                }
                if let Some(lbl) = &env.label
                    && !lbl.is_empty()
                {
                    label = lbl.clone();
                }
                env_hdr = Some(env);
            }
            WireFrame::Attempt(attempt) => {
                let unclosed = tracker.drain_all();
                records.synthesize_unclosed(&unclosed, shutdown_fail_reason(&attempt.shutdown));
                attempts.push(attempt);
                attempt_saw_panic = false;
            }
            WireFrame::RawAttemptStart(_) => {
                let unclosed = tracker.drain_all();
                let reason = if attempt_saw_panic {
                    "crash"
                } else {
                    "incomplete"
                };
                records.synthesize_unclosed(&unclosed, reason);
                active_cal_index = None;
                attempt_saw_panic = false;
            }
            WireFrame::Meta(m) => {
                meta = Some(m);
                active_cal_index = None;
            }
            WireFrame::Cal(c) => {
                let idx = cals.len();
                if cal.is_none() {
                    cal = Some(c.clone());
                }
                cals.push(c);
                active_cal_index = Some(idx);
            }
            WireFrame::Start(start) => {
                let _ = tracker.record_start(start);
            }
            WireFrame::Check(chk) => {
                let _ = tracker.close_check(&chk.id);
                records.insert_check(chk);
            }
            WireFrame::Bench(mut b) => {
                let _ = tracker.close_bench(&b.id, b.parallel);
                b.cal_index = active_cal_index;
                records.insert_bench(*b);
            }
            WireFrame::End(e) => {
                let unclosed = tracker.drain_all();
                records.synthesize_unclosed(&unclosed, "protocol_error");
                end = Some(e);
            }
            WireFrame::Panic(p) => {
                attempt_saw_panic = true;
                panic = Some(p);
            }
        }
    }

    let remaining = tracker.drain_all();
    let eof_reason = if attempt_saw_panic {
        "crash"
    } else {
        "incomplete"
    };
    records.synthesize_unclosed(&remaining, eof_reason);

    let (checks, benches) = records.finish();

    if meta.is_none()
        && checks.is_empty()
        && benches.is_empty()
        && panic.is_none()
        && attempts.is_empty()
    {
        return Err(format!("no @@MBENCH frames found in '{default_label}'"));
    }

    Ok(ParsedCapture {
        label,
        env: env_hdr,
        clock_regime,
        max_harts,
        attempts,
        meta,
        cal,
        cals,
        checks,
        benches,
        end,
        panic,
    })
}
