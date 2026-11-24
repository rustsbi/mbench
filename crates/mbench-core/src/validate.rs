//! Protocol integrity auditing and structured capture reports.

use serde::{Deserialize, Serialize};

use crate::{
    capture::RecordMerger,
    record::{BenchGroup, EndRecord, SkipReason},
    wire::{
        AttemptRecord, BenchFrame, BenchStatusTag, CheckFrame, CheckStatusTag, EndFrame, EnvLine,
        MetaFrame, PanicFrame,
    },
};

mod stream;
pub use stream::audit_raw_attempt;
use stream::{audit_merged_jsonl, audit_multi_attempt_raw, audit_single_attempt_raw};

pub use crate::capture::CaseTracker;

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

const fn is_false(value: &bool) -> bool {
    !*value
}
/// Source format detected for an audited capture.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureFormat {
    /// Single- or multiple-attempt raw serial log.
    RawSerial,
    /// Host-merged JSONL capture.
    MergedJsonl,
}

/// Counts recomputed from parsed records, following [`EndRecord`] plus `benches_effective`.
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
    /// Sum of measured, hardware-native, and S-mode-delegated benchmark results.
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

/// [`CheckFrame`] summary exposed inside [`CaptureReport`], omitting individual issues and notes.
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

/// [`BenchFrame`] summary exposed inside [`CaptureReport`], omitting measurements and notes.
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
    /// Source path or capture label reported to the caller.
    pub source: String,
    /// Detected capture input format.
    pub format: CaptureFormat,
    /// Whether auditing found no protocol integrity errors.
    pub protocol_valid: bool,
    /// Whether the applicable final-attempt completion conditions were met.
    pub completed: bool,
    /// Whether the capture contains multiple attempts or synthesized recovery records.
    pub recovered: bool,
    /// Protocol integrity diagnostics retained in encounter order.
    pub protocol_errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Latest retained environment header, if present.
    pub env: Option<EnvLine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Latest retained target metadata, if present.
    pub meta: Option<MetaFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Latest retained panic, including a panic from an earlier recovered attempt.
    pub panic: Option<PanicFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Final retained END record, absent if the final raw attempt lacks END.
    pub end: Option<EndFrame>,
    /// Counts recomputed from merged check and benchmark results.
    pub counts: CaptureCounts,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// Attempt footer records in encounter order.
    pub attempts: Vec<AttemptRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// Merged check summaries in first-seen identifier order.
    pub checks: Vec<CheckSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// Merged benchmark summaries in first-seen key order.
    pub benches: Vec<BenchSummary>,
}

struct AuditReport {
    source: String,
    format: CaptureFormat,
    errors: Vec<String>,
    env: Option<EnvLine>,
    meta: Option<MetaFrame>,
    panic: Option<PanicFrame>,
    end: Option<EndFrame>,
    attempts: Vec<AttemptRecord>,
    records: RecordMerger,
    quarantine: usize,
}

impl AuditReport {
    fn new(source: String, format: CaptureFormat) -> Self {
        Self {
            source,
            format,
            errors: Vec::new(),
            env: None,
            meta: None,
            panic: None,
            end: None,
            attempts: Vec::new(),
            records: RecordMerger::default(),
            quarantine: 0,
        }
    }

    fn finish(self, completed: bool, recovered: bool) -> CaptureReport {
        let Self {
            source,
            format,
            errors: protocol_errors,
            env,
            meta,
            panic,
            end,
            attempts,
            records,
            quarantine,
        } = self;
        let (checks, benches) = records.finish();
        let counts = CaptureCounts::from_end(&summarize_records(&checks, &benches, quarantine));
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
fn compare_end_counts(
    context: &str,
    computed: &EndRecord,
    recorded: &EndRecord,
    errors: &mut Vec<String>,
) {
    macro_rules! compare {
        ($($field:ident),+ $(,)?) => {
            $(if computed.$field != recorded.$field {
                errors.push(format!(
                    "{context}: END {}={} does not match emitted records ({})",
                    stringify!($field), recorded.$field, computed.$field
                ));
            })+
        };
    }
    compare!(
        checks_total,
        checks_passed,
        checks_skipped,
        checks_failed,
        check_assertions_total,
        check_assertions_passed,
        check_assertions_failed,
        benches_total,
        benches_passed,
        benches_skipped,
        benches_hw_native,
        benches_delegated,
        benches_failed,
    );
}

#[cfg(test)]
mod tests;
