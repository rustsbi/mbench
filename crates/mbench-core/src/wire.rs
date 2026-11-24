//! Host-side wire records and capture decoding.

use serde::{Deserialize, Serialize};

use crate::{
    config::{ClockRegime, OrderMode, Profile, RunMode},
    record::{BenchGroup, EndRecord, MeasureMode, SbiExtensionId, SkipReason, StartKind},
};

mod decode;
pub use decode::{parse_capture, parse_wire_line};

pub use crate::capture::{
    infer_bench_group, shutdown_fail_reason, synthesize_fail_bench, synthesize_fail_check,
};

const fn is_false(value: &bool) -> bool {
    !*value
}

/// Environment metadata header recorded at the top of saved `.jsonl` captures.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnvLine {
    /// Timing regime under which this capture was collected.
    pub clock_regime: ClockRegime,
    /// Optional human-readable name assigned to the capture.
    pub label: Option<String>,
    /// Optional hart count requested for the target process.
    pub smp: Option<usize>,
    /// Whether QEMU instruction-count timing was requested, if recorded.
    pub icount: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<RunMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<OrderMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional seed for deterministic benchmark ordering.
    pub seed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional ceiling on the hart count used for execution.
    pub max_harts: Option<usize>,
}

/// Owned runtime configuration; field semantics follow [`crate::config::RunConfig`].
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EffectiveConfigFrame {
    pub mode: RunMode,
    pub profile: Profile,
    pub order: OrderMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_after: Option<String>,
    #[serde(default)]
    pub allow_io: bool,
    #[serde(default)]
    pub allow_destructive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_harts: Option<usize>,
}

/// Deserialized `@@MBENCH:META`; field semantics follow [`crate::record::MetaRecord`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetaFrame {
    pub sbi_spec_version: usize,
    pub impl_id: usize,
    pub impl_version: usize,
    pub mvendorid: usize,
    pub marchid: usize,
    pub mimpid: usize,
    pub extensions: Vec<SbiExtensionId>,
    pub extensions_mask: u32,
    pub hart_count: usize,
    pub boot_hart_id: usize,
    pub timebase_hz: u64,
    pub has_cycle: bool,
    pub has_instret: bool,
    pub has_time: bool,
    pub is_rdtime_emulated: bool,
    pub is_pmu_gated: bool,
    pub has_sstc: bool,
    pub has_h_ext: bool,
    pub boot_ticks: u64,
    pub reserved_mem_bytes: u64,
    pub console_backend: String,
    pub pmu_counter_count: usize,
    pub load_addr: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<EffectiveConfigFrame>,
}

/// Deserialized `@@MBENCH:CAL`; field semantics follow [`crate::record::CalibrationRecord`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CalFrame {
    pub profile: Profile,
    pub trials: usize,
    pub enough_iters: u64,
    pub loop_overhead_cycles_x100: u64,
    pub loop_overhead_instret_x100: u64,
    pub loop_overhead_ticks_x100: u64,
    pub timer_overhead_cycles_x100: u64,
    pub timer_overhead_instret_x100: u64,
    pub timer_overhead_ticks_x100: u64,
    pub rdtime_read_cycles_x100: u64,
    pub is_rdtime_emulated: bool,
}

/// Deserialized `@@MBENCH:START` payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StartFrame {
    /// Whether the announced case is a check or a benchmark.
    pub kind: StartKind,
    pub id: String,
    /// Number of participating harts for this result.
    pub parallel: usize,
}

/// Wire status tag for an `@@MBENCH:CHECK` frame.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CheckStatusTag {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "SKIPPED")]
    Skipped,
    #[serde(rename = "FAIL")]
    Fail,
}

/// Wire status tag for an `@@MBENCH:BENCH` frame.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BenchStatusTag {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "SKIPPED")]
    Skipped,
    #[serde(rename = "HW_NATIVE")]
    /// Hardware-native operation.
    HwNative,
    #[serde(rename = "DELEGATED_TO_S")]
    /// Operation delegated to S-mode.
    DelegatedToS,
    #[serde(rename = "FAIL")]
    Fail,
}

/// Owned [`crate::stats::CounterStats`] with dynamically sized chronological samples.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CounterStatsFrame {
    pub min_x100: u64,
    pub p25_x100: u64,
    pub median_x100: u64,
    pub p75_x100: u64,
    pub p95_x100: u64,
    pub max_x100: u64,
    pub iqr_x100: u64,
    pub raw_batch_median: u64,
    pub is_noisy: bool,
    pub raw_batch_totals: Vec<u64>,
    pub net_samples_x100: Vec<u64>,
}

/// Owned [`crate::stats::DerivedNsStats`], without tick-unit raw fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DerivedNsStatsFrame {
    pub min_x100: u64,
    pub p25_x100: u64,
    pub median_x100: u64,
    pub p75_x100: u64,
    pub p95_x100: u64,
    pub max_x100: u64,
    pub iqr_x100: u64,
    pub is_noisy: bool,
    pub net_samples_x100: Vec<u64>,
}

/// Wire classification for a single conformance issue or observation inside [`CheckFrame`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckIssueClass {
    /// Normative specification violation.
    SpecViolation,
    /// Normative violation associated with a known firmware quirk.
    SpecViolationWithQuirk,
    /// Specification-permitted behavior recorded as an observation.
    PermittedBehavior,
    /// Optional prerequisite unavailable; observation only.
    Unsupported,
}

impl CheckIssueClass {
    /// Returns `true` if this issue represents a specification violation.
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::SpecViolation | Self::SpecViolationWithQuirk)
    }
}

/// Wire entry describing one failed assertion or notable observation inside a [`CheckFrame`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckIssueFrame {
    /// Stable identifier of the assertion or observation.
    pub label: String,
    /// Classification distinguishing violations from permitted observations.
    pub class: CheckIssueClass,
    /// Serialized failure or observation reason.
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional identifier of a known firmware deviation; the associated violation still fails.
    pub quirk: Option<String>,
}

/// Deserialized `@@MBENCH:CHECK`; field semantics follow [`crate::record::CheckResult`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckFrame {
    pub id: String,
    pub checks: u64,
    #[serde(default)]
    pub checks_total: u64,
    #[serde(default)]
    pub checks_failed: u64,
    pub status: CheckStatusTag,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<SkipReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_reason: Option<String>,
    #[serde(default)]
    pub quirks: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<CheckIssueFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    /// Whether the host synthesized this record for a case that did not finish.
    pub synthetic: bool,
}

/// Deserialized `@@MBENCH:BENCH`; field semantics follow [`crate::record::BenchResult`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchFrame {
    pub id: String,
    pub group: BenchGroup,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<MeasureMode>,
    pub parallel: usize,
    pub unit: String,
    pub iters_per_trial: u64,
    pub trials: usize,
    pub status: BenchStatusTag,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<SkipReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cycles: Option<CounterStatsFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instret: Option<CounterStatsFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticks: Option<CounterStatsFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ns: Option<DerivedNsStatsFrame>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throughput_ops_per_sec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    /// Whether the host synthesized this record for a case that did not finish.
    pub synthetic: bool,
    /// Zero-based index into [`ParsedCapture::cals`] identifying the calibration active when emitted.
    #[serde(skip)]
    pub cal_index: Option<usize>,
}

/// Deserialized `@@MBENCH:END` payload.
pub type EndFrame = EndRecord;

/// Target process shutdown classification observed for one run attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShutdownStatus {
    /// The process exited successfully.
    CleanExit,
    /// The process exited with a nonzero status.
    NonZeroExit { code: i32 },
    /// The process terminated after a signal.
    Signaled,
    /// The user interrupted execution.
    Interrupted,
    /// The process timed out after emitting END.
    TimedOutAfterEnd,
    /// The host terminated the process after END.
    HostTerminatedAfterEnd,
    /// The process timed out before completion.
    TimedOutDuringRun,
    /// The host stopped execution after a target panic.
    AbortedOnPanic,
}

/// Explicit attempt boundary marker written into multi-attempt raw serial logs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawAttemptStart {
    /// Zero-based execution attempt index.
    pub attempt: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional case identifier through which execution is skipped, inclusively.
    pub resume_after: Option<String>,
}

/// Host-side audit record appended after each target execution attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttemptRecord {
    /// Zero-based execution attempt index.
    pub attempt: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional case identifier through which execution is skipped, inclusively.
    pub resume_after: Option<String>,
    /// Whether this attempt observed an END frame.
    pub saw_end: bool,
    /// Observed target-process termination classification.
    pub shutdown: ShutdownStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// Protocol integrity diagnostics retained in encounter order.
    pub protocol_errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// Identifiers of cases for which the host synthesized failure records.
    pub synthesized_failures: Vec<String>,
}

/// Deserialized `@@MBENCH:PANIC` payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PanicFrame {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub scause: Option<usize>,
    #[serde(default)]
    pub stval: Option<usize>,
    #[serde(default)]
    pub sepc: Option<usize>,
}

/// Parsed streaming frame yielded by [`parse_wire_line`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireFrame {
    Env(EnvLine),
    Attempt(AttemptRecord),
    RawAttemptStart(RawAttemptStart),
    Meta(MetaFrame),
    Cal(CalFrame),
    Start(StartFrame),
    Check(CheckFrame),
    Bench(Box<BenchFrame>),
    End(EndFrame),
    Panic(PanicFrame),
}

/// Parsed representation of one saved `.jsonl` or raw serial log capture.
#[derive(Clone, Debug)]
pub struct ParsedCapture {
    /// Capture label, falling back to the caller-provided name.
    pub label: String,
    /// Most recently parsed environment header, if present.
    pub env: Option<EnvLine>,
    /// Timing regime under which this capture was collected.
    pub clock_regime: ClockRegime,
    /// Optional ceiling on the hart count used for execution.
    pub max_harts: Option<usize>,
    /// Attempt footer records in encounter order.
    pub attempts: Vec<AttemptRecord>,
    /// Most recently parsed target metadata, if present.
    pub meta: Option<MetaFrame>,
    /// First calibration record in the capture, if present.
    pub cal: Option<CalFrame>,
    /// Calibration records in encounter order across attempts.
    pub cals: Vec<CalFrame>,
    /// Merged check results in first-seen identifier order.
    pub checks: Vec<CheckFrame>,
    /// Merged benchmark results in first-seen key order.
    pub benches: Vec<BenchFrame>,
    /// Retained END record, if present.
    pub end: Option<EndFrame>,
    /// Most recently parsed panic, if present.
    pub panic: Option<PanicFrame>,
}

#[cfg(test)]
mod tests;
