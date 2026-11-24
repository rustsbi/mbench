use bitflags::bitflags;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use super::SbiExtensionId;

/// Kind of case announced in an `@@MBENCH:START` frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "std", serde(rename_all = "snake_case"))]
pub enum StartKind {
    Check,
    Bench,
}

impl StartKind {
    /// Returns the lowercase wire tag of this case kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Bench => "bench",
        }
    }
}

/// Logical suite group for a performance benchmark case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "std", serde(rename_all = "snake_case"))]
pub enum BenchGroup {
    /// Baseline instruction and loop costs.
    Baseline,
    /// Trap and instruction emulation costs.
    TrapEmul,
    /// Base discovery benchmarks.
    Base,
    /// Timer benchmarks.
    Time,
    /// Interprocessor interrupt benchmarks.
    Spi,
    /// Remote fence benchmarks.
    Rfnc,
    /// Hart state management benchmarks.
    Hsm,
    /// System reset benchmarks.
    Srst,
    /// Performance monitoring benchmarks.
    Pmu,
    /// Debug console benchmarks.
    Dbcn,
    /// System suspend benchmarks.
    Susp,
    /// Collaborative processor performance control benchmarks.
    Cppc,
    /// Nested acceleration benchmarks.
    Nacl,
    /// Steal-time accounting benchmarks.
    Sta,
    /// Supervisor software events benchmarks.
    Sse,
    /// Firmware feature configuration benchmarks.
    Fwft,
    /// Debug triggers benchmarks.
    Dbtr,
    /// Message proxy benchmarks.
    Mpxy,
    /// Multi-hart scaling measurements.
    Scale,
}

impl BenchGroup {
    /// Returns the lowercase wire name of this group.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::TrapEmul => "trap_emul",
            Self::Base => "base",
            Self::Time => "time",
            Self::Spi => "spi",
            Self::Rfnc => "rfnc",
            Self::Hsm => "hsm",
            Self::Srst => "srst",
            Self::Pmu => "pmu",
            Self::Dbcn => "dbcn",
            Self::Susp => "susp",
            Self::Cppc => "cppc",
            Self::Nacl => "nacl",
            Self::Sta => "sta",
            Self::Sse => "sse",
            Self::Fwft => "fwft",
            Self::Dbtr => "dbtr",
            Self::Mpxy => "mpxy",
            Self::Scale => "scale",
        }
    }
}

/// Measurement primitive actually executed to produce a performance benchmark result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "std", serde(rename_all = "snake_case"))]
pub enum MeasureMode {
    /// Timed batches with calibrated sampling and loop overhead subtraction.
    Batched,
    #[cfg_attr(feature = "std", serde(rename = "batched_preamble"))]
    /// Timed batches with an explicit measured preamble subtracted.
    BatchedWithPreamble,
    /// Causal event deltas summarized within and across trials.
    PairedEvent,
    /// Batched measurements across increasing hart counts.
    ParallelSweep,
}

impl MeasureMode {
    /// Returns the lowercase wire name of this mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Batched => "batched",
            Self::BatchedWithPreamble => "batched_preamble",
            Self::PairedEvent => "paired_event",
            Self::ParallelSweep => "parallel_sweep",
        }
    }
}

/// Structured reason why a check or benchmark case was skipped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "std", serde(rename_all = "snake_case"))]
pub enum SkipReason {
    /// The required SBI extension is unavailable.
    ExtensionUnsupported,
    /// The optional SBI function is unavailable.
    FunctionUnsupported,
    /// The effective hart count is below the case requirement.
    SingleHartOnly,
    /// The case requires explicit I/O permission.
    RequiresIoFlag,
    /// The case requires explicit destructive-operation permission.
    RequiresDestructiveFlag,
    /// Firmware policy prevents changing the required feature.
    FeatureLocked,
    /// A required performance or timer counter is unavailable.
    CounterUnavailable,
    /// No suitable resource is available for this case.
    NoUsableResource,
    /// The platform cannot arm a suitable suspend wake source.
    WakeSourceUnavailable,
    /// The case precedes or matches the inclusive resume point.
    ResumedPast,
    /// The case identifier does not match the configured filter.
    FilteredOut,
    /// The required shared memory exceeds local pool capacity.
    ShmemTooLarge,
}

impl SkipReason {
    /// Returns a stable machine-readable reason code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExtensionUnsupported => "extension_unsupported",
            Self::FunctionUnsupported => "function_unsupported",
            Self::SingleHartOnly => "single_hart_only",
            Self::RequiresIoFlag => "requires_io_flag",
            Self::RequiresDestructiveFlag => "requires_destructive_flag",
            Self::FeatureLocked => "feature_locked",
            Self::CounterUnavailable => "counter_unavailable",
            Self::NoUsableResource => "no_usable_resource",
            Self::WakeSourceUnavailable => "wake_source_unavailable",
            Self::ResumedPast => "resumed_past",
            Self::FilteredOut => "filtered_out",
            Self::ShmemTooLarge => "shmem_too_large",
        }
    }
}

bitflags! {
    /// Capability and safety flags attached to a conformance check or benchmark case.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct CaseFlags: u32 {
        /// Case performs visible serial/console I/O and requires `io=1`.
        const IO_BOUND = 1 << 0;
        /// Case triggers destructive or suspend platform state and requires `destructive=1`.
        const DESTRUCTIVE = 1 << 1;
    }
}

/// Shared execution gating criteria used by both conformance checks and benchmarks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaseGate {
    /// SBI extension required to execute the case, if any.
    pub required_ext: Option<SbiExtensionId>,
    /// Minimum hart count after applying the configured limit.
    pub min_harts: usize,
    /// Execution permissions required by the case.
    pub flags: CaseFlags,
}

impl CaseGate {
    /// Creates a gate requiring `required_ext`, `min_harts`, and `flags`.
    pub const fn new(
        required_ext: Option<SbiExtensionId>,
        min_harts: usize,
        flags: CaseFlags,
    ) -> Self {
        Self {
            required_ext,
            min_harts,
            flags,
        }
    }
}

/// Structured reason why a check or benchmark case failed verification or execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailReason {
    /// An SBI call returned the enclosed unexpected error code.
    UnexpectedSbiError(isize),
    /// Execution raised the enclosed unexpected trap cause.
    UnexpectedTrap(usize),
    /// Observed data did not match the expected result.
    VerificationMismatch,
    /// The operation did not complete within its deadline.
    Timeout,
    /// A secondary hart reported the enclosed error bits or code.
    SecondaryHartError(isize),
    /// Observed hardware or firmware state was inconsistent.
    HardwareInconsistent,
    /// An ABI-preserved register was unexpectedly modified.
    AbiRegClobbered,
    /// The named security boundary was violated.
    SecurityViolation(&'static str),
    /// The named assertion failed.
    AssertionFailed(&'static str),
}

/// Final classification of a functional conformance check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckStatus {
    Pass,
    Skipped(SkipReason),
    Failed(FailReason),
}

impl CheckStatus {
    /// Returns the uppercase status label emitted in wire and progress records.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Skipped(_) => "SKIPPED",
            Self::Failed(_) => "FAIL",
        }
    }
}

/// Final classification of an executed performance benchmark invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchStatus {
    Pass,
    Skipped(SkipReason),
    /// The operation executed natively without M-mode trapping.
    HwNative,
    /// The operation trapped to S-mode.
    DelegatedToS,
    Failed(FailReason),
}

impl BenchStatus {
    /// Returns the uppercase status label emitted in wire and progress records.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Skipped(_) => "SKIPPED",
            Self::HwNative => "HW_NATIVE",
            Self::DelegatedToS => "DELEGATED_TO_S",
            Self::Failed(_) => "FAIL",
        }
    }
}

/// Maximum number of per-case issues/observations retained in fixed-capacity zero-heap storage.
pub const MAX_CHECK_ISSUES: usize = 8;

/// Classification distinguishing normative SBI violations from permitted behaviors and quirks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueClass {
    /// Mandatory SBI specification requirement violated; fails the check.
    SpecViolation,
    /// Mandatory SBI requirement violated due to a known firmware quirk; still fails the check.
    SpecViolationWithQuirk(&'static str),
    /// Behavior permitted by the SBI specification (e.g., optional `SBI_ERR_FAILED`); observation only.
    PermittedBehavior,
    /// Sub-check could not run because platform contract lacks an optional input; observation only.
    Unsupported,
}

impl IssueClass {
    /// Returns `true` when this issue represents a normative specification failure.
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::SpecViolation | Self::SpecViolationWithQuirk(_))
    }

    /// Returns the known firmware quirk identifier, if this issue carries one.
    pub const fn quirk(self) -> Option<&'static str> {
        match self {
            Self::SpecViolationWithQuirk(q) => Some(q),
            Self::SpecViolation | Self::PermittedBehavior | Self::Unsupported => None,
        }
    }

    /// Returns the lowercase wire tag of this issue class.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpecViolation => "spec_violation",
            Self::SpecViolationWithQuirk(_) => "spec_violation_with_quirk",
            Self::PermittedBehavior => "permitted_behavior",
            Self::Unsupported => "unsupported",
        }
    }
}

/// One structured assertion failure or non-fatal observation recorded inside a conformance case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckIssue {
    /// Stable identifier of the assertion or observation.
    pub label: &'static str,
    /// Classification distinguishing violations from permitted observations.
    pub class: IssueClass,
    /// Structured failure or observation reason.
    pub reason: FailReason,
}

/// Fixed-capacity zero-heap collection of [`CheckIssue`] entries attached to a [`super::CheckResult`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckIssues {
    entries: [Option<CheckIssue>; MAX_CHECK_ISSUES],
    len: u8,
    truncated: bool,
}

impl Default for CheckIssues {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckIssues {
    /// Creates an empty fixed-capacity issue buffer.
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_CHECK_ISSUES],
            len: 0,
            truncated: false,
        }
    }

    /// Appends `issue`, prioritizing normative failures over informational observations if full.
    pub fn push(&mut self, issue: CheckIssue) {
        let idx = self.len as usize;
        if idx < MAX_CHECK_ISSUES {
            self.entries[idx] = Some(issue);
            self.len += 1;
            return;
        }
        if issue.class.is_failure()
            && let Some(slot) = self
                .entries
                .iter_mut()
                .find(|e| e.is_some_and(|existing| !existing.class.is_failure()))
        {
            *slot = Some(issue);
        }
        self.truncated = true;
    }

    /// Returns the number of stored entries.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` when zero entries are stored.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` when more than [`MAX_CHECK_ISSUES`] issues occurred.
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Iterates in storage-slot order; a failure can replace an earlier observation when full.
    pub fn iter(&self) -> impl Iterator<Item = CheckIssue> + '_ {
        self.entries[..self.len()].iter().flatten().copied()
    }

    /// Returns `true` if any stored entry represents a normative failure.
    pub fn has_failure(&self) -> bool {
        self.iter().any(|issue| issue.class.is_failure())
    }

    /// Returns the first stored normative failure, if any.
    pub fn first_failure(&self) -> Option<CheckIssue> {
        self.iter().find(|issue| issue.class.is_failure())
    }

    /// Counts stored entries annotated with a firmware quirk.
    pub fn quirk_count(&self) -> u8 {
        self.iter()
            .filter(|issue| issue.class.quirk().is_some())
            .count() as u8
    }
}
