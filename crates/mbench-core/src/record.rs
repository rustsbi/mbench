//! Domain records, SBI v3.0 capability masks, and shared run-state gating.

use bitflags::bitflags;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use crate::{
    config::{Profile, RunConfig, effective_max_harts},
    stats::{CounterStats, DerivedNsStats},
};

/// Minimal hart-count topology interface sufficient for functional conformance gating.
pub trait HartTopology {
    /// Returns the total number of hardware harts on the platform.
    fn total_harts(&self) -> usize;
}

/// All 16 standard extensions defined up to RISC-V SBI v3.0.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "std", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum SbiExtensionId {
    Base = 0,
    Time = 1,
    Spi = 2,
    Rfnc = 3,
    Hsm = 4,
    Srst = 5,
    Pmu = 6,
    Dbcn = 7,
    Susp = 8,
    Cppc = 9,
    Nacl = 10,
    Sta = 11,
    Sse = 12,
    Fwft = 13,
    Dbtr = 14,
    Mpxy = 15,
}

impl SbiExtensionId {
    /// Ordered list of all 16 standard SBI v3.0 extensions.
    pub const ALL: [Self; 16] = [
        Self::Base,
        Self::Time,
        Self::Spi,
        Self::Rfnc,
        Self::Hsm,
        Self::Srst,
        Self::Pmu,
        Self::Dbcn,
        Self::Susp,
        Self::Cppc,
        Self::Nacl,
        Self::Sta,
        Self::Sse,
        Self::Fwft,
        Self::Dbtr,
        Self::Mpxy,
    ];

    /// Returns the official SBI Extension ID (EID).
    pub const fn eid(self) -> usize {
        match self {
            Self::Base => 0x0000_0010,
            Self::Time => 0x5449_4D45,
            Self::Spi => 0x0073_5049,
            Self::Rfnc => 0x5246_4E43,
            Self::Hsm => 0x0048_534D,
            Self::Srst => 0x5352_5354,
            Self::Pmu => 0x0050_4D55,
            Self::Dbcn => 0x4442_434E,
            Self::Susp => 0x5355_5350,
            Self::Cppc => 0x4350_5043,
            Self::Nacl => 0x4E41_434C,
            Self::Sta => 0x0053_5441,
            Self::Sse => 0x0053_5345,
            Self::Fwft => 0x4657_4654,
            Self::Dbtr => 0x4442_5452,
            Self::Mpxy => 0x4D50_5859,
        }
    }

    /// Returns the short canonical specification name.
    pub const fn name(self) -> &'static str {
        match self {
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
        }
    }

    /// Parses a short canonical extension name (case-insensitive).
    pub fn from_name(raw: &str) -> Option<Self> {
        let lower = raw.trim();
        Self::ALL
            .into_iter()
            .find(|ext| ext.name().eq_ignore_ascii_case(lower))
    }

    /// Converts this extension to its bit position in [`SbiCapMask`].
    pub const fn as_flag(self) -> SbiCapMask {
        SbiCapMask::from_bits_retain(1u32 << (self as u8))
    }
}

bitflags! {
    /// Probed SBI v3.0 extension availability bitmap.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct SbiCapMask: u32 {
        const BASE = 1 << 0;
        const TIME = 1 << 1;
        const SPI  = 1 << 2;
        const RFNC = 1 << 3;
        const HSM  = 1 << 4;
        const SRST = 1 << 5;
        const PMU  = 1 << 6;
        const DBCN = 1 << 7;
        const SUSP = 1 << 8;
        const CPPC = 1 << 9;
        const NACL = 1 << 10;
        const STA  = 1 << 11;
        const SSE  = 1 << 12;
        const FWFT = 1 << 13;
        const DBTR = 1 << 14;
        const MPXY = 1 << 15;
    }
}

impl SbiCapMask {
    /// Returns `true` if `ext` is marked available in this capability mask.
    pub const fn contains_ext(self, ext: SbiExtensionId) -> bool {
        self.contains(ext.as_flag())
    }

    /// Marks `ext` as available in this capability mask.
    pub fn set_ext(&mut self, ext: SbiExtensionId) {
        self.insert(ext.as_flag());
    }
}

/// Hardware counter accessibility probed safely in S-mode at boot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CounterAvailability {
    pub has_cycle: bool,
    pub has_instret: bool,
    pub has_time: bool,
    pub is_rdtime_emulated: bool,
    pub is_pmu_gated: bool,
}

impl CounterAvailability {
    /// Returns `true` if at least one performance or time counter is readable in S-mode.
    pub const fn has_any(self) -> bool {
        self.has_cycle || self.has_instret || self.has_time
    }
}

/// Platform and SBI firmware metadata emitted once after boot probing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetaRecord<'a> {
    pub sbi_spec_version: usize,
    pub impl_id: usize,
    pub impl_version: usize,
    pub mvendorid: usize,
    pub marchid: usize,
    pub mimpid: usize,
    pub extensions: SbiCapMask,
    pub hart_count: usize,
    pub boot_hart_id: usize,
    pub timebase_hz: u64,
    pub counters: CounterAvailability,
    pub has_sstc: bool,
    pub has_h_ext: bool,
    pub boot_ticks: u64,
    pub reserved_mem_bytes: u64,
    pub console_backend: &'a str,
    pub pmu_counter_count: usize,
    pub load_addr: usize,
}

/// Baseline calibration data emitted once before performance benchmark suites begin.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CalibrationRecord {
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
    Baseline,
    TrapEmul,
    Base,
    Time,
    Spi,
    Rfnc,
    Hsm,
    Srst,
    Pmu,
    Dbcn,
    Susp,
    Cppc,
    Nacl,
    Sta,
    Sse,
    Fwft,
    Dbtr,
    Mpxy,
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
    Batched,
    #[cfg_attr(feature = "std", serde(rename = "batched_preamble"))]
    BatchedWithPreamble,
    PairedEvent,
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
    ExtensionUnsupported,
    FunctionUnsupported,
    SingleHartOnly,
    RequiresIoFlag,
    RequiresDestructiveFlag,
    FeatureLocked,
    CounterUnavailable,
    NoUsableResource,
    WakeSourceUnavailable,
    ResumedPast,
    FilteredOut,
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
    pub required_ext: Option<SbiExtensionId>,
    pub min_harts: usize,
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

    /// Returns `true` when this issue annotates a known firmware quirk.
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
    pub label: &'static str,
    pub class: IssueClass,
    pub reason: FailReason,
}

/// Fixed-capacity zero-heap collection of [`CheckIssue`] entries attached to a [`CheckResult`].
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

    /// Iterates over stored entries in insertion order.
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

/// Structured reason why a check or benchmark case failed verification or execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailReason {
    UnexpectedSbiError(isize),
    UnexpectedTrap(usize),
    VerificationMismatch,
    Timeout,
    SecondaryHartError(isize),
    HardwareInconsistent,
    AbiRegClobbered,
    SecurityViolation(&'static str),
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
    HwNative,
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

/// Result record for one functional conformance check suite (`@@MBENCH:CHECK`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckResult<'a> {
    pub id: &'a str,
    pub checks: u64,
    pub checks_total: u64,
    pub checks_failed: u64,
    pub status: CheckStatus,
    pub issues: CheckIssues,
    pub quirks: u8,
    pub note: Option<&'a str>,
}

/// Result record for one performance benchmark invocation (`@@MBENCH:BENCH`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BenchResult<'a> {
    pub id: &'a str,
    pub group: BenchGroup,
    pub mode: Option<MeasureMode>,
    pub parallel: usize,
    pub unit: &'a str,
    pub iters_per_trial: u64,
    pub trials: usize,
    pub status: BenchStatus,
    pub cycles: Option<CounterStats>,
    pub instret: Option<CounterStats>,
    pub ticks: Option<CounterStats>,
    pub ns: Option<DerivedNsStats>,
    pub throughput_ops_per_sec: Option<u64>,
    pub note: Option<&'a str>,
}

/// Final summary record emitted after all requested checks and benchmarks complete.
///
/// Note: `checks_total`, `checks_passed`, `checks_skipped`, and `checks_failed` count
/// top-level [`CheckCase`] invocations, whereas `check_assertions_*` aggregate sub-assertions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
pub struct EndRecord {
    pub checks_total: usize,
    pub checks_passed: usize,
    pub checks_skipped: usize,
    pub checks_failed: usize,
    #[cfg_attr(feature = "std", serde(default))]
    pub check_assertions_total: u64,
    #[cfg_attr(feature = "std", serde(default))]
    pub check_assertions_passed: u64,
    #[cfg_attr(feature = "std", serde(default))]
    pub check_assertions_failed: u64,
    pub benches_total: usize,
    pub benches_passed: usize,
    pub benches_skipped: usize,
    pub benches_hw_native: usize,
    pub benches_delegated: usize,
    pub benches_failed: usize,
    pub quarantine_warnings: usize,
}

/// Shared execution progress across functional checks and performance benchmarks.
#[derive(Debug)]
pub struct RunState<'a> {
    pub config: RunConfig<'a>,
    pub caps: SbiCapMask,
    pub cal: Option<CalibrationRecord>,
    pub passed_resume_point: bool,
    pub summary: EndRecord,
}

impl<'a> RunState<'a> {
    /// Initializes run progress with parsed configuration and probed firmware capabilities.
    pub fn new(config: RunConfig<'a>, caps: SbiCapMask) -> Self {
        let passed_resume_point = config.resume_after.is_none();
        Self {
            config,
            caps,
            cal: None,
            passed_resume_point,
            summary: EndRecord::default(),
        }
    }

    /// Stores calibration results once Phase 1 calibration finishes.
    pub fn set_calibration(&mut self, cal: CalibrationRecord) {
        self.cal = Some(cal);
    }

    /// Returns stored calibration or default zeroed constants.
    pub fn calibration(&self) -> CalibrationRecord {
        self.cal.unwrap_or_default()
    }

    /// Evaluates shared `resume_after`, `filter`, `required_ext`, `min_harts`, and flag pre-gates.
    pub fn check_common_gates(
        &mut self,
        id: &str,
        gate: CaseGate,
        total_harts: usize,
    ) -> Option<SkipReason> {
        if !self.passed_resume_point {
            if self.config.resume_after == Some(id) {
                self.passed_resume_point = true;
            }
            return Some(SkipReason::ResumedPast);
        }
        if let Some(filter) = self.config.filter
            && !id.contains(filter)
        {
            return Some(SkipReason::FilteredOut);
        }
        if let Some(ext) = gate.required_ext
            && !self.caps.contains_ext(ext)
        {
            return Some(SkipReason::ExtensionUnsupported);
        }
        let effective_harts = effective_max_harts(total_harts, self.config.max_harts);
        if effective_harts < gate.min_harts {
            return Some(SkipReason::SingleHartOnly);
        }
        if gate.flags.contains(CaseFlags::IO_BOUND) && !self.config.allow_io {
            return Some(SkipReason::RequiresIoFlag);
        }
        if gate.flags.contains(CaseFlags::DESTRUCTIVE) && !self.config.allow_destructive {
            return Some(SkipReason::RequiresDestructiveFlag);
        }
        None
    }
}
