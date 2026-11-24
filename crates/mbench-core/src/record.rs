//! Firmware capabilities, result records, and shared run-state gating.

use bitflags::bitflags;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use crate::{
    config::{Profile, RunConfig, effective_max_harts},
    stats::{CounterStats, DerivedNsStats},
};

mod case;
pub use case::{
    BenchGroup, BenchStatus, CaseFlags, CaseGate, CheckIssue, CheckIssues, CheckStatus, FailReason,
    IssueClass, MAX_CHECK_ISSUES, MeasureMode, SkipReason, StartKind,
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
    /// Base discovery extension.
    Base = 0,
    /// Timer extension.
    Time = 1,
    /// Interprocessor interrupt extension.
    Spi = 2,
    /// Remote fence extension.
    Rfnc = 3,
    /// Hart state management extension.
    Hsm = 4,
    /// System reset extension.
    Srst = 5,
    /// Performance monitoring extension.
    Pmu = 6,
    /// Debug console extension.
    Dbcn = 7,
    /// System suspend extension.
    Susp = 8,
    /// Collaborative processor performance control extension.
    Cppc = 9,
    /// Nested acceleration extension.
    Nacl = 10,
    /// Steal-time accounting extension.
    Sta = 11,
    /// Supervisor software events extension.
    Sse = 12,
    /// Firmware feature configuration extension.
    Fwft = 13,
    /// Debug triggers extension.
    Dbtr = 14,
    /// Message proxy extension.
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

    /// Converts this extension to its bit position in [`SbiCapMask`].
    pub const fn as_flag(self) -> SbiCapMask {
        SbiCapMask::from_bits_retain(1u32 << (self as u8))
    }
}

bitflags! {
    /// Availability bitmap corresponding to [`SbiExtensionId`].
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
    /// Platform timer frequency in ticks per second.
    pub timebase_hz: u64,
    /// Counter accessibility and timing characteristics probed at boot.
    pub counters: CounterAvailability,
    pub has_sstc: bool,
    pub has_h_ext: bool,
    /// Timer value sampled during startup.
    pub boot_ticks: u64,
    /// Size in bytes of firmware-reserved memory discovered at boot.
    pub reserved_mem_bytes: u64,
    pub console_backend: &'a str,
    pub pmu_counter_count: usize,
    pub load_addr: usize,
    pub config: RunConfig<'a>,
}

/// Baseline calibration data emitted once before performance benchmark suites begin.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CalibrationRecord {
    pub profile: Profile,
    /// Number of outer measurement trials.
    pub trials: usize,
    /// Calibrated empty-loop iteration count meeting the target measurement window.
    pub enough_iters: u64,
    /// Empty-loop overhead per iteration in cycles multiplied by 100.
    pub loop_overhead_cycles_x100: u64,
    /// Empty-loop overhead per iteration in retired instructions multiplied by 100.
    pub loop_overhead_instret_x100: u64,
    /// Empty-loop overhead per iteration in timer ticks multiplied by 100.
    pub loop_overhead_ticks_x100: u64,
    /// Counter sampling overhead per measurement window in cycles multiplied by 100.
    pub timer_overhead_cycles_x100: u64,
    /// Counter sampling overhead per measurement window in retired instructions multiplied by 100.
    pub timer_overhead_instret_x100: u64,
    /// Counter sampling overhead per measurement window in timer ticks multiplied by 100.
    pub timer_overhead_ticks_x100: u64,
    /// Estimated cost of one time-counter read in cycles multiplied by 100.
    pub rdtime_read_cycles_x100: u64,
    pub is_rdtime_emulated: bool,
}
/// Result record for one functional conformance check suite (`@@MBENCH:CHECK`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckResult<'a> {
    pub id: &'a str,
    /// Number of passed assertions in this check.
    pub checks: u64,
    /// Number of assertions evaluated in this check, including failures.
    pub checks_total: u64,
    pub checks_failed: u64,
    pub status: CheckStatus,
    /// Retained assertion failures and observations.
    pub issues: CheckIssues,
    /// Number of retained failures annotated with known firmware quirks.
    pub quirks: u8,
    pub note: Option<&'a str>,
}

/// Result record for one performance benchmark invocation (`@@MBENCH:BENCH`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BenchResult<'a> {
    pub id: &'a str,
    pub group: BenchGroup,
    /// Measurement primitive used, absent for unmeasured outcomes.
    pub mode: Option<MeasureMode>,
    /// Number of participating harts for this result.
    pub parallel: usize,
    pub unit: &'a str,
    /// Per-trial operation divisor or paired sample count reported by the measurement mode.
    pub iters_per_trial: u64,
    /// Number of outer measurement trials.
    pub trials: usize,
    pub status: BenchStatus,
    pub cycles: Option<CounterStats>,
    pub instret: Option<CounterStats>,
    pub ticks: Option<CounterStats>,
    /// Optional nanosecond statistics derived from the timer-tick samples.
    pub ns: Option<DerivedNsStats>,
    /// Optional aggregate throughput in operations per second.
    pub throughput_ops_per_sec: Option<u64>,
    pub note: Option<&'a str>,
}

/// Final summary record emitted after all requested checks and benchmarks complete.
///
/// Note: `checks_total`, `checks_passed`, `checks_skipped`, and `checks_failed` count
/// top-level [`crate::check::CheckCase`] invocations, whereas `check_assertions_*` aggregate sub-assertions.
/// Benchmark counts include each parallel sweep point.
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
    /// Number of warnings reported by resource cleanup between cases.
    pub quarantine_warnings: usize,
}

/// Shared execution progress across functional checks and performance benchmarks.
#[derive(Debug)]
pub struct RunState<'a> {
    pub config: RunConfig<'a>,
    pub caps: SbiCapMask,
    /// Most recent calibration, or none before calibration.
    pub cal: Option<CalibrationRecord>,
    /// Whether the inclusive resume point has already been skipped.
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
