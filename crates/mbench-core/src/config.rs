//! Runtime execution mode, timing regime, profile, ordering, and bootargs configuration.

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

/// Top-level execution mode configured via `/chosen/bootargs` (`mode=...`) or CLI `--mode`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "std", serde(rename_all = "snake_case"))]
pub enum RunMode {
    #[default]
    All,
    Check,
    Bench,
}

impl RunMode {
    /// Parses a wire/bootarg mode name (`all`, `check`, `bench`).
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "all" => Some(Self::All),
            "check" => Some(Self::Check),
            "bench" => Some(Self::Bench),
            _ => None,
        }
    }

    /// Returns `true` if functional conformance checks should execute in this mode.
    pub const fn runs_checks(self) -> bool {
        matches!(self, Self::All | Self::Check)
    }

    /// Returns `true` if performance calibration and benchmarks should execute in this mode.
    pub const fn runs_benches(self) -> bool {
        matches!(self, Self::All | Self::Bench)
    }

    /// Returns the lowercase wire name of this mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Check => "check",
            Self::Bench => "bench",
        }
    }
}

/// Timing regime recorded with an archived capture.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "std", serde(rename_all = "kebab-case"))]
pub enum ClockRegime {
    #[default]
    Unknown,
    HwCycle,
    QemuIcount,
    QemuTcgNonCycleAccurate,
}

impl ClockRegime {
    /// Returns a human-readable summary label for reports.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::HwCycle => "hw-cycle",
            Self::QemuIcount => "qemu-icount (instret-exact)",
            Self::QemuTcgNonCycleAccurate => "qemu-tcg (non-cycle-accurate)",
        }
    }
}

/// Benchmark intensity profile configured via `/chosen/bootargs` or CLI.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "std", serde(rename_all = "snake_case"))]
pub enum Profile {
    Quick,
    #[default]
    Normal,
    Thorough,
}

impl Profile {
    /// Returns the number of outer trials executed per benchmark case.
    pub const fn trials(self) -> usize {
        match self {
            Self::Quick => 5,
            Self::Normal => 11,
            Self::Thorough => 21,
        }
    }

    /// Returns the number of causal delta samples collected per trial in `PairedEvent` mode.
    pub const fn paired_samples(self) -> usize {
        match self {
            Self::Quick => 8,
            Self::Normal => 32,
            Self::Thorough => 64,
        }
    }

    /// Returns the minimum target cycle window for adaptive batch sizing (`enough`).
    pub const fn min_batch_cycles(self) -> u64 {
        match self {
            Self::Quick => 4_000,
            Self::Normal => 25_000,
            Self::Thorough => 100_000,
        }
    }

    /// Returns the minimum target retired-instruction window when cycles are unavailable.
    pub const fn min_batch_instret(self) -> u64 {
        match self {
            Self::Quick => 2_000,
            Self::Normal => 12_000,
            Self::Thorough => 50_000,
        }
    }

    /// Returns the initial iteration count before adaptive doubling.
    pub const fn initial_batch_iters(self) -> u64 {
        match self {
            Self::Quick => 16,
            Self::Normal => 32,
            Self::Thorough => 64,
        }
    }

    /// Returns the maximum iteration cap per batched trial.
    pub const fn max_batch_iters(self) -> u64 {
        match self {
            Self::Quick => 4_096,
            Self::Normal => 32_768,
            Self::Thorough => 131_072,
        }
    }

    /// Returns the number of unmeasured warmup iterations executed before trials.
    pub const fn warmup_iters(self) -> u64 {
        match self {
            Self::Quick => 8,
            Self::Normal => 32,
            Self::Thorough => 64,
        }
    }

    /// Returns the lowercase wire name of this profile.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Normal => "normal",
            Self::Thorough => "thorough",
        }
    }
}

/// Execution ordering strategy for benchmark cases within a phase.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "std", serde(rename_all = "snake_case"))]
pub enum OrderMode {
    #[default]
    Fixed,
    Shuffle,
}

impl OrderMode {
    /// Returns the lowercase wire name of this ordering mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Shuffle => "shuffle",
        }
    }
}

/// Runtime options parsed from `/chosen/bootargs`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunConfig<'a> {
    pub mode: RunMode,
    pub profile: Profile,
    pub order: OrderMode,
    pub seed: Option<u64>,
    pub filter: Option<&'a str>,
    pub resume_after: Option<&'a str>,
    pub allow_io: bool,
    pub allow_destructive: bool,
    pub max_harts: Option<usize>,
}

impl<'a> RunConfig<'a> {
    /// Parses space-delimited `key=value` parameters from a device-tree `bootargs` string.
    pub fn parse_bootargs(raw: &'a str) -> Self {
        Self::parse_bootargs_with_defaults("", raw)
    }

    /// Parses compile-time default parameters followed by runtime `/chosen/bootargs` overrides.
    pub fn parse_bootargs_with_defaults(defaults: &'a str, overrides: &'a str) -> Self {
        let mut cfg = Self::default();
        cfg.apply_bootargs(defaults);
        cfg.apply_bootargs(overrides);
        cfg
    }

    /// Applies space-delimited `key=value` parameters onto the current configuration.
    pub fn apply_bootargs(&mut self, raw: &'a str) {
        for token in raw.trim_matches('\0').split_whitespace() {
            let Some((key, value)) = token.split_once('=') else {
                continue;
            };
            match key {
                "mode" => {
                    if let Some(m) = RunMode::parse(value) {
                        self.mode = m;
                    }
                }
                "profile" => match value {
                    "quick" => self.profile = Profile::Quick,
                    "normal" => self.profile = Profile::Normal,
                    "thorough" => self.profile = Profile::Thorough,
                    _ => {}
                },
                "order" => match value {
                    "fixed" => self.order = OrderMode::Fixed,
                    "shuffle" => self.order = OrderMode::Shuffle,
                    _ => {}
                },
                "seed" => {
                    self.seed = parse_seed(value);
                }
                "filter" => {
                    self.filter = if value.is_empty() { None } else { Some(value) };
                }
                "resume_after" => {
                    self.resume_after = if value.is_empty() { None } else { Some(value) };
                }
                "io" => {
                    if let Some(flag) = parse_bool_flag(value) {
                        self.allow_io = flag;
                    }
                }
                "destructive" => {
                    if let Some(flag) = parse_bool_flag(value) {
                        self.allow_destructive = flag;
                    }
                }
                "max_harts" => {
                    if let Ok(n) = value.parse::<usize>()
                        && n > 0
                    {
                        self.max_harts = Some(n);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Computes effective hart ceiling combining platform hardware count with `max_harts` override.
pub fn effective_max_harts(available: usize, limit: Option<usize>) -> usize {
    match limit {
        Some(max_h) => available.min(max_h),
        None => available,
    }
}

fn parse_bool_flag(raw: &str) -> Option<bool> {
    match raw {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

fn parse_seed(raw: &str) -> Option<u64> {
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        raw.parse::<u64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bootargs_with_mode_and_options() {
        let cfg = RunConfig::parse_bootargs(
            "console=ttyS0 mode=bench profile=quick filter=rfnc resume_after=base/get_spec_version io=1 destructive=false max_harts=4 order=shuffle seed=0xdeadbeef\0",
        );
        assert_eq!(cfg.mode, RunMode::Bench);
        assert_eq!(cfg.profile, Profile::Quick);
        assert_eq!(cfg.filter, Some("rfnc"));
        assert_eq!(cfg.resume_after, Some("base/get_spec_version"));
        assert!(cfg.allow_io);
        assert!(!cfg.allow_destructive);
        assert_eq!(cfg.max_harts, Some(4));
        assert_eq!(cfg.order, OrderMode::Shuffle);
        assert_eq!(cfg.seed, Some(0xdead_beef));
        assert_eq!(RunConfig::parse_bootargs("seed=42").seed, Some(42));
        assert_eq!(RunConfig::parse_bootargs("seed=bad").seed, None);
        assert_eq!(ClockRegime::default(), ClockRegime::Unknown);
    }

    #[test]
    fn parses_bootargs_with_defaults_and_overrides() {
        let cfg = RunConfig::parse_bootargs_with_defaults(
            "mode=bench profile=quick filter=rfnc/ io=1",
            "mode=check filter=base/",
        );
        assert_eq!(cfg.mode, RunMode::Check);
        assert_eq!(cfg.profile, Profile::Quick);
        assert_eq!(cfg.filter, Some("base/"));
        assert!(cfg.allow_io);

        let cleared =
            RunConfig::parse_bootargs_with_defaults("filter=rfnc/", "filter= profile=thorough");
        assert_eq!(cleared.filter, None);
        assert_eq!(cleared.profile, Profile::Thorough);

        let fallback = RunConfig::parse_bootargs_with_defaults("mode=check max_harts=4", "");
        assert_eq!(fallback.mode, RunMode::Check);
        assert_eq!(fallback.max_harts, Some(4));
    }
}
