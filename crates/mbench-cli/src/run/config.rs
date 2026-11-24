//! `mbench run` CLI arguments, validated configuration, seed selection, and boot arguments.

use std::{
    path::{Path, PathBuf},
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Args, ValueEnum};
use mbench_core::config::{OrderMode, Profile, RunMode};

use super::{
    build::build_target_binary,
    output::{paths_refer_to_same_file, validate_output_file_path},
};
use crate::runner::QemuVirtRunner;

/// Largest accepted timeout, bounding all subsequent `Instant` arithmetic.
const MAX_TIMEOUT_SECONDS: u64 = 365 * 24 * 60 * 60;
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static SIGNAL_HANDLER_INIT: OnceLock<Result<(), String>> = OnceLock::new();

/// Top-level execution mode selectable via `--mode`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum CliRunMode {
    #[default]
    All,
    Check,
    Bench,
}

impl CliRunMode {
    pub(super) const fn into_core(self) -> RunMode {
        match self {
            Self::All => RunMode::All,
            Self::Check => RunMode::Check,
            Self::Bench => RunMode::Bench,
        }
    }
}

/// Benchmark intensity profile selectable via `--profile`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum CliProfile {
    Quick,
    #[default]
    Normal,
    Thorough,
}

impl CliProfile {
    pub(super) const fn into_core(self) -> Profile {
        match self {
            Self::Quick => Profile::Quick,
            Self::Normal => Profile::Normal,
            Self::Thorough => Profile::Thorough,
        }
    }
}

/// Case execution order selectable via `--order`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum CliOrder {
    #[default]
    Fixed,
    Shuffle,
}

impl CliOrder {
    pub(super) const fn into_core(self) -> OrderMode {
        match self {
            Self::Fixed => OrderMode::Fixed,
            Self::Shuffle => OrderMode::Shuffle,
        }
    }
}

/// CLI flags for `mbench run`.
#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    /// Path to the M-mode firmware binary (e.g., OpenSBI or RustSBI `.bin`).
    #[arg(long)]
    pub(crate) bios: PathBuf,

    /// Human label for this firmware run (used in `results/<name>.jsonl`).
    #[arg(long)]
    pub(crate) name: Option<String>,

    /// Optional prebuilt S-mode payload binary (auto-builds `mbench-target` if omitted).
    #[arg(long)]
    pub(crate) kernel: Option<PathBuf>,

    /// Number of virtual harts in QEMU `virt`.
    #[arg(long, default_value_t = 4)]
    pub(crate) smp: usize,

    /// Top-level suite execution mode (`all`, `check`, or `bench`).
    #[arg(long, value_enum, default_value_t = CliRunMode::All)]
    pub(crate) mode: CliRunMode,

    /// Benchmark intensity profile (`quick`, `normal`, or `thorough`).
    #[arg(long, value_enum, default_value_t = CliProfile::Normal)]
    pub(crate) profile: CliProfile,

    /// Execution ordering strategy within a benchmark phase (`fixed` or `shuffle`).
    #[arg(long, value_enum, default_value_t = CliOrder::Fixed)]
    pub(crate) order: CliOrder,

    /// Fixed PRNG seed for `--order shuffle` (decimal or `0x` hex), preserved across retries.
    #[arg(long)]
    pub(crate) seed: Option<String>,

    /// Optional case ID substring filter.
    #[arg(long)]
    pub(crate) filter: Option<String>,

    /// Run QEMU with deterministic instruction counting (`-icount shift=0,sleep=off`, requires `--smp 1`).
    #[arg(long, default_value_t = false)]
    pub(crate) icount: bool,

    /// Enable I/O-bound DBCN benchmarks (`io=1`).
    #[arg(long, default_value_t = false)]
    pub(crate) io: bool,

    /// Enable destructive benchmarks such as `SUSP` (`destructive=1`).
    #[arg(long, default_value_t = false)]
    pub(crate) destructive: bool,

    /// Cap the number of active harts used by `mbench-target` (`max_harts=<N>`).
    #[arg(long = "max-harts")]
    pub(crate) max_harts: Option<usize>,

    /// Per-case watchdog timeout in seconds.
    #[arg(long, default_value_t = 30)]
    pub(crate) timeout: u64,

    /// Extra arguments appended verbatim to the `qemu-system-riscv64` command line.
    #[arg(long = "qemu-arg")]
    pub(crate) qemu_args: Vec<String>,

    /// Path or executable name of `qemu-system-riscv64`.
    #[arg(long, default_value = "qemu-system-riscv64")]
    pub(crate) qemu: String,

    /// Output JSONL path (defaults to `results/<name>.jsonl`).
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,

    /// Optional path to save the complete raw target serial console log across attempts.
    #[arg(long)]
    pub(crate) raw_log: Option<PathBuf>,
}

pub(super) fn ensure_signal_handler() -> Result<(), String> {
    SIGNAL_HANDLER_INIT
        .get_or_init(|| {
            ctrlc::set_handler(|| {
                INTERRUPTED.store(true, Ordering::SeqCst);
            })
            .map_err(|e| format!("failed to install signal handler: {e}"))
        })
        .clone()
}

pub(super) fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

pub(super) fn reset_interrupted() {
    INTERRUPTED.store(false, Ordering::SeqCst);
}

pub(crate) fn execute(args: RunArgs) -> Result<(), String> {
    validate_run_args(&args)?;
    let kernel_path = match &args.kernel {
        Some(p) => p.clone(),
        None => build_target_binary()?,
    };
    let runner = QemuVirtRunner {
        qemu_bin: args.qemu.clone(),
    };
    super::execute_with_qemu_runner(&runner, &args, &kernel_path)
}

pub(super) fn resolve_label_and_out_path(args: &RunArgs) -> (String, PathBuf) {
    let label = args.name.clone().unwrap_or_else(|| {
        args.bios
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("firmware")
            .to_string()
    });
    let out_path = args
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from("results").join(format!("{label}.jsonl")));
    (label, out_path)
}

pub(super) fn validate_run_args(args: &RunArgs) -> Result<(), String> {
    if !args.bios.exists() {
        return Err(format!("BIOS file does not exist: {}", args.bios.display()));
    }
    if !args.bios.is_file() {
        return Err(format!(
            "BIOS path is not a regular file: {}",
            args.bios.display()
        ));
    }
    if let Some(kernel) = &args.kernel {
        if !kernel.exists() {
            return Err(format!("kernel file does not exist: {}", kernel.display()));
        }
        if !kernel.is_file() {
            return Err(format!(
                "kernel path is not a regular file: {}",
                kernel.display()
            ));
        }
    }
    if args.smp == 0 {
        return Err(String::from("--smp must be at least 1"));
    }
    if args.max_harts == Some(0) {
        return Err(String::from("--max-harts must be at least 1"));
    }
    if args.timeout == 0 {
        return Err(String::from("--timeout must be at least 1 second"));
    }
    if args.timeout > MAX_TIMEOUT_SECONDS {
        return Err(format!(
            "--timeout must not exceed {MAX_TIMEOUT_SECONDS} seconds"
        ));
    }
    if args.icount && args.smp != 1 {
        return Err(String::from(
            "--icount requires --smp 1 for deterministic single-thread TCG instruction counting",
        ));
    }
    if let Some(filter) = &args.filter {
        if filter.is_empty() {
            return Err(String::from("--filter must not be empty"));
        }
        if filter.chars().any(char::is_whitespace) {
            return Err(String::from(
                "--filter must not contain whitespace (bootargs tokens are whitespace-delimited)",
            ));
        }
    }
    if let Some(name) = &args.name {
        if name.trim().is_empty() {
            return Err(String::from("--name must not be empty"));
        }
        if args.out.is_none()
            && (name.contains('/') || name.contains('\\') || name == "." || name == "..")
        {
            return Err(String::from(
                "--name must not contain path separators or '.'/'..' when --out is omitted",
            ));
        }
    }
    if let Some(raw_seed) = &args.seed {
        let _ = parse_seed_u64(raw_seed)?;
    }
    let (_, out_path) = resolve_label_and_out_path(args);
    validate_output_file_path("--out", &out_path)?;
    reject_input_output_alias("--out", &out_path, args)?;
    if let Some(raw_log) = &args.raw_log {
        validate_output_file_path("--raw-log", raw_log)?;
        reject_input_output_alias("--raw-log", raw_log, args)?;
        if paths_refer_to_same_file(&out_path, raw_log)? {
            return Err(format!(
                "--out ('{}') and --raw-log ('{}') must not refer to the same file",
                out_path.display(),
                raw_log.display()
            ));
        }
    }
    Ok(())
}

fn reject_input_output_alias(flag: &str, output: &Path, args: &RunArgs) -> Result<(), String> {
    for (input_flag, input) in [
        ("--bios", Some(&args.bios)),
        ("--kernel", args.kernel.as_ref()),
    ] {
        let Some(input) = input else {
            continue;
        };
        if paths_refer_to_same_file(output, input)? {
            return Err(format!(
                "{flag} ('{}') and {input_flag} ('{}') must not refer to the same file",
                output.display(),
                input.display()
            ));
        }
    }
    Ok(())
}

pub(super) fn parse_seed_u64(raw: &str) -> Result<u64, String> {
    let parsed = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        raw.parse::<u64>().ok()
    };
    parsed.ok_or_else(|| format!("invalid --seed value '{raw}' (expected decimal or 0x hex u64)"))
}

pub(super) fn resolve_effective_seed(args: &RunArgs) -> Result<Option<u64>, String> {
    if let Some(raw) = &args.seed {
        return Ok(Some(parse_seed_u64(raw)?));
    }
    if args.order == CliOrder::Shuffle {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        return Ok(Some(nanos ^ u64::from(std::process::id())));
    }
    Ok(None)
}

pub(super) fn timeout_duration(args: &RunArgs) -> Result<Duration, String> {
    if args.timeout == 0 || args.timeout > MAX_TIMEOUT_SECONDS {
        return Err(format!(
            "--timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds"
        ));
    }
    Ok(Duration::from_secs(args.timeout))
}

/// Builds complete bootargs setting every knob explicitly so compiled defaults cannot leak through.
pub(super) fn build_bootargs(
    args: &RunArgs,
    seed: Option<u64>,
    resume_after: Option<&str>,
) -> String {
    let seed_tok = match seed {
        Some(seed_val) => format!("seed={seed_val:#x}"),
        None => String::from("seed="),
    };
    let filter_tok = match &args.filter {
        Some(flt) => format!("filter={flt}"),
        None => String::from("filter="),
    };
    let max_harts_tok = match args.max_harts {
        Some(mh) => format!("max_harts={mh}"),
        None => String::from("max_harts=0"),
    };
    let resume_tok = match resume_after {
        Some(id) => format!("resume_after={id}"),
        None => String::from("resume_after="),
    };
    [
        format!("mode={}", args.mode.into_core().as_str()),
        format!("profile={}", args.profile.into_core().as_str()),
        format!("order={}", args.order.into_core().as_str()),
        seed_tok,
        filter_tok,
        format!("io={}", usize::from(args.io)),
        format!("destructive={}", usize::from(args.destructive)),
        max_harts_tok,
        resume_tok,
    ]
    .join(" ")
}
