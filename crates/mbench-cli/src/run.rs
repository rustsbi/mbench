//! Target orchestration with fixed-seed shuffle, per-case watchdog timeout, and crash recovery.

use std::{
    collections::VecDeque,
    ffi::OsString,
    fs,
    io::{self, LineWriter, Write},
    path::{Component, Path, PathBuf},
    process::Command,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::{Args, ValueEnum};
use mbench_core::{
    config::{OrderMode, Profile, RunMode},
    protocol,
    record::{SbiExtensionId, SkipReason, StartKind},
    validate::{CaseTracker, audit_capture, audit_raw_attempt, summarize_records},
    wire::{
        AttemptRecord, EnvLine, RawAttemptStart, ShutdownStatus, StartFrame, WireFrame,
        parse_capture, parse_wire_line, shutdown_fail_reason, synthesize_fail_bench,
        synthesize_fail_check,
    },
};

use crate::runner::{
    QemuVirtRunner, SessionEvent, SessionExit, TargetLaunchConfig, TargetRunner, TargetSession,
};

const DEFAULT_TARGET: &str = "riscv64imac-unknown-none-elf";
const MAX_RECOVERY_ATTEMPTS: usize = 8;
const POST_END_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const POST_END_NO_SRST_GRACE: Duration = Duration::from_secs(1);

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static SIGNAL_HANDLER_INIT: OnceLock<Result<(), String>> = OnceLock::new();

fn ensure_signal_handler() -> Result<(), String> {
    SIGNAL_HANDLER_INIT
        .get_or_init(|| {
            ctrlc::set_handler(|| {
                INTERRUPTED.store(true, Ordering::SeqCst);
            })
            .map_err(|e| format!("failed to install signal handler: {e}"))
        })
        .clone()
}

fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Top-level execution mode selectable via `--mode`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum CliRunMode {
    #[default]
    All,
    Check,
    Bench,
}

impl CliRunMode {
    const fn into_core(self) -> RunMode {
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
    const fn into_core(self) -> Profile {
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
    const fn into_core(self) -> OrderMode {
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

pub(crate) fn execute(args: RunArgs) -> Result<(), String> {
    validate_run_args(&args)?;
    let kernel_path = match &args.kernel {
        Some(p) => p.clone(),
        None => build_target_binary()?,
    };
    let runner = QemuVirtRunner {
        qemu_bin: args.qemu.clone(),
    };
    execute_with_runner(&runner, &args, &kernel_path)
}

fn resolve_label_and_out_path(args: &RunArgs) -> (String, PathBuf) {
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

fn validate_run_args(args: &RunArgs) -> Result<(), String> {
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
    if let Some(raw_log) = &args.raw_log {
        validate_output_file_path("--raw-log", raw_log)?;
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

enum PathStep {
    Prefix(OsString),
    Root,
    Cur,
    Parent,
    Normal(OsString),
}

fn push_components_front(queue: &mut VecDeque<PathStep>, path: &Path) {
    let steps: Vec<PathStep> = path
        .components()
        .map(|comp| match comp {
            Component::Prefix(p) => PathStep::Prefix(p.as_os_str().to_os_string()),
            Component::RootDir => PathStep::Root,
            Component::CurDir => PathStep::Cur,
            Component::ParentDir => PathStep::Parent,
            Component::Normal(s) => PathStep::Normal(s.to_os_string()),
        })
        .collect();
    for step in steps.into_iter().rev() {
        queue.push_front(step);
    }
}

/// Resolves symlinks across existing prefixes and dangling/chained leaves before directory creation.
fn resolve_logical_target_path(path: &Path) -> Result<PathBuf, String> {
    const MAX_SYMLINK_HOPS: usize = 40;

    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("failed to resolve current directory: {e}"))?
            .join(path)
    };

    let mut queue = VecDeque::new();
    push_components_front(&mut queue, &abs);
    let mut resolved = PathBuf::new();
    let mut hops = 0usize;

    while let Some(step) = queue.pop_front() {
        match step {
            PathStep::Prefix(p) => resolved.push(p),
            PathStep::Root => resolved.push(std::path::MAIN_SEPARATOR_STR),
            PathStep::Cur => {}
            PathStep::Parent => {
                let _ = resolved.pop();
            }
            PathStep::Normal(name) => {
                let candidate = resolved.join(&name);
                match fs::symlink_metadata(&candidate) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        hops += 1;
                        if hops > MAX_SYMLINK_HOPS {
                            return Err(format!(
                                "too many levels of symbolic links while resolving '{}'",
                                path.display()
                            ));
                        }
                        let target = fs::read_link(&candidate).map_err(|e| {
                            format!("failed to read symlink {}: {e}", candidate.display())
                        })?;
                        if target.is_absolute() {
                            resolved.clear();
                        }
                        push_components_front(&mut queue, &target);
                    }
                    Ok(_) => resolved = candidate,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => resolved = candidate,
                    Err(_) => resolved = candidate,
                }
            }
        }
    }

    Ok(resolved)
}

fn validate_output_file_path(flag: &str, path: &Path) -> Result<(), String> {
    let raw = path.as_os_str().to_string_lossy();
    if path.as_os_str().is_empty()
        || raw.ends_with('/')
        || raw.ends_with('\\')
        || path.file_name().is_none()
    {
        return Err(format!(
            "{flag} path '{}' must include a file name",
            path.display()
        ));
    }
    let resolved = resolve_logical_target_path(path)?;
    if resolved.file_name().is_none() {
        return Err(format!(
            "{flag} path '{}' must include a file name",
            path.display()
        ));
    }
    if resolved.exists() && resolved.is_dir() {
        return Err(format!("{flag} path '{}' is a directory", path.display()));
    }
    if let Some(parent) = resolved.parent()
        && !parent.as_os_str().is_empty()
    {
        for ancestor in parent.ancestors() {
            if ancestor.as_os_str().is_empty() {
                break;
            }
            if ancestor.exists() {
                if !ancestor.is_dir() {
                    return Err(format!(
                        "parent component '{}' of {flag} path '{}' is not a directory",
                        ancestor.display(),
                        path.display()
                    ));
                }
                break;
            }
        }
    }
    Ok(())
}

fn paths_refer_to_same_file(a: &Path, b: &Path) -> Result<bool, String> {
    let res_a = resolve_logical_target_path(a)?;
    let res_b = resolve_logical_target_path(b)?;
    if res_a == res_b {
        return Ok(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(meta_a), Ok(meta_b)) = (fs::metadata(&res_a), fs::metadata(&res_b))
            && meta_a.dev() == meta_b.dev()
            && meta_a.ino() == meta_b.ino()
        {
            return Ok(true);
        }
        if let (Some(parent_a), Some(parent_b)) = (res_a.parent(), res_b.parent())
            && res_a.file_name() == res_b.file_name()
            && let (Ok(meta_pa), Ok(meta_pb)) = (fs::metadata(parent_a), fs::metadata(parent_b))
            && meta_pa.dev() == meta_pb.dev()
            && meta_pa.ino() == meta_pb.ino()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_seed_u64(raw: &str) -> Result<u64, String> {
    let parsed = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        raw.parse::<u64>().ok()
    };
    parsed.ok_or_else(|| format!("invalid --seed value '{raw}' (expected decimal or 0x hex u64)"))
}

fn resolve_effective_seed(args: &RunArgs) -> Result<Option<u64>, String> {
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

struct RawLogWriter {
    path: PathBuf,
    writer: LineWriter<fs::File>,
    had_write_error: bool,
}

impl RawLogWriter {
    fn create(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
        }
        let file = fs::File::create(path)
            .map_err(|e| format!("failed to create raw log {}: {e}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            writer: LineWriter::new(file),
            had_write_error: false,
        })
    }

    #[cfg(unix)]
    fn same_file_as(&self, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(raw_meta), Ok(other_meta)) =
            (self.writer.get_ref().metadata(), fs::metadata(path))
        {
            raw_meta.dev() == other_meta.dev() && raw_meta.ino() == other_meta.ino()
        } else {
            false
        }
    }

    #[cfg(not(unix))]
    fn same_file_as(&self, _path: &Path) -> bool {
        false
    }

    fn write_attempt_header(
        &mut self,
        attempt: usize,
        resume_after: Option<&str>,
    ) -> Option<String> {
        let hdr = RawAttemptStart {
            attempt,
            resume_after: resume_after.map(str::to_string),
        };
        let Ok(json) = serde_json::to_string(&hdr) else {
            return Some(String::from(
                "failed to serialize # MBENCH_RAW_ATTEMPT header",
            ));
        };
        if let Err(err) =
            writeln!(self.writer, "# MBENCH_RAW_ATTEMPT {json}").and_then(|()| self.writer.flush())
            && !self.had_write_error
        {
            self.had_write_error = true;
            return Some(format!(
                "failed to write raw log {}: {err}",
                self.path.display()
            ));
        }
        None
    }

    fn write_attempt_footer(&mut self, record: &AttemptRecord) -> Option<String> {
        let Ok(json) = serde_json::to_string(record) else {
            return Some(String::from("failed to serialize # MBENCH_ATTEMPT footer"));
        };
        if let Err(err) =
            writeln!(self.writer, "# MBENCH_ATTEMPT {json}").and_then(|()| self.writer.flush())
            && !self.had_write_error
        {
            self.had_write_error = true;
            return Some(format!(
                "failed to write raw log {}: {err}",
                self.path.display()
            ));
        }
        None
    }

    fn write_line(&mut self, line: &str) -> Option<String> {
        if let Err(err) = writeln!(self.writer, "{line}")
            && !self.had_write_error
        {
            self.had_write_error = true;
            return Some(format!(
                "failed to write raw log {}: {err}",
                self.path.display()
            ));
        }
        None
    }

    fn flush(&mut self) -> Option<String> {
        if let Err(err) = self.writer.flush()
            && !self.had_write_error
        {
            self.had_write_error = true;
            return Some(format!(
                "failed to flush raw log {}: {err}",
                self.path.display()
            ));
        }
        None
    }
}

fn prepare_outputs(
    out_path: &Path,
    raw_log: Option<&Path>,
) -> Result<Option<RawLogWriter>, String> {
    validate_output_file_path("--out", out_path)?;
    if let Some(raw) = raw_log {
        validate_output_file_path("--raw-log", raw)?;
        if paths_refer_to_same_file(out_path, raw)? {
            return Err(format!(
                "--out ('{}') and --raw-log ('{}') must not refer to the same file",
                out_path.display(),
                raw.display()
            ));
        }
    }

    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }

    let Some(raw) = raw_log else {
        return Ok(None);
    };

    if let Some(parent) = raw.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }

    if paths_refer_to_same_file(out_path, raw)? {
        return Err(format!(
            "--out ('{}') and --raw-log ('{}') must not refer to the same file",
            out_path.display(),
            raw.display()
        ));
    }

    let writer = RawLogWriter::create(raw)?;
    if paths_refer_to_same_file(out_path, &writer.path)? || writer.same_file_as(out_path) {
        return Err(format!(
            "--out ('{}') and --raw-log ('{}') must not refer to the same file",
            out_path.display(),
            writer.path.display()
        ));
    }
    Ok(Some(writer))
}

pub(crate) fn execute_with_runner<R: TargetRunner>(
    runner: &R,
    args: &RunArgs,
    kernel_path: &Path,
) -> Result<(), String> {
    INTERRUPTED.store(false, Ordering::SeqCst);
    ensure_signal_handler()?;

    let (label, out_path) = resolve_label_and_out_path(args);
    let mut raw_writer = prepare_outputs(&out_path, args.raw_log.as_deref())?;

    let effective_seed = resolve_effective_seed(args)?;

    let dummy_cfg = TargetLaunchConfig {
        bios: &args.bios,
        kernel: kernel_path,
        smp: args.smp,
        icount: args.icount,
        bootargs: "",
        extra_args: &args.qemu_args,
    };
    let env_line = EnvLine {
        clock_regime: runner.clock_regime(&dummy_cfg),
        label: Some(label.clone()),
        smp: Some(args.smp),
        icount: Some(args.icount),
        mode: Some(args.mode.into_core()),
        order: Some(args.order.into_core()),
        seed: effective_seed,
        max_harts: args.max_harts,
    };

    let mut state = CaptureState {
        frames: vec![format!(
            "# MBENCH_ENV {}",
            serde_json::to_string(&env_line).map_err(|e| e.to_string())?
        )],
        quarantine_warnings: 0,
    };

    let mut io_errors: Vec<String> = Vec::new();
    let mut resume_after: Option<String> = None;
    let mut completed_loop = false;
    let mut was_interrupted = false;

    for attempt in 0..=MAX_RECOVERY_ATTEMPTS {
        if is_interrupted() {
            let save_errs = save_outputs_independently(
                &out_path,
                Some(&render_frames(&state.frames)),
                &mut raw_writer,
            );
            io_errors.extend(save_errs);
            return Err(format_interrupted_error(&out_path, &io_errors));
        }

        let current_resume = resume_after.clone();
        let bootargs = build_bootargs(args, effective_seed, current_resume.as_deref());
        let launch_cfg = TargetLaunchConfig {
            bios: &args.bios,
            kernel: kernel_path,
            smp: args.smp,
            icount: args.icount,
            bootargs: &bootargs,
            extra_args: &args.qemu_args,
        };
        let outcome = match run_single_attempt(
            runner,
            &launch_cfg,
            attempt,
            current_resume.as_deref(),
            Duration::from_secs(args.timeout.max(1)),
            &mut state,
            raw_writer.as_mut(),
            &mut io_errors,
        ) {
            Ok(outcome) => outcome,
            Err(err) => {
                let save_errs = save_outputs_independently(
                    &out_path,
                    Some(&render_frames(&state.frames)),
                    &mut raw_writer,
                );
                io_errors.extend(save_errs);
                return Err(append_io_errors(err, &io_errors));
            }
        };

        let protocol_errors = audit_raw_attempt(&outcome.raw_lines, outcome.saw_end);

        if outcome.saw_end {
            let synthesized = append_unclosed_end_failures(&outcome.unclosed_at_end, &mut state)?;
            record_attempt(
                &mut state,
                raw_writer.as_mut(),
                &mut io_errors,
                AttemptRecord {
                    attempt,
                    resume_after: current_resume,
                    saw_end: true,
                    shutdown: outcome.shutdown.clone(),
                    protocol_errors,
                    synthesized_failures: synthesized,
                },
            )?;
            if outcome.interrupted {
                was_interrupted = true;
            }
            completed_loop = true;
            break;
        }

        if outcome.interrupted {
            let mut synth_ids = Vec::with_capacity(outcome.stuck_cases.len());
            for stuck in &outcome.stuck_cases {
                state
                    .frames
                    .push(synthesize_fail_frame(stuck, "interrupted")?);
                synth_ids.push(stuck.id.clone());
            }
            record_attempt(
                &mut state,
                raw_writer.as_mut(),
                &mut io_errors,
                AttemptRecord {
                    attempt,
                    resume_after: current_resume,
                    saw_end: false,
                    shutdown: ShutdownStatus::Interrupted,
                    protocol_errors,
                    synthesized_failures: synth_ids,
                },
            )?;
            let save_errs = save_outputs_independently(
                &out_path,
                Some(&render_frames(&state.frames)),
                &mut raw_writer,
            );
            io_errors.extend(save_errs);
            return Err(format_interrupted_error(&out_path, &io_errors));
        }

        let (next_resume, synthesized) = if !outcome.stuck_cases.is_empty() {
            let reason = shutdown_fail_reason(&outcome.shutdown);
            let resume_id = outcome
                .stuck_cases
                .last()
                .expect("non-empty stuck_cases")
                .id
                .clone();
            let mut synth_ids = Vec::with_capacity(outcome.stuck_cases.len());
            for stuck in &outcome.stuck_cases {
                eprintln!(
                    "[mbench-cli] warning: '{}' (p={}) did not finish ({reason}); synthesizing FAIL (attempt {})",
                    stuck.id,
                    stuck.parallel,
                    attempt + 1
                );
                state.frames.push(synthesize_fail_frame(stuck, reason)?);
                synth_ids.push(stuck.id.clone());
            }
            (Some(resume_id), synth_ids)
        } else if let Some(finished_id) = outcome.last_completed_id {
            eprintln!(
                "[mbench-cli] warning: target stopped after '{finished_id}' ({:?}); resuming (attempt {})",
                outcome.shutdown,
                attempt + 1
            );
            (Some(finished_id), Vec::new())
        } else {
            (None, Vec::new())
        };

        record_attempt(
            &mut state,
            raw_writer.as_mut(),
            &mut io_errors,
            AttemptRecord {
                attempt,
                resume_after: current_resume.clone(),
                saw_end: false,
                shutdown: outcome.shutdown.clone(),
                protocol_errors,
                synthesized_failures: synthesized,
            },
        )?;

        let Some(next_resume_id) = next_resume else {
            let save_errs = save_outputs_independently(
                &out_path,
                Some(&render_frames(&state.frames)),
                &mut raw_writer,
            );
            io_errors.extend(save_errs);
            return Err(append_io_errors(
                format!(
                    "target stopped ({:?}) before emitting @@MBENCH:END and no active case was recorded (saved partial capture to {})",
                    outcome.shutdown,
                    out_path.display()
                ),
                &io_errors,
            ));
        };

        if current_resume.as_deref() == Some(next_resume_id.as_str()) {
            let save_errs = save_outputs_independently(
                &out_path,
                Some(&render_frames(&state.frames)),
                &mut raw_writer,
            );
            io_errors.extend(save_errs);
            return Err(append_io_errors(
                format!(
                    "recovery stalled on '{next_resume_id}' across consecutive attempts (saved partial capture to {})",
                    out_path.display()
                ),
                &io_errors,
            ));
        }
        resume_after = Some(next_resume_id);
    }

    if !completed_loop {
        let save_errs = save_outputs_independently(
            &out_path,
            Some(&render_frames(&state.frames)),
            &mut raw_writer,
        );
        io_errors.extend(save_errs);
        return Err(append_io_errors(
            format!(
                "exceeded maximum recovery attempts ({MAX_RECOVERY_ATTEMPTS}) (saved partial capture to {})",
                out_path.display()
            ),
            &io_errors,
        ));
    }

    let content = match finalize_merged_capture(&label, &mut state) {
        Ok(content) => content,
        Err(err) => {
            let save_errs = save_outputs_independently(
                &out_path,
                Some(&render_frames(&state.frames)),
                &mut raw_writer,
            );
            io_errors.extend(save_errs);
            return Err(append_io_errors(err, &io_errors));
        }
    };

    let save_errs = save_outputs_independently(&out_path, Some(&content), &mut raw_writer);
    io_errors.extend(save_errs);

    let report = audit_capture(&label, &content);
    let mut errors = report.protocol_errors;
    if !report.completed {
        errors.push(String::from("capture did not reach completed END state"));
    }
    if let Some(meta) = &report.meta
        && meta.hart_count != args.smp
    {
        errors.push(format!(
            "reported hart_count={} does not match requested --smp {}",
            meta.hart_count, args.smp
        ));
    }
    errors.extend(io_errors);

    if was_interrupted || is_interrupted() {
        let base = format!(
            "interrupted by signal after @@MBENCH:END; saved completed capture to {}",
            out_path.display()
        );
        let msg = if errors.is_empty() {
            base
        } else {
            format!("{base}\nadditional errors:\n  - {}", errors.join("\n  - "))
        };
        return Err(msg);
    }

    if let Some(last) = report.attempts.last()
        && !matches!(
            last.shutdown,
            ShutdownStatus::CleanExit | ShutdownStatus::HostTerminatedAfterEnd
        )
    {
        eprintln!(
            "[mbench-cli] warning: target shutdown status after @@MBENCH:END was {:?}",
            last.shutdown
        );
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "run finished with errors (capture path: {}):\n  - {}",
            out_path.display(),
            errors.join("\n  - ")
        ))
    }
}

fn render_frames(frames: &[String]) -> String {
    format!("{}\n", frames.join("\n"))
}

fn format_interrupted_error(out_path: &Path, io_errors: &[String]) -> String {
    append_io_errors(
        format!(
            "interrupted by signal; saved partial capture to {}",
            out_path.display()
        ),
        io_errors,
    )
}

fn append_io_errors(msg: String, io_errors: &[String]) -> String {
    if io_errors.is_empty() {
        msg
    } else {
        format!("{msg}\noutput errors:\n  - {}", io_errors.join("\n  - "))
    }
}

fn save_outputs_independently(
    out_path: &Path,
    out_content: Option<&str>,
    raw_writer: &mut Option<RawLogWriter>,
) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(content) = out_content {
        let alias_err = raw_writer.as_ref().and_then(|writer| {
            let aliased = writer.same_file_as(out_path)
                || matches!(paths_refer_to_same_file(out_path, &writer.path), Ok(true));
            aliased.then(|| {
                format!(
                    "refusing to overwrite raw log '{}' through aliased --out path '{}'",
                    writer.path.display(),
                    out_path.display()
                )
            })
        });
        let write_res = if let Some(err) = alias_err {
            Err(err)
        } else {
            (|| -> Result<(), String> {
                if let Some(parent) = out_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
                }
                fs::write(out_path, content)
                    .map_err(|e| format!("failed to write {}: {e}", out_path.display()))?;
                eprintln!("[mbench-cli] saved {}", out_path.display());
                Ok(())
            })()
        };
        if let Err(err) = write_res {
            eprintln!("[mbench-cli] warning: {err}");
            errors.push(err);
        }
    }
    if let Some(writer) = raw_writer {
        if let Some(err) = writer.flush() {
            eprintln!("[mbench-cli] warning: {err}");
            errors.push(err);
        } else if !writer.had_write_error {
            eprintln!("[mbench-cli] saved raw log {}", writer.path.display());
        }
    }
    errors
}

fn record_attempt(
    state: &mut CaptureState,
    raw_writer: Option<&mut RawLogWriter>,
    io_errors: &mut Vec<String>,
    record: AttemptRecord,
) -> Result<(), String> {
    let json = serde_json::to_string(&record).map_err(|e| e.to_string())?;
    state.frames.push(format!("# MBENCH_ATTEMPT {json}"));
    if let Some(writer) = raw_writer
        && let Some(err) = writer.write_attempt_footer(&record)
    {
        io_errors.push(err);
    }
    Ok(())
}

fn append_unclosed_end_failures(
    unclosed: &[StartFrame],
    state: &mut CaptureState,
) -> Result<Vec<String>, String> {
    let mut ids = Vec::with_capacity(unclosed.len());
    for entry in unclosed {
        eprintln!(
            "[mbench-cli] warning: '{}' (p={}) opened before END without a valid result frame; synthesizing FAIL(protocol_error)",
            entry.id, entry.parallel,
        );
        state
            .frames
            .push(synthesize_fail_frame(entry, "protocol_error")?);
        ids.push(entry.id.clone());
    }
    Ok(ids)
}

fn finalize_merged_capture(label: &str, state: &mut CaptureState) -> Result<String, String> {
    let body = render_frames(&state.frames);
    let parsed = parse_capture(label, &body)
        .map_err(|e| format!("captured output failed wire validation: {e}"))?;
    let merged_end = summarize_records(&parsed.checks, &parsed.benches, state.quarantine_warnings);
    let mut end_line = String::new();
    protocol::write_end_line(&merged_end, &mut end_line)
        .map_err(|e| format!("failed to format END frame: {e}"))?;
    state.frames.push(end_line.trim_end().to_string());

    let content = render_frames(&state.frames);
    let _ = parse_capture(label, &content)
        .map_err(|e| format!("final capture failed wire validation: {e}"))?;
    Ok(content)
}

struct CaptureState {
    frames: Vec<String>,
    quarantine_warnings: usize,
}

struct AttemptOutcome {
    raw_lines: Vec<String>,
    saw_end: bool,
    interrupted: bool,
    shutdown: ShutdownStatus,
    stuck_cases: Vec<StartFrame>,
    unclosed_at_end: Vec<StartFrame>,
    last_completed_id: Option<String>,
}

enum LineAction {
    Continue,
    ArmCaseDeadline,
    RefreshPhaseIfIdle,
    ClearCaseAndRefreshPhase,
    ArmShutdownDeadline,
    StopSession,
}

struct AttemptTracker {
    cases: CaseTracker,
    unclosed_at_end: Vec<StartFrame>,
    last_completed_id: Option<String>,
    saw_srst: Option<bool>,
    saw_panic: bool,
    saw_end: bool,
}

impl AttemptTracker {
    const fn new() -> Self {
        Self {
            cases: CaseTracker::new(),
            unclosed_at_end: Vec::new(),
            last_completed_id: None,
            saw_srst: None,
            saw_panic: false,
            saw_end: false,
        }
    }

    fn process_line(&mut self, line: &str, state: &mut CaptureState) -> LineAction {
        match parse_wire_line(line) {
            Ok(Some(WireFrame::Start(start))) => {
                let _ = self.cases.record_start(start);
                LineAction::ArmCaseDeadline
            }
            Ok(Some(WireFrame::Meta(meta))) => {
                self.saw_srst = Some(meta.extensions.contains(&SbiExtensionId::Srst));
                push_normalized_wire_line(line, &mut state.frames);
                LineAction::RefreshPhaseIfIdle
            }
            Ok(Some(WireFrame::Cal(_))) => {
                push_normalized_wire_line(line, &mut state.frames);
                LineAction::RefreshPhaseIfIdle
            }
            Ok(Some(WireFrame::Check(chk))) => {
                if chk.skip_reason == Some(SkipReason::ResumedPast) {
                    return LineAction::RefreshPhaseIfIdle;
                }
                let _ = self.cases.close_check(&chk.id);
                self.last_completed_id = Some(chk.id);
                push_normalized_wire_line(line, &mut state.frames);
                if self.cases.is_empty() {
                    LineAction::ClearCaseAndRefreshPhase
                } else {
                    LineAction::Continue
                }
            }
            Ok(Some(WireFrame::Bench(b))) => {
                if b.skip_reason == Some(SkipReason::ResumedPast) {
                    return LineAction::RefreshPhaseIfIdle;
                }
                let _ = self.cases.close_bench(&b.id, b.parallel);
                self.last_completed_id = Some(b.id);
                push_normalized_wire_line(line, &mut state.frames);
                if self.cases.is_empty() {
                    LineAction::ClearCaseAndRefreshPhase
                } else {
                    LineAction::Continue
                }
            }
            Ok(Some(WireFrame::End(end))) => {
                self.saw_end = true;
                state.quarantine_warnings = state
                    .quarantine_warnings
                    .saturating_add(end.quarantine_warnings);
                self.unclosed_at_end.extend(self.cases.drain_all());
                LineAction::ArmShutdownDeadline
            }
            Ok(Some(WireFrame::Panic(_))) => {
                self.saw_panic = true;
                push_normalized_wire_line(line, &mut state.frames);
                println!("{line}");
                LineAction::StopSession
            }
            Ok(Some(WireFrame::Env(_) | WireFrame::Attempt(_) | WireFrame::RawAttemptStart(_))) => {
                LineAction::Continue
            }
            Ok(None) => {
                println!("{line}");
                LineAction::Continue
            }
            Err(err) => {
                eprintln!("[mbench-cli] warning: invalid wire line preserved in audit: {err}");
                println!("{line}");
                LineAction::Continue
            }
        }
    }

    fn classify_shutdown(
        &self,
        timed_out: bool,
        interrupted: bool,
        exit_status: SessionExit,
    ) -> ShutdownStatus {
        if interrupted {
            return ShutdownStatus::Interrupted;
        }
        if self.saw_panic && !self.saw_end {
            return ShutdownStatus::AbortedOnPanic;
        }
        if !self.saw_end {
            if timed_out {
                return ShutdownStatus::TimedOutDuringRun;
            }
            return match exit_status {
                SessionExit::Exited(Some(0)) => ShutdownStatus::CleanExit,
                SessionExit::Exited(Some(code)) => ShutdownStatus::NonZeroExit { code },
                SessionExit::Exited(None) => ShutdownStatus::Signaled,
                SessionExit::Killed => ShutdownStatus::TimedOutDuringRun,
            };
        }
        if timed_out {
            return if self.saw_srst == Some(false) {
                ShutdownStatus::HostTerminatedAfterEnd
            } else {
                ShutdownStatus::TimedOutAfterEnd
            };
        }
        match exit_status {
            SessionExit::Exited(Some(0)) => ShutdownStatus::CleanExit,
            SessionExit::Exited(Some(code)) => ShutdownStatus::NonZeroExit { code },
            SessionExit::Exited(None) => ShutdownStatus::Signaled,
            SessionExit::Killed => {
                if self.saw_srst == Some(false) {
                    ShutdownStatus::HostTerminatedAfterEnd
                } else {
                    ShutdownStatus::TimedOutAfterEnd
                }
            }
        }
    }

    fn into_outcome(
        mut self,
        raw_lines: Vec<String>,
        timed_out: bool,
        interrupted: bool,
        exit_status: SessionExit,
    ) -> AttemptOutcome {
        let shutdown = self.classify_shutdown(timed_out, interrupted, exit_status);
        let stuck_cases = if self.saw_end {
            Vec::new()
        } else {
            self.cases.drain_all()
        };
        AttemptOutcome {
            raw_lines,
            saw_end: self.saw_end,
            interrupted,
            shutdown,
            stuck_cases,
            unclosed_at_end: self.unclosed_at_end,
            last_completed_id: self.last_completed_id,
        }
    }
}

fn record_and_handle_line(
    line: String,
    tracker: &mut AttemptTracker,
    state: &mut CaptureState,
    attempt_raw_lines: &mut Vec<String>,
    raw_writer: Option<&mut RawLogWriter>,
    io_errors: &mut Vec<String>,
) -> LineAction {
    if let Some(writer) = raw_writer
        && let Some(err) = writer.write_line(&line)
    {
        io_errors.push(err);
    }
    attempt_raw_lines.push(line.clone());
    tracker.process_line(&line, state)
}

#[expect(clippy::too_many_arguments)]
fn run_single_attempt<R: TargetRunner>(
    runner: &R,
    cfg: &TargetLaunchConfig<'_>,
    attempt: usize,
    resume_after: Option<&str>,
    timeout: Duration,
    state: &mut CaptureState,
    mut raw_writer: Option<&mut RawLogWriter>,
    io_errors: &mut Vec<String>,
) -> Result<AttemptOutcome, String> {
    let mut session = runner.launch(cfg)?;
    if let Some(writer) = raw_writer.as_deref_mut()
        && let Some(err) = writer.write_attempt_header(attempt, resume_after)
    {
        io_errors.push(err);
    }
    let mut phase_deadline = Instant::now() + timeout;
    let mut case_deadline: Option<Instant> = None;
    let mut tracker = AttemptTracker::new();
    let mut attempt_raw_lines = Vec::new();
    let mut timed_out = false;
    let mut interrupted = false;
    let mut stopped_early = false;

    loop {
        if is_interrupted() {
            interrupted = true;
            stopped_early = true;
            let _ = session.terminate_and_wait();
            break;
        }
        let now = Instant::now();
        let active_deadline = case_deadline.unwrap_or(phase_deadline);
        if now >= active_deadline {
            timed_out = true;
            stopped_early = true;
            let _ = session.terminate_and_wait();
            break;
        }
        let wait_for = active_deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(100));

        match session.next_event(wait_for) {
            Ok(Some(SessionEvent::Line(line))) => {
                let action = record_and_handle_line(
                    line,
                    &mut tracker,
                    state,
                    &mut attempt_raw_lines,
                    raw_writer.as_deref_mut(),
                    io_errors,
                );
                match action {
                    LineAction::Continue => {}
                    LineAction::ArmCaseDeadline => case_deadline = Some(Instant::now() + timeout),
                    LineAction::RefreshPhaseIfIdle => {
                        if case_deadline.is_none() {
                            phase_deadline = Instant::now() + timeout;
                        }
                    }
                    LineAction::ClearCaseAndRefreshPhase => {
                        case_deadline = None;
                        phase_deadline = Instant::now() + timeout;
                    }
                    LineAction::ArmShutdownDeadline => {
                        case_deadline = None;
                        let grace = if tracker.saw_srst == Some(false) {
                            timeout.min(POST_END_NO_SRST_GRACE)
                        } else {
                            timeout.min(POST_END_SHUTDOWN_TIMEOUT)
                        };
                        phase_deadline = Instant::now() + grace;
                    }
                    LineAction::StopSession => {
                        stopped_early = true;
                        let _ = session.terminate_and_wait();
                        break;
                    }
                }
            }
            Ok(Some(SessionEvent::Eof)) => break,
            Ok(None) => {}
            Err(err) => {
                let _ = session.terminate_and_wait();
                return Err(err);
            }
        }
    }

    let exit_status = if stopped_early {
        session.terminate_and_wait()
    } else {
        let exit_grace = if tracker.saw_srst == Some(false) {
            timeout.min(POST_END_NO_SRST_GRACE)
        } else {
            timeout.min(POST_END_SHUTDOWN_TIMEOUT)
        };
        let exit_deadline = Instant::now() + exit_grace;
        loop {
            if is_interrupted() {
                interrupted = true;
                break session.terminate_and_wait();
            }
            let slice = exit_deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100));
            match session.wait_for_exit(slice) {
                Ok(Some(exit)) => break exit,
                Ok(None) => {
                    if Instant::now() >= exit_deadline {
                        if is_interrupted() {
                            interrupted = true;
                        } else {
                            timed_out = true;
                        }
                        break session.terminate_and_wait();
                    }
                }
                Err(err) => {
                    let _ = session.terminate_and_wait();
                    return Err(err);
                }
            }
        }
    };

    // Drain any buffered serial lines delivered before the reader joined.
    while let Ok(Some(SessionEvent::Line(line))) = session.next_event(Duration::ZERO) {
        let _ = record_and_handle_line(
            line,
            &mut tracker,
            state,
            &mut attempt_raw_lines,
            raw_writer.as_deref_mut(),
            io_errors,
        );
    }

    if is_interrupted() {
        interrupted = true;
    }

    Ok(tracker.into_outcome(attempt_raw_lines, timed_out, interrupted, exit_status))
}

fn push_normalized_wire_line(raw_line: &str, out: &mut Vec<String>) {
    if let Some(pos) = raw_line.find("@@MBENCH:") {
        out.push(raw_line[pos..].trim_end_matches(['\r', '\n']).to_string());
    }
}

fn synthesize_fail_frame(started: &StartFrame, reason: &str) -> Result<String, String> {
    match started.kind {
        StartKind::Check => {
            let frame = synthesize_fail_check(&started.id, reason);
            let json = serde_json::to_string(&frame).map_err(|e| e.to_string())?;
            Ok(format!("@@MBENCH:CHECK {json}"))
        }
        StartKind::Bench => {
            let frame = synthesize_fail_bench(&started.id, started.parallel, reason);
            let json = serde_json::to_string(&frame).map_err(|e| e.to_string())?;
            Ok(format!("@@MBENCH:BENCH {json}"))
        }
    }
}

/// Builds complete bootargs setting every knob explicitly so compiled defaults cannot leak through.
fn build_bootargs(args: &RunArgs, seed: Option<u64>, resume_after: Option<&str>) -> String {
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

pub(crate) fn build_target_binary() -> Result<PathBuf, String> {
    eprintln!("[mbench-cli] building mbench-target ({DEFAULT_TARGET})...");
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "mbench-target",
            "--target",
            DEFAULT_TARGET,
        ])
        .status()
        .map_err(|e| format!("failed to run cargo build: {e}"))?;
    if !status.success() {
        return Err(String::from("cargo build -p mbench-target failed"));
    }

    let elf = PathBuf::from(format!("target/{DEFAULT_TARGET}/release/mbench-target"));
    let bin = PathBuf::from(format!("target/{DEFAULT_TARGET}/release/mbench.bin"));
    convert_elf_to_binary(&elf, &bin)?;
    Ok(bin)
}

fn convert_elf_to_binary(elf: &Path, bin: &Path) -> Result<(), String> {
    for tool in ["rust-objcopy", "llvm-objcopy"] {
        match Command::new(tool)
            .args(["-O", "binary"])
            .arg(elf)
            .arg(bin)
            .status()
        {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => {
                return Err(format!("{tool} failed with exit status {status}"));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!("failed to run {tool}: {err}"));
            }
        }
    }
    Err(String::from(
        "failed to convert ELF to binary: neither rust-objcopy nor llvm-objcopy was found on PATH",
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use mbench_core::{
        config::ClockRegime, protocol::write_cal_line, record::CalibrationRecord,
        wire::CheckStatusTag,
    };

    use super::*;

    static NEXT_DIR_ID: AtomicUsize = AtomicUsize::new(0);

    struct TestWorkDir(PathBuf);

    impl TestWorkDir {
        fn new(tag: &str) -> Self {
            let id = NEXT_DIR_ID.fetch_add(1, Ordering::Relaxed);
            let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/mbench-cli-unit-tests")
                .join(format!("{tag}-{}-{id}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TestWorkDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn base_test_args(out: Option<PathBuf>) -> RunArgs {
        RunArgs {
            bios: PathBuf::from("fw.bin"),
            name: Some(String::from("fw")),
            kernel: None,
            smp: 4,
            mode: CliRunMode::Check,
            profile: CliProfile::Quick,
            order: CliOrder::Fixed,
            seed: None,
            filter: None,
            icount: false,
            io: false,
            destructive: false,
            max_harts: None,
            timeout: 30,
            qemu_args: Vec::new(),
            qemu: String::from("qemu-system-riscv64"),
            out,
            raw_log: None,
        }
    }

    #[test]
    fn builds_explicit_bootargs_synthesizes_synthetic_fails_and_merges_end() {
        let mut args = base_test_args(None);
        let default_bootargs = build_bootargs(&args, None, None);
        assert_eq!(
            default_bootargs,
            "mode=check profile=quick order=fixed seed= filter= io=0 destructive=0 max_harts=0 resume_after="
        );

        args.mode = CliRunMode::Bench;
        args.order = CliOrder::Shuffle;
        args.seed = Some(String::from("0xdeadbeef"));
        args.filter = Some(String::from("rfnc/"));
        args.io = true;
        args.destructive = true;
        args.max_harts = Some(2);
        assert_eq!(parse_seed_u64("0xdeadbeef").unwrap(), 0xdead_beef);
        assert_eq!(parse_seed_u64("42").unwrap(), 42);
        assert!(parse_seed_u64("not_a_seed").is_err());

        let seed = resolve_effective_seed(&args).unwrap();
        assert_eq!(seed, Some(0xdead_beef));
        let bootargs = build_bootargs(&args, seed, Some("rfnc/sfence_vma"));
        assert_eq!(
            bootargs,
            "mode=bench profile=quick order=shuffle seed=0xdeadbeef filter=rfnc/ io=1 destructive=1 max_harts=2 resume_after=rfnc/sfence_vma"
        );

        let check_line = synthesize_fail_frame(
            &StartFrame {
                kind: StartKind::Check,
                id: String::from("conformance/base"),
                parallel: 1,
            },
            "timeout",
        )
        .unwrap();
        let sweep_p1 = "@@MBENCH:BENCH {\"id\":\"scale/base_ecall\",\"group\":\"scale\",\"mode\":\"parallel_sweep\",\"parallel\":1,\"unit\":\"call\",\"iters_per_trial\":0,\"trials\":0,\"status\":\"FAIL\",\"fail_reason\":\"hardware_inconsistent\"}".to_string();
        let sweep_p2_fail = synthesize_fail_frame(
            &StartFrame {
                kind: StartKind::Bench,
                id: String::from("scale/base_ecall"),
                parallel: 2,
            },
            "crash",
        )
        .unwrap();

        let mut cal0 = String::new();
        write_cal_line(&CalibrationRecord::default(), &mut cal0).unwrap();
        let mut cal1 = String::new();
        write_cal_line(
            &CalibrationRecord {
                enough_iters: 512,
                ..CalibrationRecord::default()
            },
            &mut cal1,
        )
        .unwrap();

        let env_hdr = serde_json::to_string(&EnvLine {
            clock_regime: ClockRegime::QemuTcgNonCycleAccurate,
            label: Some(String::from("fw")),
            smp: Some(4),
            icount: Some(false),
            mode: Some(RunMode::All),
            order: Some(OrderMode::Shuffle),
            seed: Some(0xdead_beef),
            max_harts: Some(2),
        })
        .unwrap();

        let mut state = CaptureState {
            frames: vec![
                format!("# MBENCH_ENV {env_hdr}"),
                "@@MBENCH:META {\"sbi_spec_version\":50331648,\"impl_id\":1,\"impl_version\":1,\"mvendorid\":0,\"marchid\":0,\"mimpid\":0,\"extensions\":[\"base\"],\"extensions_mask\":1,\"hart_count\":2,\"boot_hart_id\":0,\"timebase_hz\":10000000,\"has_cycle\":true,\"has_instret\":true,\"has_time\":true,\"is_rdtime_emulated\":false,\"is_pmu_gated\":false,\"has_sstc\":false,\"has_h_ext\":false,\"boot_ticks\":1,\"reserved_mem_bytes\":0,\"console_backend\":\"dbcn\",\"pmu_counter_count\":0,\"load_addr\":2149580800}".to_string(),
                cal0.trim().to_string(),
                check_line,
                sweep_p1,
                "@@MBENCH:META {\"sbi_spec_version\":50331648,\"impl_id\":1,\"impl_version\":1,\"mvendorid\":0,\"marchid\":0,\"mimpid\":0,\"extensions\":[\"base\"],\"extensions_mask\":1,\"hart_count\":2,\"boot_hart_id\":0,\"timebase_hz\":10000000,\"has_cycle\":true,\"has_instret\":true,\"has_time\":true,\"is_rdtime_emulated\":false,\"is_pmu_gated\":false,\"has_sstc\":false,\"has_h_ext\":false,\"boot_ticks\":1,\"reserved_mem_bytes\":0,\"console_backend\":\"dbcn\",\"pmu_counter_count\":0,\"load_addr\":2149580800}".to_string(),
                cal1.trim().to_string(),
                sweep_p2_fail,
            ],
            quarantine_warnings: 2,
        };
        let merged = finalize_merged_capture("fw", &mut state).unwrap();
        let cap = parse_capture("fw", &merged).unwrap();
        assert_eq!(cap.cals.len(), 2);
        assert_eq!(cap.checks.len(), 1);
        assert!(cap.checks[0].synthetic);
        assert_eq!(cap.benches.len(), 2);
        assert!(!cap.benches[0].synthetic);
        assert!(cap.benches[1].synthetic);
        assert_eq!(cap.benches[0].cal_index, Some(0));
        assert_eq!(cap.benches[1].cal_index, Some(1));
        let end = cap.end.unwrap();
        assert_eq!(end.checks_total, 1);
        assert_eq!(end.checks_failed, 1);
        assert_eq!(end.benches_total, 2);
        assert_eq!(end.benches_failed, 2);
        assert_eq!(end.quarantine_warnings, 2);
    }

    #[test]
    fn preserves_unclosed_started_case_as_protocol_error_when_end_arrives() {
        let lines = [
            "@@MBENCH:META {\"sbi_spec_version\":50331648,\"impl_id\":1,\"impl_version\":1,\"mvendorid\":0,\"marchid\":0,\"mimpid\":0,\"extensions\":[\"base\"],\"extensions_mask\":1,\"hart_count\":2,\"boot_hart_id\":0,\"timebase_hz\":10000000,\"has_cycle\":true,\"has_instret\":true,\"has_time\":true,\"is_rdtime_emulated\":false,\"is_pmu_gated\":false,\"has_sstc\":false,\"has_h_ext\":false,\"boot_ticks\":1,\"reserved_mem_bytes\":0,\"console_backend\":\"dbcn\",\"pmu_counter_count\":0,\"load_addr\":2149580800}",
            "@@MBENCH:START {\"kind\":\"check\",\"id\":\"conformance/base\",\"parallel\":1}",
            "@@MBENCH:CHECK {\"id\":\"conformance/base\",INVALID_JSON}",
            "@@MBENCH:END {\"checks_total\":0,\"checks_passed\":0,\"checks_skipped\":0,\"checks_failed\":0,\"check_assertions_total\":0,\"check_assertions_passed\":0,\"check_assertions_failed\":0,\"benches_total\":0,\"benches_passed\":0,\"benches_skipped\":0,\"benches_hw_native\":0,\"benches_delegated\":0,\"benches_failed\":0,\"quarantine_warnings\":0}",
        ];
        let mut state = CaptureState {
            frames: Vec::new(),
            quarantine_warnings: 0,
        };
        let mut tracker = AttemptTracker::new();
        for line in lines {
            let _ = tracker.process_line(line, &mut state);
        }
        let raw_vec: Vec<String> = lines.iter().map(|s| (*s).to_string()).collect();
        let outcome = tracker.into_outcome(raw_vec, false, false, SessionExit::Exited(Some(0)));
        assert!(outcome.saw_end);
        assert_eq!(outcome.unclosed_at_end.len(), 1);
        assert_eq!(outcome.unclosed_at_end[0].id, "conformance/base");
        assert!(
            !audit_raw_attempt(&outcome.raw_lines, outcome.saw_end).is_empty(),
            "raw attempt audit must preserve unclosed START and invalid JSON errors"
        );
        let synth = append_unclosed_end_failures(&outcome.unclosed_at_end, &mut state).unwrap();
        assert_eq!(synth, vec!["conformance/base"]);
        let merged = finalize_merged_capture("fw", &mut state).unwrap();
        let cap = parse_capture("fw", &merged).unwrap();
        assert_eq!(cap.checks.len(), 1);
        assert!(cap.checks[0].synthetic);
        assert_eq!(cap.checks[0].status, CheckStatusTag::Fail);
        assert_eq!(cap.checks[0].fail_reason.as_deref(), Some("protocol_error"));
    }

    #[test]
    fn validates_output_paths_hardlinks_and_independent_saving() {
        let dir = TestWorkDir::new("args");
        let bios = dir.0.join("fw.bin");
        fs::write(&bios, b"fw").unwrap();

        let base_args = || {
            let mut a = base_test_args(None);
            a.bios = bios.clone();
            a.mode = CliRunMode::All;
            a
        };
        assert!(validate_run_args(&base_args()).is_ok());

        let mut dir_out = base_args();
        dir_out.out = Some(dir.0.clone());
        let err = validate_run_args(&dir_out).unwrap_err();
        assert!(err.contains("is a directory"), "{err}");

        let mut dir_raw = base_args();
        dir_raw.raw_log = Some(dir.0.clone());
        let err = validate_run_args(&dir_raw).unwrap_err();
        assert!(err.contains("is a directory"), "{err}");

        let mut bad_parent = base_args();
        bad_parent.out = Some(bios.join("nested.jsonl"));
        let err = validate_run_args(&bad_parent).unwrap_err();
        assert!(err.contains("is not a directory"), "{err}");

        // Two distinct paths pointing to the same hardlinked file must be rejected.
        let link_a = dir.0.join("link-a.log");
        let link_b = dir.0.join("link-b.log");
        fs::write(&link_a, b"existing").unwrap();
        fs::hard_link(&link_a, &link_b).unwrap();
        let mut hardlinked = base_args();
        hardlinked.out = Some(link_a.clone());
        hardlinked.raw_log = Some(link_b.clone());
        let err = validate_run_args(&hardlinked).unwrap_err();
        assert!(err.contains("same file"), "{err}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            // Dangling symlink pointing out -> nonexistent raw log must be rejected before creating raw log.
            let raw_target = dir.0.join("dangling-raw.log");
            let out_symlink = dir.0.join("dangling-out.jsonl");
            symlink(&raw_target, &out_symlink).unwrap();
            let mut dangling_args = base_args();
            dangling_args.out = Some(out_symlink.clone());
            dangling_args.raw_log = Some(raw_target.clone());
            let err = validate_run_args(&dangling_args).unwrap_err();
            assert!(err.contains("same file"), "{err}");
            let prep_err = match prepare_outputs(&out_symlink, Some(&raw_target)) {
                Ok(_) => panic!("expected prepare_outputs to reject dangling symlink alias"),
                Err(e) => e,
            };
            assert!(prep_err.contains("same file"), "{prep_err}");
            assert!(!raw_target.exists());

            // Reverse dangling symlink raw -> nonexistent out must also be rejected.
            let out_target = dir.0.join("dangling-target.jsonl");
            let raw_symlink = dir.0.join("dangling-raw-link.log");
            symlink(&out_target, &raw_symlink).unwrap();
            let mut rev_args = base_args();
            rev_args.out = Some(out_target.clone());
            rev_args.raw_log = Some(raw_symlink.clone());
            let err = validate_run_args(&rev_args).unwrap_err();
            assert!(err.contains("same file"), "{err}");

            // Chained dangling symlinks and cyclic symlink loops must be handled cleanly.
            let hop1 = dir.0.join("hop1.jsonl");
            let hop2 = dir.0.join("hop2.jsonl");
            symlink(&hop2, &hop1).unwrap();
            symlink(&raw_target, &hop2).unwrap();
            assert!(paths_refer_to_same_file(&hop1, &raw_target).unwrap());

            let loop_a = dir.0.join("loop-a");
            let loop_b = dir.0.join("loop-b");
            symlink(&loop_b, &loop_a).unwrap();
            symlink(&loop_a, &loop_b).unwrap();
            let loop_err = validate_output_file_path("--out", &loop_a).unwrap_err();
            assert!(loop_err.contains("symbolic links"), "{loop_err}");

            // Aliased directory symlink above uncreated subdirectories must be rejected before mkdir.
            let real_dir = dir.0.join("real-dir");
            fs::create_dir_all(&real_dir).unwrap();
            let alias_dir = dir.0.join("alias-dir");
            symlink(&real_dir, &alias_dir).unwrap();
            let aliased_out = alias_dir.join("sub1/sub2/shared.out");
            let aliased_raw = real_dir.join("sub1/sub2/shared.out");
            let mut sub_args = base_args();
            sub_args.out = Some(aliased_out.clone());
            sub_args.raw_log = Some(aliased_raw.clone());
            let err = validate_run_args(&sub_args).unwrap_err();
            assert!(err.contains("same file"), "{err}");
            let prep_err = match prepare_outputs(&aliased_out, Some(&aliased_raw)) {
                Ok(_) => panic!("expected prepare_outputs to reject aliased dir subpaths"),
                Err(e) => e,
            };
            assert!(prep_err.contains("same file"), "{prep_err}");
            assert!(!real_dir.join("sub1").exists());

            // Distinct filenames under aliased directories remain allowed.
            let distinct_raw = alias_dir.join("sub1/sub2/raw.log");
            assert!(prepare_outputs(&aliased_out, Some(&distinct_raw)).is_ok());

            // Mid-run symlink swap before final save must refuse to overwrite raw_log.
            let swap_raw = dir.0.join("swap-raw.log");
            let swap_out = dir.0.join("swap-out.jsonl");
            let mut swap_writer = Some(RawLogWriter::create(&swap_raw).unwrap());
            assert!(
                swap_writer
                    .as_mut()
                    .unwrap()
                    .write_line("untouched raw serial")
                    .is_none()
            );
            symlink(&swap_raw, &swap_out).unwrap();
            let errs = save_outputs_independently(&swap_out, Some("overwritten"), &mut swap_writer);
            assert_eq!(errs.len(), 1);
            assert!(errs[0].contains("refusing to overwrite"), "{errs:?}");
            assert_eq!(
                fs::read_to_string(&swap_raw).unwrap(),
                "untouched raw serial\n"
            );
        }

        // Interruption after END must classify as ShutdownStatus::Interrupted, never TimedOutAfterEnd.
        let mut tracker = AttemptTracker::new();
        let mut cap_state = CaptureState {
            frames: Vec::new(),
            quarantine_warnings: 0,
        };
        let _ = tracker.process_line(
            "@@MBENCH:END {\"checks_total\":0,\"checks_passed\":0,\"checks_skipped\":0,\"checks_failed\":0,\"check_assertions_total\":0,\"check_assertions_passed\":0,\"check_assertions_failed\":0,\"benches_total\":0,\"benches_passed\":0,\"benches_skipped\":0,\"benches_hw_native\":0,\"benches_delegated\":0,\"benches_failed\":0,\"quarantine_warnings\":0}",
            &mut cap_state,
        );
        assert_eq!(
            tracker.classify_shutdown(false, true, SessionExit::Killed),
            ShutdownStatus::Interrupted
        );
        assert_eq!(
            tracker.classify_shutdown(true, true, SessionExit::Killed),
            ShutdownStatus::Interrupted
        );

        // Failing to write one output must not skip flushing/saving the other output.
        let raw_ok = dir.0.join("independent.log");
        let mut writer = Some(RawLogWriter::create(&raw_ok).unwrap());
        assert!(
            writer
                .as_mut()
                .unwrap()
                .write_line("serial line 1")
                .is_none()
        );
        let errs = save_outputs_independently(&dir.0, Some("payload"), &mut writer);
        assert_eq!(errs.len(), 1);
        assert_eq!(fs::read_to_string(&raw_ok).unwrap(), "serial line 1\n");
    }
}
