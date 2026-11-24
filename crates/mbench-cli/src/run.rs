//! Target orchestration with fixed-seed shuffle, per-case watchdog timeout, and crash recovery.

use std::{
    fs, io,
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::{Args, ValueEnum};
use mbench_core::{
    config::{OrderMode, Profile, RunMode},
    protocol,
    record::{BenchGroup, SbiExtensionId, SkipReason, StartKind},
    validate::{audit_capture, audit_raw_attempt, summarize_records},
    wire::{
        AttemptRecord, BenchFrame, BenchStatusTag, CheckFrame, CheckStatusTag, EnvLine,
        ShutdownStatus, StartFrame, WireFrame, parse_capture, parse_wire_line,
    },
};

use crate::runner::{
    QemuVirtRunner, SessionEvent, SessionExit, TargetLaunchConfig, TargetRunner, TargetSession,
};

const DEFAULT_TARGET: &str = "riscv64imac-unknown-none-elf";
const MAX_RECOVERY_ATTEMPTS: usize = 8;
const POST_END_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const POST_END_NO_SRST_GRACE: Duration = Duration::from_secs(1);

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
    if let (Some(out_path), Some(raw_log)) = (&args.out, &args.raw_log)
        && paths_refer_to_same_file(out_path, raw_log)?
    {
        return Err(format!(
            "--out ('{}') and --raw-log ('{}') must not refer to the same file",
            out_path.display(),
            raw_log.display()
        ));
    }
    Ok(())
}

fn resolve_comparable_path(path: &Path) -> Result<PathBuf, String> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("failed to resolve current directory: {e}"))?
            .join(path)
    };
    if let Ok(canonical) = fs::canonicalize(&abs) {
        return Ok(canonical);
    }
    if let (Some(parent), Some(file_name)) = (abs.parent(), abs.file_name())
        && parent.exists()
    {
        let canonical_parent = fs::canonicalize(parent)
            .map_err(|e| format!("failed to canonicalize {}: {e}", parent.display()))?;
        return Ok(canonical_parent.join(file_name));
    }
    let mut cleaned = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = cleaned.pop();
            }
            other => cleaned.push(other.as_os_str()),
        }
    }
    Ok(cleaned)
}

fn paths_refer_to_same_file(a: &Path, b: &Path) -> Result<bool, String> {
    Ok(resolve_comparable_path(a)? == resolve_comparable_path(b)?)
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

pub(crate) fn execute_with_runner<R: TargetRunner>(
    runner: &R,
    args: &RunArgs,
    kernel_path: &Path,
) -> Result<(), String> {
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
    if let Some(raw_log) = &args.raw_log
        && paths_refer_to_same_file(&out_path, raw_log)?
    {
        return Err(format!(
            "--out ('{}') and --raw-log ('{}') must not refer to the same file",
            out_path.display(),
            raw_log.display()
        ));
    }
    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }

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
        record_raw: args.raw_log.is_some(),
        raw_lines: Vec::new(),
    };

    let mut resume_after: Option<String> = None;
    let mut completed_loop = false;

    for attempt in 0..=MAX_RECOVERY_ATTEMPTS {
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
            Duration::from_secs(args.timeout.max(1)),
            &mut state,
        ) {
            Ok(outcome) => outcome,
            Err(err) => {
                persist_partial_outputs(&out_path, args.raw_log.as_deref(), &state);
                return Err(err);
            }
        };

        let protocol_errors = audit_raw_attempt(&outcome.raw_lines, outcome.saw_end);

        if outcome.saw_end {
            let synthesized = append_unclosed_end_failures(&outcome.unclosed_at_end, &mut state)?;
            push_attempt_record(
                &mut state,
                AttemptRecord {
                    attempt,
                    resume_after: current_resume,
                    saw_end: true,
                    shutdown: outcome.shutdown.clone(),
                    protocol_errors,
                    synthesized_failures: synthesized,
                },
            )?;
            completed_loop = true;
            break;
        }

        let (next_resume, synthesized) = if !outcome.stuck_cases.is_empty() {
            let reason = match outcome.shutdown {
                ShutdownStatus::TimedOutDuringRun => "timeout",
                _ => "crash",
            };
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

        push_attempt_record(
            &mut state,
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
            persist_partial_outputs(&out_path, args.raw_log.as_deref(), &state);
            return Err(format!(
                "target stopped ({:?}) before emitting @@MBENCH:END and no active case was recorded (saved outputs to {})",
                outcome.shutdown,
                out_path.display()
            ));
        };

        if current_resume.as_deref() == Some(next_resume_id.as_str()) {
            persist_partial_outputs(&out_path, args.raw_log.as_deref(), &state);
            return Err(format!(
                "recovery stalled on '{next_resume_id}' across consecutive attempts (saved outputs to {})",
                out_path.display()
            ));
        }
        resume_after = Some(next_resume_id);
    }

    if !completed_loop {
        persist_partial_outputs(&out_path, args.raw_log.as_deref(), &state);
        return Err(format!(
            "exceeded maximum recovery attempts ({MAX_RECOVERY_ATTEMPTS}) (saved outputs to {})",
            out_path.display()
        ));
    }

    let content = match finalize_merged_capture(&label, &mut state) {
        Ok(content) => content,
        Err(err) => {
            persist_partial_outputs(&out_path, args.raw_log.as_deref(), &state);
            return Err(err);
        }
    };
    fs::write(&out_path, &content)
        .map_err(|e| format!("failed to write {}: {e}", out_path.display()))?;
    eprintln!("[mbench-cli] saved {}", out_path.display());
    write_raw_log(args.raw_log.as_deref(), &state.raw_lines)?;

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
            "capture integrity check failed (saved to {}):\n  - {}",
            out_path.display(),
            errors.join("\n  - ")
        ))
    }
}

fn push_attempt_record(state: &mut CaptureState, record: AttemptRecord) -> Result<(), String> {
    let json = serde_json::to_string(&record).map_err(|e| e.to_string())?;
    state.frames.push(format!("# MBENCH_ATTEMPT {json}"));
    Ok(())
}

fn persist_partial_outputs(out_path: &Path, raw_log: Option<&Path>, state: &CaptureState) {
    if state.frames.len() > 1 {
        let partial = format!("{}\n", state.frames.join("\n"));
        if let Err(err) = fs::write(out_path, partial) {
            eprintln!(
                "[mbench-cli] warning: failed to save partial capture {}: {err}",
                out_path.display()
            );
        } else {
            eprintln!("[mbench-cli] saved partial capture {}", out_path.display());
        }
    }
    if let Err(err) = write_raw_log(raw_log, &state.raw_lines) {
        eprintln!("[mbench-cli] warning: {err}");
    }
}

fn write_raw_log(path: Option<&Path>, raw_lines: &[String]) -> Result<(), String> {
    let Some(path) = path else {
        return Ok(());
    };
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let mut text = raw_lines.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    fs::write(path, text).map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    eprintln!("[mbench-cli] saved raw log {}", path.display());
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
    let body = format!("{}\n", state.frames.join("\n"));
    let parsed = parse_capture(label, &body)
        .map_err(|e| format!("captured output failed wire validation: {e}"))?;
    let merged_end = summarize_records(&parsed.checks, &parsed.benches, state.quarantine_warnings);
    let mut end_line = String::new();
    protocol::write_end_line(&merged_end, &mut end_line)
        .map_err(|e| format!("failed to format END frame: {e}"))?;
    state.frames.push(end_line.trim_end().to_string());

    let content = format!("{}\n", state.frames.join("\n"));
    let _ = parse_capture(label, &content)
        .map_err(|e| format!("final capture failed wire validation: {e}"))?;
    Ok(content)
}

struct CaptureState {
    frames: Vec<String>,
    quarantine_warnings: usize,
    record_raw: bool,
    raw_lines: Vec<String>,
}

struct AttemptOutcome {
    raw_lines: Vec<String>,
    saw_end: bool,
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
    active_cases: Vec<StartFrame>,
    unclosed_at_end: Vec<StartFrame>,
    last_completed_id: Option<String>,
    saw_srst: Option<bool>,
    saw_panic: bool,
    saw_end: bool,
}

impl AttemptTracker {
    const fn new() -> Self {
        Self {
            active_cases: Vec::new(),
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
                let already_tracked = self.active_cases.iter().any(|s| {
                    s.kind == start.kind && s.id == start.id && s.parallel == start.parallel
                });
                if !already_tracked {
                    self.active_cases.push(start);
                }
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
                self.active_cases
                    .retain(|s| !(s.kind == StartKind::Check && s.id == chk.id));
                self.last_completed_id = Some(chk.id);
                push_normalized_wire_line(line, &mut state.frames);
                if self.active_cases.is_empty() {
                    LineAction::ClearCaseAndRefreshPhase
                } else {
                    LineAction::Continue
                }
            }
            Ok(Some(WireFrame::Bench(b))) => {
                if b.skip_reason == Some(SkipReason::ResumedPast) {
                    return LineAction::RefreshPhaseIfIdle;
                }
                self.active_cases.retain(|s| {
                    !(s.kind == StartKind::Bench && s.id == b.id && s.parallel == b.parallel)
                });
                self.last_completed_id = Some(b.id);
                push_normalized_wire_line(line, &mut state.frames);
                if self.active_cases.is_empty() {
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
                self.unclosed_at_end.append(&mut self.active_cases);
                LineAction::ArmShutdownDeadline
            }
            Ok(Some(WireFrame::Panic(_))) => {
                self.saw_panic = true;
                push_normalized_wire_line(line, &mut state.frames);
                println!("{line}");
                LineAction::StopSession
            }
            Ok(Some(WireFrame::Env(_) | WireFrame::Attempt(_))) => LineAction::Continue,
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

    fn classify_shutdown(&self, timed_out: bool, exit_status: SessionExit) -> ShutdownStatus {
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
        self,
        raw_lines: Vec<String>,
        timed_out: bool,
        exit_status: SessionExit,
    ) -> AttemptOutcome {
        let shutdown = self.classify_shutdown(timed_out, exit_status);
        let stuck_cases = if self.saw_end {
            Vec::new()
        } else {
            self.active_cases
        };
        AttemptOutcome {
            raw_lines,
            saw_end: self.saw_end,
            shutdown,
            stuck_cases,
            unclosed_at_end: self.unclosed_at_end,
            last_completed_id: self.last_completed_id,
        }
    }
}

fn run_single_attempt<R: TargetRunner>(
    runner: &R,
    cfg: &TargetLaunchConfig<'_>,
    timeout: Duration,
    state: &mut CaptureState,
) -> Result<AttemptOutcome, String> {
    let mut session = runner.launch(cfg)?;
    let mut phase_deadline = Instant::now() + timeout;
    let mut case_deadline: Option<Instant> = None;
    let mut tracker = AttemptTracker::new();
    let mut attempt_raw_lines = Vec::new();
    let mut timed_out = false;
    let mut stopped_early = false;

    loop {
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
            .min(Duration::from_millis(200));

        match session.next_event(wait_for) {
            Ok(Some(SessionEvent::Line(line))) => {
                if state.record_raw {
                    state.raw_lines.push(line.clone());
                }
                attempt_raw_lines.push(line.clone());
                match tracker.process_line(&line, state) {
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
        match session.wait_for_exit(exit_grace) {
            Ok(Some(exit)) => exit,
            Ok(None) => {
                timed_out = true;
                session.terminate_and_wait()
            }
            Err(err) => {
                let _ = session.terminate_and_wait();
                return Err(err);
            }
        }
    };
    Ok(tracker.into_outcome(attempt_raw_lines, timed_out, exit_status))
}

fn push_normalized_wire_line(raw_line: &str, out: &mut Vec<String>) {
    if let Some(pos) = raw_line.find("@@MBENCH:") {
        out.push(raw_line[pos..].trim_end_matches(['\r', '\n']).to_string());
    }
}

fn synthesize_fail_frame(started: &StartFrame, reason: &str) -> Result<String, String> {
    match started.kind {
        StartKind::Check => {
            let frame = CheckFrame {
                id: started.id.clone(),
                checks: 0,
                checks_total: 1,
                checks_failed: 1,
                status: CheckStatusTag::Fail,
                skip_reason: None,
                fail_reason: Some(reason.to_string()),
                quirks: 0,
                issues: Vec::new(),
                note: None,
                synthetic: true,
            };
            let json = serde_json::to_string(&frame).map_err(|e| e.to_string())?;
            Ok(format!("@@MBENCH:CHECK {json}"))
        }
        StartKind::Bench => {
            let frame = BenchFrame {
                id: started.id.clone(),
                group: infer_bench_group(&started.id),
                mode: None,
                parallel: started.parallel,
                unit: String::from("op"),
                iters_per_trial: 0,
                trials: 0,
                status: BenchStatusTag::Fail,
                skip_reason: None,
                fail_reason: Some(reason.to_string()),
                cycles: None,
                instret: None,
                ticks: None,
                ns: None,
                throughput_ops_per_sec: None,
                note: None,
                synthetic: true,
                cal_index: None,
            };
            let json = serde_json::to_string(&frame).map_err(|e| e.to_string())?;
            Ok(format!("@@MBENCH:BENCH {json}"))
        }
    }
}

fn infer_bench_group(id: &str) -> BenchGroup {
    let prefix = id.split_once('/').map_or(id, |(head, _)| head);
    match prefix {
        "baseline" => BenchGroup::Baseline,
        "trap" => BenchGroup::TrapEmul,
        "base" => BenchGroup::Base,
        "time" => BenchGroup::Time,
        "spi" => BenchGroup::Spi,
        "rfnc" => BenchGroup::Rfnc,
        "hsm" => BenchGroup::Hsm,
        "srst" => BenchGroup::Srst,
        "pmu" => BenchGroup::Pmu,
        "dbcn" => BenchGroup::Dbcn,
        "susp" => BenchGroup::Susp,
        "cppc" => BenchGroup::Cppc,
        "nacl" => BenchGroup::Nacl,
        "sta" => BenchGroup::Sta,
        "sse" => BenchGroup::Sse,
        "fwft" => BenchGroup::Fwft,
        "dbtr" => BenchGroup::Dbtr,
        "mpxy" => BenchGroup::Mpxy,
        "scale" => BenchGroup::Scale,
        _ => BenchGroup::Baseline,
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use mbench_core::{config::ClockRegime, protocol::write_cal_line, record::CalibrationRecord};

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
                cal0.trim().to_string(),
                check_line,
                sweep_p1,
                "@@MBENCH:META {\"sbi_spec_version\":50331648,\"impl_id\":1,\"impl_version\":1,\"mvendorid\":0,\"marchid\":0,\"mimpid\":0,\"extensions\":[\"base\"],\"extensions_mask\":1,\"hart_count\":2,\"boot_hart_id\":0,\"timebase_hz\":10000000,\"has_cycle\":true,\"has_instret\":true,\"has_time\":true,\"is_rdtime_emulated\":false,\"is_pmu_gated\":false,\"has_sstc\":false,\"has_h_ext\":false,\"boot_ticks\":1,\"reserved_mem_bytes\":0,\"console_backend\":\"dbcn\",\"pmu_counter_count\":0,\"load_addr\":2149580800}".to_string(),
                cal1.trim().to_string(),
                sweep_p2_fail,
            ],
            quarantine_warnings: 2,
            record_raw: false,
            raw_lines: Vec::new(),
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
            record_raw: false,
            raw_lines: Vec::new(),
        };
        let mut tracker = AttemptTracker::new();
        for line in lines {
            let _ = tracker.process_line(line, &mut state);
        }
        let raw_vec: Vec<String> = lines.iter().map(|s| (*s).to_string()).collect();
        let outcome = tracker.into_outcome(raw_vec, false, SessionExit::Exited(Some(0)));
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
    fn validates_run_args_and_rejects_colliding_output_paths() {
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

        let mut bad_timeout = base_args();
        bad_timeout.timeout = 0;
        assert!(validate_run_args(&bad_timeout).is_err());

        let mut empty_filter = base_args();
        empty_filter.filter = Some(String::new());
        assert!(validate_run_args(&empty_filter).is_err());

        let mut space_filter = base_args();
        space_filter.filter = Some(String::from("base/ time/"));
        assert!(validate_run_args(&space_filter).is_err());

        let mut empty_name = base_args();
        empty_name.name = Some(String::from("   "));
        assert!(validate_run_args(&empty_name).is_err());

        let mut path_name = base_args();
        path_name.name = Some(String::from("../escape"));
        assert!(validate_run_args(&path_name).is_err());

        let mut missing_kernel = base_args();
        missing_kernel.kernel = Some(dir.0.join("missing-kernel.bin"));
        assert!(validate_run_args(&missing_kernel).is_err());

        let mut colliding = base_args();
        colliding.out = Some(dir.0.join("sub/../out.log"));
        colliding.raw_log = Some(dir.0.join("out.log"));
        let err = validate_run_args(&colliding).unwrap_err();
        assert!(err.contains("same file"));

        let mut non_colliding = base_args();
        non_colliding.out = Some(dir.0.join("out.jsonl"));
        non_colliding.raw_log = Some(dir.0.join("out.log"));
        assert!(validate_run_args(&non_colliding).is_ok());
    }
}
