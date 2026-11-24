//! Target orchestration with fixed-seed shuffle, per-case watchdog timeout, and crash recovery.

use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::{Args, ValueEnum};
use mbench_core::{
    config::{OrderMode, Profile, RunMode},
    protocol,
    record::{BenchGroup, EndRecord, SkipReason, StartKind},
    validate::{ValidationPolicy, validate_capture},
    wire::{
        BenchFrame, BenchStatusTag, CheckFrame, CheckStatusTag, EnvLine, ParsedCapture, StartFrame,
        WireFrame, parse_capture, parse_wire_line,
    },
};

use crate::{
    runner::{
        QemuVirtRunner, SessionEvent, SessionExit, TargetLaunchConfig, TargetRunner, TargetSession,
    },
    validate::PolicyArgs,
};

const DEFAULT_TARGET: &str = "riscv64imac-unknown-none-elf";
const MAX_RECOVERY_ATTEMPTS: usize = 8;
const POST_END_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

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

    /// Enforce capture completeness, clean QEMU exit, zero failures, and policy gates.
    #[arg(long, default_value_t = false)]
    pub(crate) strict: bool,

    #[command(flatten)]
    pub(crate) validation: PolicyArgs,
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
    let _ = args.validation.to_policy()?;
    Ok(())
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
    let policy = args.validation.to_policy()?;
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
        record_raw: args.raw_log.is_some() || !policy.forbidden_patterns.is_empty(),
        raw_lines: Vec::new(),
    };

    let mut resume_after: Option<String> = None;
    let mut final_outcome: Option<AttemptOutcome> = None;

    for attempt in 0..=MAX_RECOVERY_ATTEMPTS {
        let bootargs = build_bootargs(args, effective_seed, resume_after.as_deref());
        let launch_cfg = TargetLaunchConfig {
            bios: &args.bios,
            kernel: kernel_path,
            smp: args.smp,
            icount: args.icount,
            bootargs: &bootargs,
            extra_args: &args.qemu_args,
        };
        let outcome = run_single_attempt(
            runner,
            &launch_cfg,
            Duration::from_secs(args.timeout.max(1)),
            &mut state,
        )?;

        if outcome.saw_end {
            append_unclosed_end_failures(&outcome.unclosed_at_end, &mut state)?;
            final_outcome = Some(outcome);
            break;
        }

        let next_resume = if !outcome.stuck_cases.is_empty() {
            let reason = if outcome.timed_out {
                "timeout"
            } else {
                "crash"
            };
            let resume_id = outcome
                .stuck_cases
                .last()
                .expect("non-empty stuck_cases")
                .id
                .clone();
            for stuck in &outcome.stuck_cases {
                eprintln!(
                    "[mbench-cli] warning: '{}' (p={}) failed ({reason}); synthesizing FAIL (attempt {})",
                    stuck.id,
                    stuck.parallel,
                    attempt + 1
                );
                state.frames.push(synthesize_fail_frame(stuck, reason)?);
            }
            resume_id
        } else if let Some(finished_id) = outcome.last_completed_id {
            eprintln!(
                "[mbench-cli] warning: target exited after '{finished_id}' ({}); resuming (attempt {})",
                outcome.exit_status,
                attempt + 1
            );
            finished_id
        } else {
            write_raw_log(args.raw_log.as_deref(), &state.raw_lines)?;
            return Err(format!(
                "target exited ({}) before emitting @@MBENCH:END and no active case was recorded",
                outcome.exit_status
            ));
        };

        if resume_after.as_deref() == Some(next_resume.as_str()) {
            write_raw_log(args.raw_log.as_deref(), &state.raw_lines)?;
            return Err(format!(
                "recovery stalled on '{next_resume}' across consecutive attempts"
            ));
        }
        resume_after = Some(next_resume);
    }

    let Some(outcome) = final_outcome else {
        write_raw_log(args.raw_log.as_deref(), &state.raw_lines)?;
        return Err(format!(
            "exceeded maximum recovery attempts ({MAX_RECOVERY_ATTEMPTS})"
        ));
    };

    let content = finalize_merged_capture(&label, &mut state)?;
    fs::write(&out_path, &content)
        .map_err(|e| format!("failed to write {}: {e}", out_path.display()))?;
    eprintln!("[mbench-cli] saved {}", out_path.display());
    write_raw_log(args.raw_log.as_deref(), &state.raw_lines)?;

    if outcome.timed_out || !outcome.exit_status.is_clean_zero() {
        return Err(format!(
            "target did not shut down cleanly after @@MBENCH:END (timed_out={}, exit={}); saved capture to {}",
            outcome.timed_out,
            outcome.exit_status,
            out_path.display()
        ));
    }

    if args.strict {
        validate_strict_result(&content, &state.raw_lines, &policy, &out_path)?;
    }

    Ok(())
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

fn validate_strict_result(
    merged_jsonl: &str,
    raw_lines: &[String],
    policy: &ValidationPolicy,
    out_path: &Path,
) -> Result<(), String> {
    let mut raw_errors = Vec::new();
    for (idx, line) in raw_lines.iter().enumerate() {
        for pat in &policy.forbidden_patterns {
            if !pat.is_empty() && line.contains(pat.as_str()) {
                raw_errors.push(format!(
                    "forbidden pattern '{pat}' matched in raw serial output at line {}: {}",
                    idx + 1,
                    line.trim()
                ));
            }
        }
    }

    let merged_policy = ValidationPolicy {
        require_closed_starts: false,
        forbidden_patterns: Vec::new(),
        ..policy.clone()
    };

    if let Err(mut errs) = validate_capture(merged_jsonl, &merged_policy) {
        raw_errors.append(&mut errs);
    }

    if raw_errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "strict capture validation failed (capture saved to {}):\n  - {}",
            out_path.display(),
            raw_errors.join("\n  - ")
        ))
    }
}

fn append_unclosed_end_failures(
    unclosed: &[StartFrame],
    state: &mut CaptureState,
) -> Result<(), String> {
    for entry in unclosed {
        eprintln!(
            "[mbench-cli] warning: '{}' (p={}) opened before END without a valid result frame; synthesizing FAIL(protocol_error)",
            entry.id, entry.parallel,
        );
        state
            .frames
            .push(synthesize_fail_frame(entry, "protocol_error")?);
    }
    Ok(())
}

fn finalize_merged_capture(label: &str, state: &mut CaptureState) -> Result<String, String> {
    let body = format!("{}\n", state.frames.join("\n"));
    let parsed = parse_capture(label, &body)
        .map_err(|e| format!("captured output failed wire validation: {e}"))?;
    let merged_end = compute_merged_end_record(&parsed, state.quarantine_warnings);
    let mut end_line = String::new();
    protocol::write_end_line(&merged_end, &mut end_line)
        .map_err(|e| format!("failed to format END frame: {e}"))?;
    state.frames.push(end_line.trim_end().to_string());

    let content = format!("{}\n", state.frames.join("\n"));
    let _ = parse_capture(label, &content)
        .map_err(|e| format!("final capture failed wire validation: {e}"))?;
    Ok(content)
}

fn compute_merged_end_record(cap: &ParsedCapture, quarantine_warnings: usize) -> EndRecord {
    let mut end = EndRecord {
        quarantine_warnings,
        ..EndRecord::default()
    };
    for chk in &cap.checks {
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
    for bench in &cap.benches {
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

struct CaptureState {
    frames: Vec<String>,
    quarantine_warnings: usize,
    record_raw: bool,
    raw_lines: Vec<String>,
}

struct AttemptOutcome {
    saw_end: bool,
    timed_out: bool,
    exit_status: SessionExit,
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
    saw_end: bool,
}

impl AttemptTracker {
    const fn new() -> Self {
        Self {
            active_cases: Vec::new(),
            unclosed_at_end: Vec::new(),
            last_completed_id: None,
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
            Ok(Some(WireFrame::Meta(_) | WireFrame::Cal(_))) => {
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
                push_normalized_wire_line(line, &mut state.frames);
                println!("{line}");
                LineAction::StopSession
            }
            Ok(Some(WireFrame::Env(_))) => LineAction::Continue,
            Ok(None) => {
                println!("{line}");
                LineAction::Continue
            }
            Err(err) => {
                eprintln!("[mbench-cli] warning: ignoring malformed wire line: {err}");
                println!("{line}");
                LineAction::Continue
            }
        }
    }

    fn into_outcome(self, timed_out: bool, exit_status: SessionExit) -> AttemptOutcome {
        let stuck_cases = if self.saw_end {
            Vec::new()
        } else {
            self.active_cases
        };
        AttemptOutcome {
            saw_end: self.saw_end,
            timed_out,
            exit_status,
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

        match session.next_event(wait_for)? {
            Some(SessionEvent::Line(line)) => {
                if state.record_raw {
                    state.raw_lines.push(line.clone());
                }
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
                        phase_deadline = Instant::now() + timeout.min(POST_END_SHUTDOWN_TIMEOUT);
                    }
                    LineAction::StopSession => {
                        stopped_early = true;
                        let _ = session.terminate_and_wait();
                        break;
                    }
                }
            }
            Some(SessionEvent::Eof) => break,
            None => {}
        }
    }

    let exit_status = if stopped_early {
        session.terminate_and_wait()
    } else if let Some(exit) = session.wait_for_exit(timeout.min(POST_END_SHUTDOWN_TIMEOUT))? {
        exit
    } else {
        timed_out = true;
        session.terminate_and_wait()
    };
    Ok(tracker.into_outcome(timed_out, exit_status))
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

fn build_bootargs(args: &RunArgs, seed: Option<u64>, resume_after: Option<&str>) -> String {
    let mut parts = vec![
        format!("mode={}", args.mode.into_core().as_str()),
        format!("profile={}", args.profile.into_core().as_str()),
        format!("order={}", args.order.into_core().as_str()),
    ];
    if let Some(seed_val) = seed {
        parts.push(format!("seed={seed_val:#x}"));
    }
    if let Some(filter) = &args.filter {
        parts.push(format!("filter={filter}"));
    }
    if args.io {
        parts.push(String::from("io=1"));
    }
    if args.destructive {
        parts.push(String::from("destructive=1"));
    }
    if let Some(max_harts) = args.max_harts {
        parts.push(format!("max_harts={max_harts}"));
    }
    if let Some(id) = resume_after {
        parts.push(format!("resume_after={id}"));
    }
    parts.join(" ")
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
    use std::{
        collections::VecDeque,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

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

    struct FakeAttempt {
        events: VecDeque<SessionEvent>,
        natural_exit: Option<SessionExit>,
    }

    struct FakeRunner {
        attempts: Mutex<VecDeque<FakeAttempt>>,
    }

    impl FakeRunner {
        fn new(attempts: Vec<FakeAttempt>) -> Self {
            Self {
                attempts: Mutex::new(attempts.into()),
            }
        }
    }

    struct FakeSession {
        events: VecDeque<SessionEvent>,
        natural_exit: Option<SessionExit>,
        exit: Option<SessionExit>,
    }

    impl TargetRunner for FakeRunner {
        type Session = FakeSession;

        fn clock_regime(&self, _cfg: &TargetLaunchConfig<'_>) -> ClockRegime {
            ClockRegime::QemuTcgNonCycleAccurate
        }

        fn launch(&self, _cfg: &TargetLaunchConfig<'_>) -> Result<Self::Session, String> {
            let attempt = self
                .attempts
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra launch attempt");
            Ok(FakeSession {
                events: attempt.events,
                natural_exit: attempt.natural_exit,
                exit: None,
            })
        }
    }

    impl TargetSession for FakeSession {
        fn next_event(&mut self, _timeout: Duration) -> Result<Option<SessionEvent>, String> {
            Ok(self.events.pop_front())
        }

        fn wait_for_exit(&mut self, _timeout: Duration) -> Result<Option<SessionExit>, String> {
            if let Some(exit) = self.exit {
                return Ok(Some(exit));
            }
            if let Some(exit) = self.natural_exit {
                self.exit = Some(exit);
                return Ok(Some(exit));
            }
            Ok(None)
        }

        fn terminate_and_wait(&mut self) -> SessionExit {
            if let Some(exit) = self.exit {
                return exit;
            }
            let exit = self.natural_exit.unwrap_or(SessionExit::Killed);
            self.exit = Some(exit);
            exit
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
            strict: false,
            validation: PolicyArgs::default(),
        }
    }

    const META_4_HARTS: &str = "@@MBENCH:META {\"sbi_spec_version\":33554432,\"impl_id\":4,\"impl_version\":1,\"mvendorid\":0,\"marchid\":0,\"mimpid\":0,\"extensions\":[\"base\",\"time\",\"hsm\"],\"extensions_mask\":19,\"hart_count\":4,\"boot_hart_id\":0,\"timebase_hz\":10000000,\"has_cycle\":true,\"has_instret\":true,\"has_time\":true,\"is_rdtime_emulated\":false,\"is_pmu_gated\":false,\"has_sstc\":true,\"has_h_ext\":true,\"boot_ticks\":1,\"reserved_mem_bytes\":0,\"console_backend\":\"dbcn\",\"pmu_counter_count\":0,\"load_addr\":2149580800}";
    const END_ONE_PASS: &str = "@@MBENCH:END {\"checks_total\":1,\"checks_passed\":1,\"checks_skipped\":0,\"checks_failed\":0,\"check_assertions_total\":5,\"check_assertions_passed\":5,\"check_assertions_failed\":0,\"benches_total\":0,\"benches_passed\":0,\"benches_skipped\":0,\"benches_hw_native\":0,\"benches_delegated\":0,\"benches_failed\":0,\"quarantine_warnings\":0}";

    #[test]
    fn builds_bootargs_synthesizes_parallel_fails_and_recomputes_merged_end() {
        let mut args = base_test_args(None);
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
        assert_eq!(cap.benches.len(), 2);
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
        let outcome = tracker.into_outcome(false, SessionExit::Exited(Some(0)));
        assert!(outcome.saw_end);
        assert_eq!(outcome.unclosed_at_end.len(), 1);
        assert_eq!(outcome.unclosed_at_end[0].id, "conformance/base");
        append_unclosed_end_failures(&outcome.unclosed_at_end, &mut state).unwrap();
        let merged = finalize_merged_capture("fw", &mut state).unwrap();
        let cap = parse_capture("fw", &merged).unwrap();
        assert_eq!(cap.checks.len(), 1);
        assert_eq!(cap.checks[0].status, CheckStatusTag::Fail);
        assert_eq!(cap.checks[0].fail_reason.as_deref(), Some("protocol_error"));
        let end = cap.end.unwrap();
        assert_eq!(end.checks_total, 1);
        assert_eq!(end.checks_failed, 1);
    }

    #[test]
    fn validates_run_args_and_refreshes_phase_on_resumed_past() {
        let existing_file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let base_args = || {
            let mut a = base_test_args(None);
            a.bios = existing_file.clone();
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

        let mut path_name_with_out = base_args();
        path_name_with_out.name = Some(String::from("group/label"));
        path_name_with_out.out = Some(PathBuf::from("out.jsonl"));
        assert!(validate_run_args(&path_name_with_out).is_ok());

        let mut missing_kernel = base_args();
        missing_kernel.kernel = Some(existing_file.with_file_name("missing-kernel.bin"));
        assert!(validate_run_args(&missing_kernel).is_err());

        let mut tracker = AttemptTracker::new();
        let mut state = CaptureState {
            frames: Vec::new(),
            quarantine_warnings: 0,
            record_raw: false,
            raw_lines: Vec::new(),
        };
        let chk_resumed = "@@MBENCH:CHECK {\"id\":\"conformance/base\",\"checks\":0,\"checks_total\":0,\"status\":\"SKIPPED\",\"skip_reason\":\"resumed_past\"}";
        assert!(matches!(
            tracker.process_line(chk_resumed, &mut state),
            LineAction::RefreshPhaseIfIdle
        ));
        let bench_resumed = "@@MBENCH:BENCH {\"id\":\"base/get_spec_version\",\"group\":\"base\",\"parallel\":1,\"unit\":\"call\",\"iters_per_trial\":0,\"trials\":0,\"status\":\"SKIPPED\",\"skip_reason\":\"resumed_past\"}";
        assert!(matches!(
            tracker.process_line(bench_resumed, &mut state),
            LineAction::RefreshPhaseIfIdle
        ));
        assert!(state.frames.is_empty());
    }

    #[test]
    fn enforces_clean_exit_and_strict_validation_after_saving_outputs() {
        let dir = TestWorkDir::new("runner");
        let kernel = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");

        let pass_events = || {
            VecDeque::from([
                SessionEvent::Line(META_4_HARTS.to_string()),
                SessionEvent::Line(String::from(
                    "@@MBENCH:START {\"kind\":\"check\",\"id\":\"conformance/base\",\"parallel\":1}",
                )),
                SessionEvent::Line(String::from(
                    "@@MBENCH:CHECK {\"id\":\"conformance/base\",\"checks\":5,\"checks_total\":5,\"checks_failed\":0,\"status\":\"PASS\"}",
                )),
                SessionEvent::Line(END_ONE_PASS.to_string()),
                SessionEvent::Eof,
            ])
        };

        // 1. Hang after END must fail even though END arrived, after writing .jsonl.
        let out_hang = dir.0.join("hang.jsonl");
        let runner = FakeRunner::new(vec![FakeAttempt {
            events: pass_events(),
            natural_exit: None,
        }]);
        let args = base_test_args(Some(out_hang.clone()));
        let err = execute_with_runner(&runner, &args, &kernel).unwrap_err();
        assert!(err.contains("did not shut down cleanly"));
        assert!(out_hang.exists());

        // 2. Non-zero exit after END must fail, after writing .jsonl.
        let out_nonzero = dir.0.join("nonzero.jsonl");
        let runner = FakeRunner::new(vec![FakeAttempt {
            events: pass_events(),
            natural_exit: Some(SessionExit::Exited(Some(2))),
        }]);
        let args = base_test_args(Some(out_nonzero.clone()));
        let err = execute_with_runner(&runner, &args, &kernel).unwrap_err();
        assert!(err.contains("exit code 2"));
        assert!(out_nonzero.exists());

        // 3. Recovery followed by clean second boot must fail in --strict mode because earlier case failed.
        let out_recovered = dir.0.join("recovered.jsonl");
        let raw_recovered = dir.0.join("recovered.log");
        let runner = FakeRunner::new(vec![
            FakeAttempt {
                events: VecDeque::from([
                    SessionEvent::Line(META_4_HARTS.to_string()),
                    SessionEvent::Line(String::from(
                        "@@MBENCH:START {\"kind\":\"check\",\"id\":\"conformance/time\",\"parallel\":1}",
                    )),
                    SessionEvent::Eof,
                ]),
                natural_exit: Some(SessionExit::Exited(Some(1))),
            },
            FakeAttempt {
                events: VecDeque::from([
                    SessionEvent::Line(META_4_HARTS.to_string()),
                    SessionEvent::Line(String::from(
                        "@@MBENCH:CHECK {\"id\":\"conformance/time\",\"checks\":0,\"checks_total\":0,\"status\":\"SKIPPED\",\"skip_reason\":\"resumed_past\"}",
                    )),
                    SessionEvent::Line(String::from(
                        "@@MBENCH:START {\"kind\":\"check\",\"id\":\"conformance/base\",\"parallel\":1}",
                    )),
                    SessionEvent::Line(String::from(
                        "@@MBENCH:CHECK {\"id\":\"conformance/base\",\"checks\":5,\"checks_total\":5,\"checks_failed\":0,\"status\":\"PASS\"}",
                    )),
                    SessionEvent::Line(END_ONE_PASS.to_string()),
                    SessionEvent::Eof,
                ]),
                natural_exit: Some(SessionExit::Exited(Some(0))),
            },
        ]);
        let mut args = base_test_args(Some(out_recovered.clone()));
        args.raw_log = Some(raw_recovered.clone());
        args.strict = true;
        args.validation.expect_harts = Some(4);
        args.validation.require_check_pass = vec![String::from("conformance/base")];
        let err = execute_with_runner(&runner, &args, &kernel).unwrap_err();
        assert!(err.contains("conformance/time"));
        assert!(out_recovered.exists());
        assert!(raw_recovered.exists());

        // 4. Clean strict pass succeeds and saves both outputs.
        let out_ok = dir.0.join("ok.jsonl");
        let raw_ok = dir.0.join("ok.log");
        let runner = FakeRunner::new(vec![FakeAttempt {
            events: pass_events(),
            natural_exit: Some(SessionExit::Exited(Some(0))),
        }]);
        let mut args = base_test_args(Some(out_ok.clone()));
        args.raw_log = Some(raw_ok.clone());
        args.strict = true;
        args.validation.expect_harts = Some(4);
        args.validation.require_ext = vec![String::from("base"), String::from("hsm")];
        args.validation.require_check_pass = vec![String::from("conformance/base")];
        args.validation.max_quarantine_warnings = Some(0);
        execute_with_runner(&runner, &args, &kernel).unwrap();
        assert!(out_ok.exists());
        assert!(raw_ok.exists());
    }
}
