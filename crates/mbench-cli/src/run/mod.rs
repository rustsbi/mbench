//! Attempt orchestration, capture aggregation, recovery, and final validation.

mod attempt;
mod build;
mod config;
mod output;
#[cfg(test)]
mod tests;

use std::path::Path;

use mbench_core::{
    protocol,
    record::StartKind,
    validate::{audit_capture, audit_raw_attempt, summarize_records},
    wire::{
        AttemptRecord, EnvLine, ShutdownStatus, StartFrame, parse_capture, shutdown_fail_reason,
        synthesize_fail_bench, synthesize_fail_check,
    },
};

pub(crate) use self::config::{RunArgs, execute};
use self::{
    attempt::{AttemptIo, AttemptOutcome, AttemptSpec, run_single_attempt},
    config::{
        build_bootargs, ensure_signal_handler, is_interrupted, reset_interrupted,
        resolve_effective_seed, resolve_label_and_out_path, timeout_duration,
    },
    output::{RawLogWriter, prepare_outputs, save_outputs_independently},
};
use crate::runner::{QemuVirtRunner, TargetLaunchConfig};

pub(in crate::run) const MAX_RECOVERY_ATTEMPTS: usize = 8;

pub(in crate::run) struct CaptureState {
    pub(in crate::run) frames: Vec<String>,
    pub(in crate::run) quarantine_warnings: usize,
}

pub(in crate::run) fn execute_with_qemu_runner(
    runner: &QemuVirtRunner,
    args: &RunArgs,
    kernel_path: &Path,
) -> Result<(), String> {
    reset_interrupted();
    ensure_signal_handler()?;

    let (label, out_path) = resolve_label_and_out_path(args);
    let mut raw_writer = prepare_outputs(&out_path, args.raw_log.as_deref())?;

    let effective_seed = resolve_effective_seed(args)?;

    let launch_template_cfg = TargetLaunchConfig {
        bios: &args.bios,
        kernel: kernel_path,
        smp: args.smp,
        icount: args.icount,
        bootargs: "",
        extra_args: &args.qemu_args,
        attempt: 0,
    };
    let env_line = EnvLine {
        clock_regime: runner.clock_regime(&launch_template_cfg),
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
            attempt,
        };
        let outcome = match run_single_attempt(
            AttemptSpec {
                runner,
                cfg: &launch_cfg,
                attempt,
                resume_after: current_resume.as_deref(),
                timeout: timeout_duration(args)?,
            },
            AttemptIo {
                state: &mut state,
                raw_writer: raw_writer.as_mut(),
                io_errors: &mut io_errors,
            },
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

        let (next_resume, synthesized) = recovery_decision(&outcome, attempt);
        let mut synth_ids = Vec::with_capacity(synthesized.len());
        for (stuck, reason) in synthesized {
            state.frames.push(synthesize_fail_frame(&stuck, reason)?);
            synth_ids.push(stuck.id);
        }

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
                synthesized_failures: synth_ids,
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

pub(in crate::run) fn render_frames(frames: &[String]) -> String {
    format!("{}\n", frames.join("\n"))
}

pub(in crate::run) fn format_interrupted_error(out_path: &Path, io_errors: &[String]) -> String {
    append_io_errors(
        format!(
            "interrupted by signal; saved partial capture to {}",
            out_path.display()
        ),
        io_errors,
    )
}

pub(in crate::run) fn append_io_errors(msg: String, io_errors: &[String]) -> String {
    if io_errors.is_empty() {
        msg
    } else {
        format!("{msg}\noutput errors:\n  - {}", io_errors.join("\n  - "))
    }
}

pub(in crate::run) fn record_attempt(
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

pub(in crate::run) fn append_unclosed_end_failures(
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

pub(in crate::run) fn finalize_merged_capture(
    label: &str,
    state: &mut CaptureState,
) -> Result<String, String> {
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

pub(in crate::run) fn synthesize_fail_frame(
    started: &StartFrame,
    reason: &str,
) -> Result<String, String> {
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

pub(in crate::run) fn recovery_decision(
    outcome: &AttemptOutcome,
    attempt: usize,
) -> (Option<String>, Vec<(StartFrame, &'static str)>) {
    if !outcome.stuck_cases.is_empty() {
        let reason = shutdown_fail_reason(&outcome.shutdown);
        let resume_id = outcome
            .stuck_cases
            .last()
            .expect("non-empty stuck_cases")
            .id
            .clone();
        let synthesized = outcome
            .stuck_cases
            .iter()
            .map(|stuck| {
                eprintln!(
                    "[mbench-cli] warning: '{}' (p={}) did not finish ({reason}); synthesizing FAIL (attempt {})",
                    stuck.id,
                    stuck.parallel,
                    attempt + 1
                );
                (stuck.clone(), reason)
            })
            .collect();
        (Some(resume_id), synthesized)
    } else if let Some(finished_id) = &outcome.last_completed_id {
        eprintln!(
            "[mbench-cli] warning: target stopped after '{finished_id}' ({:?}); resuming (attempt {})",
            outcome.shutdown,
            attempt + 1
        );
        (Some(finished_id.clone()), Vec::new())
    } else {
        (None, Vec::new())
    }
}
