//! Single-attempt protocol tracking, deadline handling, and outcome classification.

use std::time::{Duration, Instant};

use mbench_core::{
    record::{SbiExtensionId, SkipReason},
    validate::CaseTracker,
    wire::{ShutdownStatus, StartFrame, WireFrame, parse_wire_line},
};

use super::{CaptureState, config::is_interrupted, output::RawLogWriter};
use crate::runner::{
    QemuVirtRunner, QemuVirtSession, SessionEvent, SessionExit, TargetLaunchConfig,
};

const POST_END_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const POST_END_NO_SRST_GRACE: Duration = Duration::from_secs(1);

pub(super) struct AttemptOutcome {
    pub(super) raw_lines: Vec<String>,
    pub(super) saw_end: bool,
    pub(super) interrupted: bool,
    pub(super) shutdown: ShutdownStatus,
    pub(super) stuck_cases: Vec<StartFrame>,
    pub(super) unclosed_at_end: Vec<StartFrame>,
    pub(super) last_completed_id: Option<String>,
}

pub(super) enum LineAction {
    Continue,
    ArmCaseDeadline,
    RefreshPhaseIfIdle,
    ClearCaseAndRefreshPhase,
    ArmShutdownDeadline,
    StopSession,
}

pub(super) struct AttemptTracker {
    cases: CaseTracker,
    unclosed_at_end: Vec<StartFrame>,
    last_completed_id: Option<String>,
    pub(super) saw_srst: Option<bool>,
    saw_panic: bool,
    saw_end: bool,
}

impl AttemptTracker {
    pub(super) const fn new() -> Self {
        Self {
            cases: CaseTracker::new(),
            unclosed_at_end: Vec::new(),
            last_completed_id: None,
            saw_srst: None,
            saw_panic: false,
            saw_end: false,
        }
    }

    pub(super) fn process_line(&mut self, line: &str, state: &mut CaptureState) -> LineAction {
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

    pub(super) fn classify_shutdown(
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

    pub(super) fn into_outcome(
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
    event: SessionEvent,
    tracker: &mut AttemptTracker,
    state: &mut CaptureState,
    attempt_raw_lines: &mut Vec<String>,
    raw_writer: Option<&mut RawLogWriter>,
    io_errors: &mut Vec<String>,
) -> LineAction {
    let SessionEvent::Line { raw, text } = event else {
        return LineAction::Continue;
    };
    if let Some(writer) = raw_writer
        && let Some(err) = writer.write_bytes(&raw)
    {
        io_errors.push(err);
    }
    attempt_raw_lines.push(text.clone());
    tracker.process_line(&text, state)
}

pub(super) struct AttemptSpec<'a> {
    pub(super) runner: &'a QemuVirtRunner,
    pub(super) cfg: &'a TargetLaunchConfig<'a>,
    pub(super) attempt: usize,
    pub(super) resume_after: Option<&'a str>,
    pub(super) timeout: Duration,
}

pub(super) struct AttemptIo<'a> {
    pub(super) state: &'a mut CaptureState,
    pub(super) raw_writer: Option<&'a mut RawLogWriter>,
    pub(super) io_errors: &'a mut Vec<String>,
}

pub(super) fn run_single_attempt(
    spec: AttemptSpec<'_>,
    io: AttemptIo<'_>,
) -> Result<AttemptOutcome, String> {
    let AttemptSpec {
        runner,
        cfg,
        attempt,
        resume_after,
        timeout,
    } = spec;
    let AttemptIo {
        state,
        mut raw_writer,
        io_errors,
    } = io;
    let mut session: QemuVirtSession = runner.launch(cfg)?;
    if let Some(writer) = raw_writer.as_deref_mut()
        && let Some(err) = writer.write_attempt_header(attempt, resume_after)
    {
        io_errors.push(err);
    }
    let mut phase_deadline = checked_deadline(timeout)?;
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
            Ok(Some(event @ SessionEvent::Line { .. })) => {
                let action = record_and_handle_line(
                    event,
                    &mut tracker,
                    state,
                    &mut attempt_raw_lines,
                    raw_writer.as_deref_mut(),
                    io_errors,
                );
                match action {
                    LineAction::Continue => {}
                    LineAction::ArmCaseDeadline => case_deadline = Some(checked_deadline(timeout)?),
                    LineAction::RefreshPhaseIfIdle => {
                        if case_deadline.is_none() {
                            phase_deadline = checked_deadline(timeout)?;
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
                        phase_deadline = checked_deadline(grace)?;
                    }
                    LineAction::StopSession => {
                        stopped_early = true;
                        let _ = session.terminate_and_wait();
                        break;
                    }
                }
            }
            Ok(Some(SessionEvent::ReadError(err))) => {
                eprintln!("[mbench-cli] warning: {err}");
                io_errors.push(err);
                break;
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
        let exit_deadline = checked_deadline(exit_grace)?;
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

    // Drain any buffered serial lines delivered before the reader joined, bounded by count and wall time.
    const MAX_POST_EXIT_DRAIN_LINES: usize = 4096;
    const MAX_POST_EXIT_DRAIN_DURATION: Duration = Duration::from_millis(250);
    let drain_deadline = Instant::now() + MAX_POST_EXIT_DRAIN_DURATION;
    for _ in 0..MAX_POST_EXIT_DRAIN_LINES {
        if Instant::now() >= drain_deadline {
            break;
        }
        let Ok(Some(event @ SessionEvent::Line { .. })) = session.next_event(Duration::ZERO) else {
            break;
        };
        let _ = record_and_handle_line(
            event,
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

fn checked_deadline(duration: Duration) -> Result<Instant, String> {
    Instant::now()
        .checked_add(duration)
        .ok_or_else(|| String::from("timeout duration exceeds the monotonic clock range"))
}

fn push_normalized_wire_line(raw_line: &str, out: &mut Vec<String>) {
    if let Some(pos) = raw_line.find("@@MBENCH:") {
        out.push(raw_line[pos..].trim_end_matches(['\r', '\n']).to_string());
    }
}
