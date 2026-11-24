//! Concrete QEMU `virt` runner, active-session reaping, and serial-stream ownership.

use std::{
    fmt,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use mbench_core::config::ClockRegime;

mod serial;
#[cfg(test)]
mod tests;

use self::serial::SerialReader;

const CLEANUP_POLL: Duration = Duration::from_millis(10);
const READER_COMPLETION_TIMEOUT: Duration = Duration::from_millis(250);

/// Final OS exit status observed for a target session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionExit {
    Exited(Option<i32>),
    Killed,
}

impl fmt::Display for SessionExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited(Some(code)) => write!(f, "exit code {code}"),
            Self::Exited(None) => f.write_str("terminated by signal"),
            Self::Killed => f.write_str("killed after timeout or abort"),
        }
    }
}

/// Line or EOF event received from a running target serial stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SessionEvent {
    Line { raw: Vec<u8>, text: String },
    ReadError(String),
    Eof,
}

/// Target launch parameters independent of host transport backend.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TargetLaunchConfig<'a> {
    pub(crate) bios: &'a Path,
    pub(crate) kernel: &'a Path,
    pub(crate) smp: usize,
    pub(crate) icount: bool,
    pub(crate) bootargs: &'a str,
    pub(crate) extra_args: &'a [String],
    pub(crate) attempt: usize,
}

/// QEMU `virt` machine backend launching `qemu-system-riscv64`.
#[derive(Clone, Debug)]
pub(crate) struct QemuVirtRunner {
    pub(crate) qemu_bin: String,
}

impl QemuVirtRunner {
    pub(crate) fn clock_regime(&self, cfg: &TargetLaunchConfig<'_>) -> ClockRegime {
        if cfg.icount {
            ClockRegime::QemuIcount
        } else {
            ClockRegime::QemuTcgNonCycleAccurate
        }
    }

    pub(crate) fn launch(&self, cfg: &TargetLaunchConfig<'_>) -> Result<QemuVirtSession, String> {
        let mut cmd = Command::new(&self.qemu_bin);
        cmd.arg("-machine")
            .arg("virt")
            .arg("-nographic")
            .arg("-bios")
            .arg(cfg.bios)
            .arg("-kernel")
            .arg(cfg.kernel)
            .arg("-smp")
            .arg(cfg.smp.to_string())
            .arg("-append")
            .arg(cfg.bootargs);

        if cfg.icount {
            cmd.arg("-icount")
                .arg("shift=0,sleep=off")
                .arg("-accel")
                .arg("tcg,thread=single");
        }
        for extra in cfg.extra_args {
            cmd.arg(extra);
        }

        configure_child(&mut cmd);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn {}: {e}", self.qemu_bin))?;
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                reap_after_failed_launch(&mut child);
                return Err(String::from("missing QEMU stdout pipe"));
            }
        };

        let (rx, reader, done_rx) = QemuVirtSession::spawn_serial_reader(stdout, cfg.attempt);
        Ok(QemuVirtSession::new(child, rx, reader, done_rx))
    }
}

fn reap_after_failed_launch(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Active `qemu-system-riscv64` process with bounded RAII cleanup guarantees.
pub(crate) struct QemuVirtSession {
    child: Child,
    rx: Receiver<SessionEvent>,
    reader: Option<JoinHandle<()>>,
    serial_done: Receiver<()>,
    exit: Option<SessionExit>,
}

impl QemuVirtSession {
    #[cfg(test)]
    fn child_exit_status(&self) -> Option<SessionExit> {
        self.exit
    }

    #[cfg(test)]
    fn reader_joined(&self) -> bool {
        self.reader.is_none()
    }

    fn new(
        child: Child,
        rx: Receiver<SessionEvent>,
        reader: JoinHandle<()>,
        serial_done: Receiver<()>,
    ) -> Self {
        Self {
            child,
            rx,
            reader: Some(reader),
            serial_done,
            exit: None,
        }
    }

    /// Waits briefly for serial-thread completion without requiring inherited-pipe EOF.
    fn spawn_serial_reader(
        stdout: std::process::ChildStdout,
        attempt: usize,
    ) -> (Receiver<SessionEvent>, JoinHandle<()>, Receiver<()>) {
        let (tx, rx) = mpsc::channel::<SessionEvent>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let reader = thread::spawn(move || {
            let _done_guard = done_tx;
            let mut serial = SerialReader::new(stdout, attempt, "qemu-stdout");
            loop {
                match serial.next_line() {
                    Ok(Some(line)) => {
                        if tx
                            .send(SessionEvent::Line {
                                raw: line.raw,
                                text: line.text,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = tx.send(SessionEvent::Eof);
                        break;
                    }
                    Err(err) => {
                        let _ = tx.send(SessionEvent::ReadError(err));
                        let _ = tx.send(SessionEvent::Eof);
                        break;
                    }
                }
            }
        });
        (rx, reader, done_rx)
    }

    fn finish_reader(&mut self) {
        if self.reader.is_none() {
            return;
        }
        let _ = self.serial_done.recv_timeout(READER_COMPLETION_TIMEOUT);
        self.join_finished_reader();
    }

    fn join_finished_reader(&mut self) {
        if self.reader.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(handle) = self.reader.take()
        {
            let _ = handle.join();
        }
    }

    fn record_exit(&mut self, status: ExitStatus) -> SessionExit {
        let exit = SessionExit::Exited(status.code());
        self.exit = Some(exit);
        self.finish_reader();
        exit
    }

    fn reap_killed_child(&mut self) -> SessionExit {
        // `kill` has been requested; always reap the direct child before returning.
        let _ = self.child.wait();
        let exit = SessionExit::Killed;
        self.exit = Some(exit);
        self.finish_reader();
        exit
    }

    pub(crate) fn next_event(&mut self, timeout: Duration) -> Result<Option<SessionEvent>, String> {
        match self.rx.recv_timeout(timeout) {
            Ok(ev) => Ok(Some(ev)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Ok(Some(SessionEvent::Eof)),
        }
    }

    pub(crate) fn wait_for_exit(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<SessionExit>, String> {
        if let Some(exit) = self.exit {
            self.finish_reader();
            return Ok(Some(exit));
        }

        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Ok(Some(self.record_exit(status))),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    thread::sleep(CLEANUP_POLL);
                }
                Err(err) => return Err(format!("failed waiting for QEMU exit: {err}")),
            }
        }
    }

    pub(crate) fn terminate_and_wait(&mut self) -> SessionExit {
        if let Some(exit) = self.exit {
            self.finish_reader();
            return exit;
        }
        match self.child.try_wait() {
            Ok(Some(status)) => self.record_exit(status),
            Ok(None) | Err(_) => {
                let pgid = self.child.id();
                if let Err(err) = self.child.kill() {
                    eprintln!("[mbench-cli] warning: failed to kill QEMU child: {err}");
                }
                terminate_process_group(pgid);
                self.reap_killed_child()
            }
        }
    }
}

impl Drop for QemuVirtSession {
    fn drop(&mut self) {
        let _ = self.terminate_and_wait();
    }
}

#[cfg(unix)]
fn configure_child(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_child(command: &mut Command) {
    let _ = command;
}

/// Terminates an active session-owned process group after direct child termination.
#[cfg(unix)]
fn terminate_process_group(pgid: u32) {
    if pgid == 0 {
        return;
    }
    let _ = Command::new("kill")
        .args(["-KILL", "--", &format!("-{pgid}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// No-op process-group fallback on platforms without POSIX process groups.
#[cfg(not(unix))]
fn terminate_process_group(pgid: u32) {
    let _ = pgid;
}
