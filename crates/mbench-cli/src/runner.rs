//! Target execution abstraction isolating QEMU orchestration from future hardware board runners.

use std::{
    fmt,
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use mbench_core::config::ClockRegime;

/// Final OS exit status observed for a target session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionExit {
    Exited(Option<i32>),
    Killed,
}

impl SessionExit {
    /// Returns `true` when the child exited normally with exit code `0`.
    pub(crate) const fn is_clean_zero(self) -> bool {
        matches!(self, Self::Exited(Some(0)))
    }
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
    Line(String),
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
}

/// Active target session streaming serial output lines to the runner coordinator.
pub(crate) trait TargetSession {
    /// Polls for the next serial event up to `timeout`, returning `Ok(None)` on slice timeout.
    fn next_event(&mut self, timeout: Duration) -> Result<Option<SessionEvent>, String>;

    /// Waits up to `timeout` for the child process to exit naturally without killing it.
    fn wait_for_exit(&mut self, timeout: Duration) -> Result<Option<SessionExit>, String>;

    /// Stops any live execution, reaps associated OS resources, and returns the exit status.
    fn terminate_and_wait(&mut self) -> SessionExit;
}

/// Backend responsible for launching `mbench-target` on a concrete RISC-V platform.
pub(crate) trait TargetRunner {
    type Session: TargetSession;

    /// Returns the clock accuracy regime implied by `cfg` on this target backend.
    fn clock_regime(&self, cfg: &TargetLaunchConfig<'_>) -> ClockRegime;

    /// Starts one execution attempt and returns its active serial session.
    fn launch(&self, cfg: &TargetLaunchConfig<'_>) -> Result<Self::Session, String>;
}

/// QEMU `virt` machine backend launching `qemu-system-riscv64`.
#[derive(Clone, Debug)]
pub(crate) struct QemuVirtRunner {
    pub(crate) qemu_bin: String,
}

impl TargetRunner for QemuVirtRunner {
    type Session = QemuVirtSession;

    fn clock_regime(&self, cfg: &TargetLaunchConfig<'_>) -> ClockRegime {
        if cfg.icount {
            ClockRegime::QemuIcount
        } else {
            ClockRegime::QemuTcgNonCycleAccurate
        }
    }

    fn launch(&self, cfg: &TargetLaunchConfig<'_>) -> Result<Self::Session, String> {
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

        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn {}: {e}", self.qemu_bin))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| String::from("missing QEMU stdout pipe"))?;

        let (tx, rx) = mpsc::channel::<SessionEvent>();
        let reader = thread::spawn(move || {
            let mut buf_reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match buf_reader.read_line(&mut line) {
                    Ok(0) | Err(_) => {
                        let _ = tx.send(SessionEvent::Eof);
                        break;
                    }
                    Ok(_) => {
                        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
                        if tx.send(SessionEvent::Line(trimmed)).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(QemuVirtSession {
            child,
            rx,
            reader: Some(reader),
            exit: None,
        })
    }
}

/// Active `qemu-system-riscv64` process with RAII cleanup guarantees.
pub(crate) struct QemuVirtSession {
    child: Child,
    rx: Receiver<SessionEvent>,
    reader: Option<JoinHandle<()>>,
    exit: Option<SessionExit>,
}

impl QemuVirtSession {
    fn join_reader(&mut self) {
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }

    fn record_exit(&mut self, status: ExitStatus) -> SessionExit {
        let exit = SessionExit::Exited(status.code());
        self.exit = Some(exit);
        self.join_reader();
        exit
    }
}

impl TargetSession for QemuVirtSession {
    fn next_event(&mut self, timeout: Duration) -> Result<Option<SessionEvent>, String> {
        match self.rx.recv_timeout(timeout) {
            Ok(ev) => Ok(Some(ev)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Ok(Some(SessionEvent::Eof)),
        }
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> Result<Option<SessionExit>, String> {
        if let Some(exit) = self.exit {
            self.join_reader();
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
                    thread::sleep(Duration::from_millis(20));
                }
                Err(err) => return Err(format!("failed waiting for QEMU exit: {err}")),
            }
        }
    }

    fn terminate_and_wait(&mut self) -> SessionExit {
        if let Some(exit) = self.exit {
            self.join_reader();
            return exit;
        }
        let exit = match self.child.try_wait() {
            Ok(Some(status)) => SessionExit::Exited(status.code()),
            Ok(None) | Err(_) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                SessionExit::Killed
            }
        };
        self.exit = Some(exit);
        self.join_reader();
        exit
    }
}

impl Drop for QemuVirtSession {
    fn drop(&mut self) {
        let _ = self.terminate_and_wait();
    }
}
