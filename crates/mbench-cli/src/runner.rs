//! Target execution abstraction isolating QEMU orchestration from future hardware board runners.

use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::Duration,
};

use mbench_core::config::ClockRegime;

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

    /// Stops any live execution and reaps associated OS resources.
    fn terminate_and_wait(&mut self);
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
            finished: false,
        })
    }
}

/// Active `qemu-system-riscv64` process with RAII cleanup guarantees.
pub(crate) struct QemuVirtSession {
    child: Child,
    rx: Receiver<SessionEvent>,
    reader: Option<JoinHandle<()>>,
    finished: bool,
}

impl TargetSession for QemuVirtSession {
    fn next_event(&mut self, timeout: Duration) -> Result<Option<SessionEvent>, String> {
        match self.rx.recv_timeout(timeout) {
            Ok(ev) => Ok(Some(ev)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Ok(Some(SessionEvent::Eof)),
        }
    }

    fn terminate_and_wait(&mut self) {
        if self.finished {
            return;
        }
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
        self.finished = true;
    }
}

impl Drop for QemuVirtSession {
    fn drop(&mut self) {
        self.terminate_and_wait();
    }
}
