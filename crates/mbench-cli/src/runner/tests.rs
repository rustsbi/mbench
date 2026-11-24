//! Real-pipe and host-process runner regression tests.

use std::{
    io::{self, Write},
    time::Duration,
};

use crate::runner::{SessionEvent, SessionExit, serial::SerialReader};

#[test]
fn decodes_non_utf8_without_losing_bytes_or_eof_state() {
    let input = b"before\ninvalid-\xff-line\r\nlast";
    let mut reader = SerialReader::new(&input[..], 3, "test-pipe");
    let first = reader.next_line().unwrap().unwrap();
    assert_eq!(first.raw, b"before\n");
    assert_eq!(first.text, "before");
    assert_eq!(first.offset, 0);

    let second = reader.next_line().unwrap().unwrap();
    assert_eq!(second.raw, b"invalid-\xff-line\r\n");
    assert_eq!(second.text, "invalid-\u{fffd}-line");
    assert_eq!(second.offset, 7);

    let third = reader.next_line().unwrap().unwrap();
    assert_eq!(third.raw, b"last");
    assert_eq!(third.text, "last");
    assert!(reader.next_line().unwrap().is_none());
}

#[test]
fn rejects_overlong_lines_with_operation_context() {
    let input = vec![b'x'; crate::runner::serial::MAX_LINE_BYTES + 1];
    let mut reader = SerialReader::new(&input[..], 5, "qemu-stdout");
    let err = reader.next_line().unwrap_err();
    assert!(err.contains("attempt 5"), "{err}");
    assert!(err.contains("qemu-stdout"), "{err}");
    assert!(err.contains("byte offset 0"), "{err}");
    assert!(err.contains("exceeds"), "{err}");
}

#[cfg(unix)]
#[test]
fn preserves_read_errors_instead_of_reporting_clean_eof() {
    let dir_handle = std::fs::File::open(env!("CARGO_MANIFEST_DIR")).unwrap();
    let mut reader = SerialReader::new(dir_handle, 2, "qemu-stdout");
    let err = reader.next_line().unwrap_err();
    assert!(err.contains("failed to read serial input"), "{err}");
    assert!(err.contains("attempt 2"), "{err}");
    assert!(err.contains("qemu-stdout"), "{err}");
    assert!(err.contains("byte offset 0"), "{err}");
}

#[test]
fn real_anonymous_pipe_preserves_bytes_until_reader_closes() {
    let (reader, mut writer) = io::pipe().unwrap();
    let sender = std::thread::spawn(move || {
        writer.write_all(b"frame\nraw-\xfe\n").unwrap();
    });
    let mut serial = SerialReader::new(reader, 0, "pipe");
    assert_eq!(serial.next_line().unwrap().unwrap().raw, b"frame\n");
    assert_eq!(serial.next_line().unwrap().unwrap().raw, b"raw-\xfe\n");
    assert!(serial.next_line().unwrap().is_none());
    sender.join().unwrap();
}

#[cfg(unix)]
#[test]
fn session_reader_consumes_non_utf8_child_stdout() {
    use std::process::{Command, Stdio};

    use crate::runner::{QemuVirtSession, SessionExit, configure_child};

    let mut command = Command::new("printf");
    command
        .args(["start\\ninvalid-\\377\\n"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    configure_child(&mut command);
    let mut child = command.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (rx, reader, done_rx) = QemuVirtSession::spawn_serial_reader(stdout, 4);
    let mut session = QemuVirtSession::new(child, rx, reader, done_rx);
    let mut events = Vec::new();
    while let Some(event) = session.next_event(Duration::from_secs(1)).unwrap() {
        if matches!(event, SessionEvent::Eof) {
            break;
        }
        events.push(event);
    }
    assert_eq!(
        events,
        vec![
            SessionEvent::Line {
                raw: b"start\n".to_vec(),
                text: "start".into(),
            },
            SessionEvent::Line {
                raw: b"invalid-\xff\n".to_vec(),
                text: "invalid-\u{fffd}".into(),
            },
        ]
    );
    assert!(matches!(
        session.wait_for_exit(Duration::from_secs(1)).unwrap(),
        Some(SessionExit::Exited(Some(0)))
    ));
    assert!(session.reader_joined());
}

#[cfg(unix)]
#[test]
fn direct_child_is_killed_and_reaped() {
    let child = direct_sleep(30);
    let pid = child.id();
    let mut session = session_with_pipe(child, "started");
    let started = std::time::Instant::now();
    assert_eq!(session.terminate_and_wait(), SessionExit::Killed);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(session.child_exit_status().is_some());
    assert_eq!(
        session.terminate_and_wait(),
        session.child_exit_status().unwrap()
    );
    drop(session);
    assert!(!process_is_running(pid), "child {pid} is still running");
}

#[cfg(unix)]
fn direct_sleep(seconds: u64) -> std::process::Child {
    let mut command = std::process::Command::new("sleep");
    command
        .arg(seconds.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    super::configure_child(&mut command);
    command.spawn().unwrap()
}

#[cfg(unix)]
fn session_with_pipe(child: std::process::Child, _text: &str) -> crate::runner::QemuVirtSession {
    let mut child = child;
    let stdout = child.stdout.take().unwrap();
    let (rx, reader, done_rx) = crate::runner::QemuVirtSession::spawn_serial_reader(stdout, 0);
    crate::runner::QemuVirtSession::new(child, rx, reader, done_rx)
}

#[cfg(unix)]
fn process_is_running(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}/stat")).exists()
}

#[cfg(unix)]
#[test]
fn descendant_pipe_ownership_does_not_block_bounded_cleanup() {
    use std::{
        process::{Command, Stdio},
        time::Instant,
    };

    use crate::runner::{QemuVirtSession, SessionExit, configure_child};

    let mut command = Command::new("sh");
    command
        .args(["-c", "printf 'started\\n'; sleep 30 & wait"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    configure_child(&mut command);
    let mut child = command.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (rx, reader, done_rx) = QemuVirtSession::spawn_serial_reader(stdout, 0);
    let mut session = QemuVirtSession::new(child, rx, reader, done_rx);
    assert_eq!(
        session.next_event(Duration::from_secs(1)).unwrap(),
        Some(SessionEvent::Line {
            raw: b"started\n".to_vec(),
            text: "started".into()
        })
    );

    let started = Instant::now();
    assert_eq!(session.terminate_and_wait(), SessionExit::Killed);
    assert!(
        session.reader_joined(),
        "serial reader thread should join once process group is killed"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "cleanup exceeded its bound"
    );
}
