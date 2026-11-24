//! Bounded byte-oriented serial decoding with operation and offset diagnostics.

use std::io::{self, Read};

/// Maximum accepted protocol-line size before the stream is rejected.
pub(super) const MAX_LINE_BYTES: usize = 1024 * 1024;
const READ_CHUNK_BYTES: usize = 16 * 1024;

/// A serial line with its original bytes and lossy protocol representation.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct SerialLine {
    pub(super) raw: Vec<u8>,
    pub(super) text: String,
    pub(super) offset: u64,
}

/// Incremental newline decoder. It never requires UTF-8 on the transport.
pub(super) struct SerialReader<R> {
    reader: R,
    attempt: usize,
    stream: &'static str,
    pending: Vec<u8>,
    next_offset: u64,
    finished: bool,
}

impl<R: Read> SerialReader<R> {
    pub(super) fn new(reader: R, attempt: usize, stream: &'static str) -> Self {
        Self {
            reader,
            attempt,
            stream,
            pending: Vec::new(),
            next_offset: 0,
            finished: false,
        }
    }

    /// Returns one complete line or EOF. Read errors never masquerade as clean EOF.
    pub(super) fn next_line(&mut self) -> Result<Option<SerialLine>, String> {
        if self.finished {
            return Ok(None);
        }
        loop {
            if let Some(newline) = self.pending.iter().position(|&byte| byte == b'\n') {
                return Ok(Some(self.take_line(newline + 1)));
            }
            if self.pending.len() >= MAX_LINE_BYTES {
                return Err(self.line_too_long());
            }

            let mut chunk = [0u8; READ_CHUNK_BYTES];
            let remaining = MAX_LINE_BYTES + 1 - self.pending.len();
            let read_len = remaining.min(chunk.len());
            let read = self
                .reader
                .read(&mut chunk[..read_len])
                .map_err(|err| self.error("read", &err))?;
            if read == 0 {
                self.finished = true;
                if self.pending.is_empty() {
                    return Ok(None);
                }
                let len = self.pending.len();
                return Ok(Some(self.take_line(len)));
            }
            self.pending.extend_from_slice(&chunk[..read]);
        }
    }

    fn take_line(&mut self, len: usize) -> SerialLine {
        let offset = self.next_offset;
        let raw: Vec<u8> = self.pending.drain(..len).collect();
        self.next_offset += len as u64;
        let text = String::from_utf8_lossy(&raw)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        SerialLine { raw, text, offset }
    }

    fn line_too_long(&self) -> String {
        format!(
            "attempt {} stream {} byte offset {}: serial line exceeds {} bytes",
            self.attempt, self.stream, self.next_offset, MAX_LINE_BYTES
        )
    }

    fn error(&self, operation: &str, err: &io::Error) -> String {
        format!(
            "attempt {} stream {} byte offset {}: failed to {operation} serial input: {err}",
            self.attempt, self.stream, self.next_offset
        )
    }
}
