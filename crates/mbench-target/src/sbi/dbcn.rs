//! SBI Debug Console extension with slice-bounded safe wrappers.

use sbi_rt::Physical;

use super::SbiRet;

/// Issues `sbi_debug_console_write` for a physical byte range.
///
/// # Safety
///
/// `num_bytes` must describe a readable, identity-mapped S-mode memory range starting at
/// `(phys_lo, phys_hi)`, or the caller must intentionally probe M-mode validation with an
/// out-of-range address. The range must remain valid for the duration of the call.
#[inline(always)]
unsafe fn write_raw(num_bytes: usize, phys_lo: usize, phys_hi: usize) -> SbiRet {
    sbi_rt::console_write(Physical::<&[u8]>::new(num_bytes, phys_lo, phys_hi))
}

/// Issues `sbi_debug_console_read` for a physical byte range.
///
/// # Safety
///
/// `num_bytes` must describe a writable, identity-mapped S-mode memory range starting at
/// `(phys_lo, phys_hi)`, or the caller must intentionally probe M-mode validation with an
/// out-of-range address. The range must remain exclusively borrowed for the duration of the call.
#[inline(always)]
unsafe fn read_raw(num_bytes: usize, phys_lo: usize, phys_hi: usize) -> SbiRet {
    sbi_rt::console_read(Physical::<&mut [u8]>::new(num_bytes, phys_lo, phys_hi))
}

/// Writes `bytes` to the SBI debug console (safe in Bare and identity-mapped Sv39).
#[inline(always)]
pub(crate) fn write_slice(bytes: &[u8]) -> SbiRet {
    let dummy = 0u8;
    // CAST: SBI takes a physical address; the payload is identity-mapped S-mode RAM and the
    // non-empty slice retains its Rust provenance until the call returns.
    let phys_lo = if bytes.is_empty() {
        (&raw const dummy) as usize
    } else {
        bytes.as_ptr() as usize
    };
    // SAFETY: `bytes` (or stack `dummy` when `len == 0`) lies in valid readable identity-mapped RAM.
    unsafe { write_raw(bytes.len(), phys_lo, 0) }
}

/// Reads up to `buf.len()` bytes non-blockingly into `buf` from the SBI debug console.
#[inline(always)]
pub(crate) fn read_slice(buf: &mut [u8]) -> SbiRet {
    let mut dummy = 0u8;
    // CAST: SBI takes a physical address; the buffer is identity-mapped S-mode RAM and remains
    // uniquely borrowed for the duration of the call.
    let phys_lo = if buf.is_empty() {
        (&raw mut dummy) as usize
    } else {
        buf.as_mut_ptr() as usize
    };
    // SAFETY: `buf` is uniquely borrowed writable memory in identity-mapped RAM.
    unsafe { read_raw(buf.len(), phys_lo, 0) }
}

/// Probes M-mode validation by requesting a write from out-of-range physical address `phys_hi = u32::MAX`.
pub(crate) fn probe_invalid_phys_hi() -> SbiRet {
    // SAFETY: `phys_hi = 0xFFFF_FFFF` lies outside physical RAM and tests M-mode range checks without writes.
    unsafe { write_raw(4, 0, 0xFFFF_FFFF) }
}

#[inline(always)]
pub(crate) fn write_byte(byte: u8) -> SbiRet {
    sbi_rt::console_write_byte(byte)
}
