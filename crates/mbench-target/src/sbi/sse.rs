//! SBI Supervisor Software Events extension.

use mbench_core::record::SbiExtensionId;

use super::{SbiRet, raw_ecall};

pub(crate) const EID: usize = SbiExtensionId::Sse.eid();
const FID_READ_ATTRS: usize = 0;
const FID_WRITE_ATTRS: usize = 1;
const FID_REGISTER: usize = 2;
const FID_UNREGISTER: usize = 3;
const FID_ENABLE: usize = 4;
const FID_DISABLE: usize = 5;
pub(crate) const FID_COMPLETE: usize = 6;
const FID_INJECT: usize = 7;
const FID_HART_UNMASK: usize = 8;
const FID_HART_MASK: usize = 9;

pub(crate) const EVENT_LOCAL_SOFTWARE: usize = 0xFFFF_0000;
pub(crate) const EVENT_INVALID: usize = 0xDEAD_BEEF;

pub(crate) const ATTR_STATUS: usize = 0;
pub(crate) const ATTR_PRIO: usize = 1;
pub(crate) const ATTR_INVALID: usize = 10;

pub(crate) const STATUS_STATE_MASK: usize = 0b11;
pub(crate) const STATUS_STATE_UNUSED: usize = 0;
pub(crate) const STATUS_STATE_REGISTERED: usize = 1;
pub(crate) const STATUS_STATE_ENABLED: usize = 2;
pub(crate) const STATUS_INJECTABLE: usize = 1 << 3;
pub(crate) const STATUS_RESERVED_MASK: usize = !0b1111usize;

/// Reads `attr_count` attributes for `event_id` into `(out_lo, out_hi)`.
///
/// # Safety
///
/// `(out_lo, out_hi)` must point to writable identity-mapped S-mode memory for `attr_count * size_of::<usize>()` bytes.
#[inline(always)]
pub(crate) unsafe fn read_attrs_raw(
    event_id: usize,
    base_attr_id: usize,
    attr_count: usize,
    out_lo: usize,
    out_hi: usize,
) -> SbiRet {
    // SAFETY: Caller guarantees writable output buffer for `attr_count` attributes.
    unsafe {
        raw_ecall(
            EID,
            FID_READ_ATTRS,
            [event_id, base_attr_id, attr_count, out_lo, out_hi, 0],
        )
    }
}

/// Writes `attr_count` attributes for `event_id` from `(in_lo, in_hi)`.
///
/// # Safety
///
/// `(in_lo, in_hi)` must point to readable identity-mapped S-mode memory for `attr_count * size_of::<usize>()` bytes.
#[inline(always)]
pub(crate) unsafe fn write_attrs_raw(
    event_id: usize,
    base_attr_id: usize,
    attr_count: usize,
    in_lo: usize,
    in_hi: usize,
) -> SbiRet {
    // SAFETY: Caller guarantees readable input buffer for `attr_count` attributes.
    unsafe {
        raw_ecall(
            EID,
            FID_WRITE_ATTRS,
            [event_id, base_attr_id, attr_count, in_lo, in_hi, 0],
        )
    }
}

/// Registers an S-mode SSE trampoline for `event_id`.
///
/// # Safety
///
/// `handler_pc` must be a valid SSE entry routine ending in `FID_COMPLETE`, and `handler_arg`
/// must remain valid for the entire registered lifetime of `event_id`.
#[inline(always)]
pub(crate) unsafe fn register(event_id: usize, handler_pc: usize, handler_arg: usize) -> SbiRet {
    // SAFETY: Caller guarantees valid handler entrypoint and `handler_arg` lifetime.
    unsafe {
        raw_ecall(
            EID,
            FID_REGISTER,
            [event_id, handler_pc, handler_arg, 0, 0, 0],
        )
    }
}

#[inline(always)]
pub(crate) fn unregister(event_id: usize) -> SbiRet {
    // SAFETY: Unregisters an SSE handler without passing memory pointers.
    unsafe { raw_ecall(EID, FID_UNREGISTER, [event_id, 0, 0, 0, 0, 0]) }
}

#[inline(always)]
pub(crate) fn enable(event_id: usize) -> SbiRet {
    // SAFETY: Enables SSE event delivery without passing memory pointers.
    unsafe { raw_ecall(EID, FID_ENABLE, [event_id, 0, 0, 0, 0, 0]) }
}

#[inline(always)]
pub(crate) fn disable(event_id: usize) -> SbiRet {
    // SAFETY: Disables SSE event delivery without passing memory pointers.
    unsafe { raw_ecall(EID, FID_DISABLE, [event_id, 0, 0, 0, 0, 0]) }
}

#[inline(always)]
pub(crate) fn inject(event_id: usize, hart_id: usize) -> SbiRet {
    // SAFETY: Triggers delivery for an already-registered SSE event.
    unsafe { raw_ecall(EID, FID_INJECT, [event_id, hart_id, 0, 0, 0, 0]) }
}

#[inline(always)]
pub(crate) fn hart_unmask() -> SbiRet {
    // SAFETY: Unmasks SSE events on current hart without memory operands.
    unsafe { raw_ecall(EID, FID_HART_UNMASK, [0; 6]) }
}

#[inline(always)]
pub(crate) fn hart_mask() -> SbiRet {
    // SAFETY: Masks SSE events on current hart without memory operands.
    unsafe { raw_ecall(EID, FID_HART_MASK, [0; 6]) }
}

/// Invokes `sbi_sse_complete` directly from normal S-mode context to verify `INVALID_STATE`.
#[inline(always)]
pub(crate) fn complete_outside_handler() -> SbiRet {
    // SAFETY: Calling `FID_COMPLETE` with no RUNNING SSE event takes no memory pointers.
    unsafe { raw_ecall(EID, FID_COMPLETE, [0; 6]) }
}
