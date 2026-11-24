//! Unified SBI `TIME` and `Sstc` (`stimecmp`) timer control isolated out of benchmark suites.

use core::arch::asm;

use riscv::register::sip;

use crate::{platform::trap, sbi};

/// Active supervisor timer backend selected from probed ISA/firmware capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimerMode {
    Sbi,
    Sstc,
}

/// Probes whether S-mode `stimecmp` (`0x14D`) is writable without trapping.
pub(crate) fn probe_stimecmp_writable() -> bool {
    /// Writes `u64::MAX` to `stimecmp` to detect Sstc trap vs acceptance.
    ///
    /// # Safety
    ///
    /// Must execute inside [`trap::try_catch_raw`] with zero `Drop` locals in scope.
    unsafe extern "C" fn probe(_ctx: *mut u8) {
        // SAFETY: Pure CSR write inside `try_catch_raw` with zero `Drop` locals.
        unsafe { write_stimecmp_raw(u64::MAX) };
    }
    // SAFETY: `probe` holds no `Drop` locals and executes one `csrw stimecmp` instruction.
    unsafe { trap::try_catch_raw(core::ptr::null_mut(), probe).is_ok() }
}

/// Clears any pending supervisor timer compare condition using `mode`.
pub(crate) fn clear_timer(mode: TimerMode) -> sbi::SbiRet {
    match mode {
        TimerMode::Sbi => sbi::time::set_timer(u64::MAX),
        TimerMode::Sstc => {
            if probe_stimecmp_writable() {
                sbi::SbiRet::success(0)
            } else {
                sbi::SbiRet::not_supported()
            }
        }
    }
}

/// Returns `true` if `sip.STIP` is currently pending on the calling hart.
pub(crate) fn is_timer_pending() -> bool {
    sip::read().stimer()
}

/// Clears pending `Sstc` timer compare (`stimecmp = u64::MAX`) without re-probing.
///
/// # Safety
///
/// Caller must guarantee `has_sstc == true` (`stimecmp` CSR `0x14D` is writable in S-mode).
#[inline(always)]
pub(in crate::platform) unsafe fn clear_timer_sstc_direct() {
    // SAFETY: Caller guarantees `has_sstc == true`.
    unsafe { write_stimecmp_raw(u64::MAX) };
}

/// Writes S-mode `stimecmp` (`0x14D`) directly without a trap recovery wrapper.
///
/// # Safety
///
/// Caller must guarantee either `has_sstc == true` (verified at boot) or execution inside
/// [`trap::try_catch_raw`].
#[inline(always)]
pub(in crate::platform) unsafe fn write_stimecmp_raw(val: u64) {
    // SAFETY: Caller guarantees `menvcfg.STCE` permits S-mode `stimecmp` writes or wraps in `try_catch_raw`.
    unsafe {
        asm!("csrw 0x14D, {v}", v = in(reg) val, options(nostack));
    }
}
