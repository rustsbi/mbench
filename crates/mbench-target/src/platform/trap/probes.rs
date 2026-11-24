//! CSR, timer, IPI, and forbidden-CSR probes isolated from guard policy.

use core::{arch::asm, sync::atomic::Ordering};

use super::{TrapInfo, try_catch_raw};
use crate::platform::boot::HART_LOCALS;

/// Returns `true` if `sip.SSIP` is pending on the current hart.
pub(crate) fn is_ssip_pending() -> bool {
    riscv::register::sip::read().ssoft()
}

/// Clears `sip.SSIP` (bit 1) on the current hart.
pub(crate) fn clear_ssip() {
    // SAFETY: Acknowledges any pending S-mode software interrupt on the current hart.
    unsafe { riscv::register::sip::clear_ssoft() };
}

/// Reads `hook_flag` from `HART_LOCALS[slot_idx]` on a secondary worker hart using `Acquire` ordering.
pub(in crate::platform) fn read_slot_hook_flag(slot_idx: usize) -> usize {
    assert!(
        slot_idx < crate::platform::boot::MAX_HARTS,
        "hart slot out of bounds"
    );
    // SAFETY: `slot_idx < MAX_HARTS`, `HART_LOCALS` is `'static`, and `trap.S` updates `hook_flag`
    // via RV64A release atomics matching Rust `AtomicUsize::load(Ordering::Acquire)`.
    unsafe {
        (*HART_LOCALS.get())[slot_idx]
            .hook_flag
            .load(Ordering::Acquire)
    }
}

/// Probes whether reading `cycle` executes in S-mode without trapping.
pub(crate) fn probe_csr_cycle() -> bool {
    /// Reads the S-mode `cycle` CSR inside a trap-guarded probe.
    ///
    /// # Safety
    ///
    /// Must run inside [`try_catch_raw`] with zero `Drop` locals in scope.
    unsafe extern "C" fn probe(_ctx: *mut u8) {
        let val = riscv::register::cycle::read64();
        core::hint::black_box(val);
    }
    // SAFETY: `probe` holds no `Drop` locals and executes a single CSR read.
    unsafe { try_catch_raw(core::ptr::null_mut(), probe).is_ok() }
}

/// Probes whether reading `instret` executes in S-mode without trapping.
pub(crate) fn probe_csr_instret() -> bool {
    /// Reads the S-mode `instret` CSR inside a trap-guarded probe.
    ///
    /// # Safety
    ///
    /// Must run inside [`try_catch_raw`] with zero `Drop` locals in scope.
    unsafe extern "C" fn probe(_ctx: *mut u8) {
        let val = riscv::register::instret::read64();
        core::hint::black_box(val);
    }
    // SAFETY: `probe` holds no `Drop` locals and executes a single CSR read.
    unsafe { try_catch_raw(core::ptr::null_mut(), probe).is_ok() }
}

/// Probes whether reading `time` executes in S-mode without trapping.
pub(crate) fn probe_csr_time() -> bool {
    /// Reads the S-mode `time` CSR inside a trap-guarded probe.
    ///
    /// # Safety
    ///
    /// Must run inside [`try_catch_raw`] with zero `Drop` locals in scope.
    unsafe extern "C" fn probe(_ctx: *mut u8) {
        let val = riscv::register::time::read64();
        core::hint::black_box(val);
    }
    // SAFETY: `probe` holds no `Drop` locals and executes a single CSR read.
    unsafe { try_catch_raw(core::ptr::null_mut(), probe).is_ok() }
}

/// Probes a forbidden M-mode or custom CSR read; `Ok(val)` indicates an unexpected privilege leak.
pub(crate) fn probe_forbidden_csr(selector: usize) -> Result<usize, TrapInfo> {
    macro_rules! define_csr_probe {
        ($fn_name:ident, $csr:literal) => {
            /// Executes a trap-guarded privilege probe for the target CSR encoding.
            ///
            /// # Safety
            ///
            /// `ctx` must point to valid writable `usize` storage and run inside [`try_catch_raw`].
            unsafe extern "C" fn $fn_name(ctx: *mut u8) {
                let out_ptr = ctx.cast::<usize>();
                let val: usize;
                // SAFETY: Pure CSR read guarded by `try_catch_raw`; `out_ptr` points to caller stack `usize`.
                unsafe {
                    asm!(
                        ".option push",
                        ".option norvc",
                        concat!("csrrs {out}, ", $csr, ", zero"),
                        ".option pop",
                        out = out(reg) val,
                        options(nostack),
                    );
                    out_ptr.write(val);
                }
            }
        };
    }

    define_csr_probe!(p_mstatus, "0x300");
    define_csr_probe!(p_misa, "0x301");
    define_csr_probe!(p_medeleg, "0x302");
    define_csr_probe!(p_mideleg, "0x303");
    define_csr_probe!(p_mie, "0x304");
    define_csr_probe!(p_mtvec, "0x305");
    define_csr_probe!(p_mscratch, "0x340");
    define_csr_probe!(p_mepc, "0x341");
    define_csr_probe!(p_mvendorid, "0xf11");
    define_csr_probe!(p_marchid, "0xf12");
    define_csr_probe!(p_mimpid, "0xf13");
    define_csr_probe!(p_mhartid, "0xf14");
    define_csr_probe!(p_cust0, "0x7c0");
    define_csr_probe!(p_cust1, "0x7c1");
    define_csr_probe!(p_cust2, "0x7c2");
    define_csr_probe!(p_cust3, "0x7c3");

    const TABLE: [unsafe extern "C" fn(*mut u8); 16] = [
        p_mstatus,
        p_misa,
        p_medeleg,
        p_mideleg,
        p_mie,
        p_mtvec,
        p_mscratch,
        p_mepc,
        p_mvendorid,
        p_marchid,
        p_mimpid,
        p_mhartid,
        p_cust0,
        p_cust1,
        p_cust2,
        p_cust3,
    ];

    assert!(
        selector < TABLE.len(),
        "forbidden CSR selector out of bounds"
    );
    let mut out_val = 0usize;
    let probe_fn = TABLE[selector];
    // SAFETY: Leaf probe writes only to `usize` (`out_val`) and has zero `Drop` locals.
    unsafe { try_catch_raw((&raw mut out_val).cast::<u8>(), probe_fn)? };
    Ok(out_val)
}
