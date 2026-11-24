//! Raw SBI `ecall` boundary and ABI-preservation probes.

use core::arch::asm;

use mbench_core::record::SbiExtensionId;

use super::SbiRet;

/// Executes a raw SBI `ecall` with extension `eid`, function `fid`, and arguments `a0..a5`.
///
/// # Safety
///
/// Any physical address, hart entry PC, or state transition implied by `(eid, fid, args)` must
/// point to valid S-mode-owned memory/code and satisfy the RISC-V SBI v3.0 specification.
#[inline(always)]
pub(crate) unsafe fn raw_ecall(eid: usize, fid: usize, args: [usize; 6]) -> SbiRet {
    let error: usize;
    let value: usize;
    // SAFETY: Caller upholds all SBI pointer, lifetime, and state-machine preconditions for
    // `(eid, fid, args)`. Register mapping follows the RISC-V SBI calling convention.
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") args[0] => error,
            inlateout("a1") args[1] => value,
            in("a2") args[2],
            in("a3") args[3],
            in("a4") args[4],
            in("a5") args[5],
            in("a6") fid,
            in("a7") eid,
            options(nostack),
        );
    }
    SbiRet { error, value }
}

/// Executes an SBI `ecall` and verifies that `a2..a7` and callee-saved `s2..s5` are preserved.
///
/// # Safety
///
/// Same requirements as [`raw_ecall`]; additionally `s2..s5` are temporarily clobbered inside the
/// `asm!` block before restoration by the compiler.
pub(crate) unsafe fn ecall_check_abi(eid: usize, fid: usize, args: [usize; 6]) -> (SbiRet, bool) {
    const S2_MAGIC: usize = 0x1122_3344_5566_7788;
    const S3_MAGIC: usize = 0x99AA_BBCC_DDEE_FF01;
    const S4_MAGIC: usize = 0xCAFE_BABE_1357_2468;
    const S5_MAGIC: usize = 0xFEED_FACE_8642_7531;

    let error: usize;
    let value: usize;
    let out_a2: usize;
    let out_a3: usize;
    let out_a4: usize;
    let out_a5: usize;
    let out_a6: usize;
    let out_a7: usize;
    let out_s2: usize;
    let out_s3: usize;
    let out_s4: usize;
    let out_s5: usize;

    // SAFETY: All operands use disjoint explicit architectural registers (`t0..t3`, `s2..s5`,
    // `a0..a7`) and caller guarantees `(eid, fid, args)` obeys SBI memory/state preconditions.
    unsafe {
        asm!(
            "mv s2, t0",
            "mv s3, t1",
            "mv s4, t2",
            "mv s5, t3",
            "ecall",
            "mv t0, s2",
            "mv t1, s3",
            "mv t2, s4",
            "mv t3, s5",
            inlateout("t0") S2_MAGIC => out_s2,
            inlateout("t1") S3_MAGIC => out_s3,
            inlateout("t2") S4_MAGIC => out_s4,
            inlateout("t3") S5_MAGIC => out_s5,
            inlateout("a0") args[0] => error,
            inlateout("a1") args[1] => value,
            inlateout("a2") args[2] => out_a2,
            inlateout("a3") args[3] => out_a3,
            inlateout("a4") args[4] => out_a4,
            inlateout("a5") args[5] => out_a5,
            inlateout("a6") fid => out_a6,
            inlateout("a7") eid => out_a7,
            out("s2") _,
            out("s3") _,
            out("s4") _,
            out("s5") _,
            options(nostack),
        );
    }

    let abi_ok = out_s2 == S2_MAGIC
        && out_s3 == S3_MAGIC
        && out_s4 == S4_MAGIC
        && out_s5 == S5_MAGIC
        && out_a2 == args[2]
        && out_a3 == args[3]
        && out_a4 == args[4]
        && out_a5 == args[5]
        && out_a6 == fid
        && out_a7 == eid;
    (SbiRet { error, value }, abi_ok)
}

/// Probes an intentionally invalid EID (`0x7FFF_FFFF`) cleanly without memory side effects.
pub(crate) fn probe_invalid_eid() -> SbiRet {
    // SAFETY: Unassigned EID `0x7FFF_FFFF` takes no memory operands and must return NOT_SUPPORTED.
    unsafe { raw_ecall(0x7FFF_FFFF, 0, [0; 6]) }
}

/// Probes a known-unsupported function ID on standard extension `ext` and checks ABI preservation.
pub(crate) fn probe_invalid_fid_abi(ext: SbiExtensionId) -> (SbiRet, bool) {
    let fid = match ext {
        SbiExtensionId::Time | SbiExtensionId::Spi => 1,
        _ => 99,
    };
    // SAFETY: Non-existent FIDs within standard extensions perform no memory accesses.
    unsafe {
        ecall_check_abi(
            ext.eid(),
            fid,
            [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666],
        )
    }
}

/// Probes a known-unsupported function ID on standard extension `ext` without memory side effects.
pub(crate) fn probe_invalid_fid(ext: SbiExtensionId) -> SbiRet {
    probe_invalid_fid_abi(ext).0
}
