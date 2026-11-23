//! SBI System Suspend (`SUSP`) context preservation and safe platform wrapper.

use core::{arch::global_asm, mem::offset_of};

use mbench_core::record::FailReason;

use crate::{
    platform::{Platform, boot::SyncUnsafeCell, trap},
    sbi,
};

#[repr(C, align(64))]
struct SuspContext {
    ra: usize,
    sp: usize,
    gp: usize,
    tp: usize,
    s0: usize,
    s1: usize,
    s2: usize,
    s3: usize,
    s4: usize,
    s5: usize,
    s6: usize,
    s7: usize,
    s8: usize,
    s9: usize,
    s10: usize,
    s11: usize,
    resumed_via_trampoline: usize,
    resumed_hart_id: usize,
    resumed_opaque: usize,
    resumed_satp: usize,
    resumed_sstatus: usize,
}

impl SuspContext {
    const fn new() -> Self {
        Self {
            ra: 0,
            sp: 0,
            gp: 0,
            tp: 0,
            s0: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            s5: 0,
            s6: 0,
            s7: 0,
            s8: 0,
            s9: 0,
            s10: 0,
            s11: 0,
            resumed_via_trampoline: 0,
            resumed_hart_id: usize::MAX,
            resumed_opaque: 0,
            resumed_satp: usize::MAX,
            resumed_sstatus: usize::MAX,
        }
    }
}

static SUSP_CTX: SyncUnsafeCell<SuspContext> = SyncUnsafeCell::new(SuspContext::new());

global_asm!(
    r#"
.text

.balign 4
.global mbench_susp_call_and_resume
.type mbench_susp_call_and_resume, @function
mbench_susp_call_and_resume:
    # `a0 = sleep_type`, `a1 = &SUSP_CTX`
    sd   ra,  {OFF_RA}(a1)
    sd   sp,  {OFF_SP}(a1)
    sd   gp,  {OFF_GP}(a1)
    sd   tp,  {OFF_TP}(a1)
    sd   s0,  {OFF_S0}(a1)
    sd   s1,  {OFF_S1}(a1)
    sd   s2,  {OFF_S2}(a1)
    sd   s3,  {OFF_S3}(a1)
    sd   s4,  {OFF_S4}(a1)
    sd   s5,  {OFF_S5}(a1)
    sd   s6,  {OFF_S6}(a1)
    sd   s7,  {OFF_S7}(a1)
    sd   s8,  {OFF_S8}(a1)
    sd   s9,  {OFF_S9}(a1)
    sd   s10, {OFF_S10}(a1)
    sd   s11, {OFF_S11}(a1)
    mv   a2, a1
    la   a1, mbench_susp_resume_entry
    li   a6, {FID_SUSPEND}
    li   a7, {EID_SUSP}
    ecall
    # Direct return occurs only if `sbi_system_suspend` failed; `a0` carries error code.
    ret
.size mbench_susp_call_and_resume, . - mbench_susp_call_and_resume

.balign 4
.global mbench_susp_resume_entry
.type mbench_susp_resume_entry, @function
mbench_susp_resume_entry:
    # Non-retentive resume passes `a0 = hart_id`, `a1 = opaque (&SUSP_CTX)`.
    sd   a0,  {OFF_RESUMED_HART}(a1)
    sd   a1,  {OFF_RESUMED_OPAQUE}(a1)
    csrr t0,  satp
    sd   t0,  {OFF_RESUMED_SATP}(a1)
    csrr t0,  sstatus
    sd   t0,  {OFF_RESUMED_SSTATUS}(a1)
    li   t0,  1
    sd   t0,  {OFF_RESUMED_VIA}(a1)
    ld   ra,  {OFF_RA}(a1)
    ld   sp,  {OFF_SP}(a1)
    ld   gp,  {OFF_GP}(a1)
    ld   tp,  {OFF_TP}(a1)
    ld   s0,  {OFF_S0}(a1)
    ld   s1,  {OFF_S1}(a1)
    ld   s2,  {OFF_S2}(a1)
    ld   s3,  {OFF_S3}(a1)
    ld   s4,  {OFF_S4}(a1)
    ld   s5,  {OFF_S5}(a1)
    ld   s6,  {OFF_S6}(a1)
    ld   s7,  {OFF_S7}(a1)
    ld   s8,  {OFF_S8}(a1)
    ld   s9,  {OFF_S9}(a1)
    ld   s10, {OFF_S10}(a1)
    ld   s11, {OFF_S11}(a1)
    li   a0, 0
    ret
.size mbench_susp_resume_entry, . - mbench_susp_resume_entry
"#,
    OFF_RA = const offset_of!(SuspContext, ra),
    OFF_SP = const offset_of!(SuspContext, sp),
    OFF_GP = const offset_of!(SuspContext, gp),
    OFF_TP = const offset_of!(SuspContext, tp),
    OFF_S0 = const offset_of!(SuspContext, s0),
    OFF_S1 = const offset_of!(SuspContext, s1),
    OFF_S2 = const offset_of!(SuspContext, s2),
    OFF_S3 = const offset_of!(SuspContext, s3),
    OFF_S4 = const offset_of!(SuspContext, s4),
    OFF_S5 = const offset_of!(SuspContext, s5),
    OFF_S6 = const offset_of!(SuspContext, s6),
    OFF_S7 = const offset_of!(SuspContext, s7),
    OFF_S8 = const offset_of!(SuspContext, s8),
    OFF_S9 = const offset_of!(SuspContext, s9),
    OFF_S10 = const offset_of!(SuspContext, s10),
    OFF_S11 = const offset_of!(SuspContext, s11),
    OFF_RESUMED_VIA = const offset_of!(SuspContext, resumed_via_trampoline),
    OFF_RESUMED_HART = const offset_of!(SuspContext, resumed_hart_id),
    OFF_RESUMED_OPAQUE = const offset_of!(SuspContext, resumed_opaque),
    OFF_RESUMED_SATP = const offset_of!(SuspContext, resumed_satp),
    OFF_RESUMED_SSTATUS = const offset_of!(SuspContext, resumed_sstatus),
    FID_SUSPEND = const sbi::susp::FID_SUSPEND,
    EID_SUSP = const sbi::susp::EID,
);

unsafe extern "C" {
    fn mbench_susp_call_and_resume(sleep_type: usize, ctx: *mut SuspContext) -> isize;
}

/// Invokes `sbi_system_suspend` exclusively from BSP when no secondary harts are running.
pub(in crate::platform) fn call_system_suspend(
    platform: &mut Platform,
    sleep_type: u32,
) -> Result<isize, FailReason> {
    if platform.harts.is_poisoned()
        || platform.harts.online_harts_count() != 1
        || platform.harts.dedicated_worker_active()
    {
        return Err(FailReason::HardwareInconsistent);
    }
    let ctx = SUSP_CTX.get();
    // SAFETY: Exclusive BSP access before invoking `sbi_system_suspend`.
    unsafe {
        core::ptr::write_volatile(&raw mut (*ctx).resumed_via_trampoline, 0);
        core::ptr::write_volatile(&raw mut (*ctx).resumed_hart_id, usize::MAX);
        core::ptr::write_volatile(&raw mut (*ctx).resumed_opaque, 0);
        core::ptr::write_volatile(&raw mut (*ctx).resumed_satp, usize::MAX);
        core::ptr::write_volatile(&raw mut (*ctx).resumed_sstatus, usize::MAX);
    }
    // SAFETY: `ctx` points to static `SUSP_CTX` owned exclusively by BSP (`online_harts == 1`);
    // `mbench_susp_call_and_resume` preserves and restores `ra, sp, gp, tp, s0..s11`.
    let ret = unsafe { mbench_susp_call_and_resume(sleep_type as usize, ctx) };
    // Non-retentive resume resets supervisor CSRs (`stvec`, `sie`, `sstatus`); restore `mbench_trap_entry`.
    // SAFETY: `tp` was restored to `&HART_LOCALS[0]` before returning.
    unsafe { trap::init_on_current_hart() };
    if ret == 0 {
        // SAFETY: Written by `mbench_susp_resume_entry` if firmware resumed properly via resume_addr.
        let (via_trampoline, hart_id, opaque, satp, sstatus) = unsafe {
            (
                core::ptr::read_volatile(&raw const (*ctx).resumed_via_trampoline),
                core::ptr::read_volatile(&raw const (*ctx).resumed_hart_id),
                core::ptr::read_volatile(&raw const (*ctx).resumed_opaque),
                core::ptr::read_volatile(&raw const (*ctx).resumed_satp),
                core::ptr::read_volatile(&raw const (*ctx).resumed_sstatus),
            )
        };
        if via_trampoline != 1 {
            return Err(FailReason::AssertionFailed("susp_returned_without_resume"));
        }
        if hart_id != platform.info.boot_hart_id
            || opaque != (ctx as usize)
            || satp != 0
            || (sstatus & (1 << 1)) != 0
        {
            return Err(FailReason::VerificationMismatch);
        }
    }
    Ok(ret)
}

/// Probes `sbi_system_suspend` with fixed reserved `sleep_type = 1` while protecting saved BSP context.
pub(in crate::platform) fn probe_invalid_sleep_type(
    platform: &mut Platform,
) -> Result<isize, FailReason> {
    call_system_suspend(platform, sbi::susp::SLEEP_TYPE_INVALID_RESERVED)
}
