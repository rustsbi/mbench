//! S-mode trap isolation, CSR privilege boundary, `ebreak`, and misaligned access conformance checks.

use mbench_core::{
    check::{CheckCase, CheckCtx, CheckOutcome},
    engine::Clock,
    record::{CaseFlags, FailReason, IssueClass},
};
use riscv::interrupt::{Exception, Trap};

use super::check_case;
use crate::platform::{Platform, trap};

pub(super) static CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/traps",
    None,
    1,
    CaseFlags::empty(),
    conf_traps,
)];

fn conf_traps(env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();

    for idx in 0..16 {
        match trap::probe_forbidden_csr(idx) {
            Ok(_) => ctx.record_fail(
                "trap_forbidden_csr_illegal",
                FailReason::SecurityViolation("mmode_csr_readable_in_s"),
            ),
            Err(info) => {
                let is_illegal = info.cause() == Ok(Trap::Exception(Exception::IllegalInstruction));
                ctx.expect(is_illegal, "trap_forbidden_csr_illegal");
            }
        }
    }

    match trap::EbreakHookGuard::install(env.availability()) {
        Ok(guard) => {
            guard.reset_flag();
            guard.exec_ebreak();
            ctx.expect(guard.read_flag() == 1, "trap_ebreak_delivered");
        }
        Err(err) => ctx.record_fail("trap_ebreak_hook_install", err),
    }

    let mut probe = env.misalign_probe();
    let mut saw_load_deleg = false;
    let mut saw_load_fault = false;
    probe.write_odd_pattern(&[0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8]);
    let r_ld64 = probe.probe_ld_64();
    record_misalign_load(
        &mut ctx,
        r_ld64,
        0xF8E7_D6C5_B4A3_9281u64,
        "trap_misalign_ld_64",
        &mut saw_load_deleg,
        &mut saw_load_fault,
    );
    let r_lh = probe.probe_lh();
    record_misalign_load(
        &mut ctx,
        r_lh,
        -0x6D7Fisize,
        "trap_misalign_lh",
        &mut saw_load_deleg,
        &mut saw_load_fault,
    );
    let r_lhu = probe.probe_lhu();
    record_misalign_load(
        &mut ctx,
        r_lhu,
        0x9281usize,
        "trap_misalign_lhu",
        &mut saw_load_deleg,
        &mut saw_load_fault,
    );
    let r_lw = probe.probe_lw();
    record_misalign_load(
        &mut ctx,
        r_lw,
        -0x4B5C_6D7Fisize,
        "trap_misalign_lw",
        &mut saw_load_deleg,
        &mut saw_load_fault,
    );
    let r_lwu = probe.probe_lwu();
    record_misalign_load(
        &mut ctx,
        r_lwu,
        0xB4A3_9281usize,
        "trap_misalign_lwu",
        &mut saw_load_deleg,
        &mut saw_load_fault,
    );

    let mut saw_store_deleg = false;
    let mut saw_store_fault = false;
    let sentinel = 0xDEAD_BEEF_CAFE_BABEu64;
    probe.write_odd_pattern(&[0xA5; 8]);
    let r_sd64 = probe.probe_sd_64(sentinel);
    record_misalign_store(
        &mut ctx,
        &probe,
        r_sd64,
        &sentinel.to_le_bytes(),
        "trap_misalign_sd_64",
        &mut saw_store_deleg,
        &mut saw_store_fault,
    );

    probe.write_odd_pattern(&[0xA5; 8]);
    let r_sh = probe.probe_sh(0xABCD);
    record_misalign_store(
        &mut ctx,
        &probe,
        r_sh,
        &[0xCD, 0xAB],
        "trap_misalign_sh",
        &mut saw_store_deleg,
        &mut saw_store_fault,
    );

    probe.write_odd_pattern(&[0xA5; 8]);
    let r_sw = probe.probe_sw(0x1234_5678);
    record_misalign_store(
        &mut ctx,
        &probe,
        r_sw,
        &[0x78, 0x56, 0x34, 0x12],
        "trap_misalign_sw",
        &mut saw_store_deleg,
        &mut saw_store_fault,
    );

    ctx.finish()
}

fn record_misalign_load<T: Eq>(
    ctx: &mut CheckCtx,
    res: Result<T, trap::TrapInfo>,
    expected: T,
    label: &'static str,
    saw_deleg: &mut bool,
    saw_fault: &mut bool,
) {
    match res {
        Ok(val) => {
            ctx.expect(val == expected, label);
        }
        Err(info) if info.cause() == Ok(Trap::Exception(Exception::LoadMisaligned)) => {
            if !*saw_deleg {
                ctx.observe(
                    "trap_misalign_load_delegated_to_s",
                    IssueClass::PermittedBehavior,
                );
                *saw_deleg = true;
            }
        }
        Err(info) if info.cause() == Ok(Trap::Exception(Exception::LoadFault)) => {
            if !*saw_fault {
                ctx.observe(
                    "trap_misalign_load_access_fault_permitted",
                    IssueClass::PermittedBehavior,
                );
                *saw_fault = true;
            }
        }
        Err(info) => ctx.record_fail(label, FailReason::UnexpectedTrap(info.scause)),
    }
}

fn record_misalign_store(
    ctx: &mut CheckCtx,
    probe: &crate::platform::misalign::MisalignProbe<'_>,
    res: Result<(), trap::TrapInfo>,
    expected_bytes: &[u8],
    label: &'static str,
    saw_deleg: &mut bool,
    saw_fault: &mut bool,
) {
    match res {
        Ok(()) => {
            ctx.expect(probe.verify_odd_bytes_and_canaries(expected_bytes), label);
        }
        Err(info) if info.cause() == Ok(Trap::Exception(Exception::StoreMisaligned)) => {
            if !*saw_deleg {
                ctx.observe(
                    "trap_misalign_store_delegated_to_s",
                    IssueClass::PermittedBehavior,
                );
                *saw_deleg = true;
            }
        }
        Err(info) if info.cause() == Ok(Trap::Exception(Exception::StoreFault)) => {
            if !*saw_fault {
                ctx.observe(
                    "trap_misalign_store_access_fault_permitted",
                    IssueClass::PermittedBehavior,
                );
                *saw_fault = true;
            }
        }
        Err(info) => ctx.record_fail(label, FailReason::UnexpectedTrap(info.scause)),
    }
}
