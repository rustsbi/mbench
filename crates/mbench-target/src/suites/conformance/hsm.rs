//! SBI Hart State Management (`HSM`) handoff, status, and secondary suspend conformance checks.

use mbench_core::{
    check::{CheckCase, CheckCtx, CheckOutcome},
    engine::Clock,
    record::{CaseFlags, IssueClass, SbiExtensionId, SkipReason},
};

use super::check_case;
use crate::{
    platform::{
        Platform,
        hsm::{self, SuspendWakeMode},
    },
    sbi::{self, SbiError},
};

const HSM_CONF_MAGIC_OPAQUE: usize = 0x55AA_55AA_DEAD_BEEFusize;

pub(super) static CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/hsm",
    Some(SbiExtensionId::Hsm),
    2,
    CaseFlags::empty(),
    conf_hsm,
)];

fn conf_hsm(env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();
    let total_harts = env.info().hart_count;
    if total_harts < 2 {
        return ctx.finish_or_skip(SkipReason::SingleHartOnly);
    }

    let boot_hart = env.info().boot_hart_id;
    let peer = env.hart_id(1);
    let timeout = env.timebase_hz().saturating_mul(2).max(1);

    let boot_st = sbi::hsm::hart_get_status(boot_hart);
    ctx.expect(
        boot_st.error == 0 && boot_st.value == sbi::hsm::state::STARTED,
        "hsm_boot_hart_started",
    );

    let peer_st = sbi::hsm::hart_get_status(peer);
    ctx.expect(
        peer_st.error == 0 && peer_st.value == sbi::hsm::state::STOPPED,
        "hsm_peer_hart_stopped",
    );

    let bad_id = sbi::hsm::hart_get_status(usize::MAX);
    ctx.expect_sbi_err(
        sbi::error_code(bad_id),
        SbiError::InvalidParam.as_code(),
        "hsm_invalid_hartid",
    );

    let dup = hsm::probe_duplicate_start_boot_hart(env);
    ctx.expect_sbi_err(
        sbi::error_code(dup),
        SbiError::AlreadyAvailable.as_code(),
        "hsm_duplicate_start_already_available",
    );

    let inv_fid = sbi::probe_invalid_fid(SbiExtensionId::Hsm);
    ctx.expect_sbi_err(
        sbi::error_code(inv_fid),
        SbiError::NotSupported.as_code(),
        "hsm_invalid_fid",
    );

    match hsm::probe_secondary_handoff(env, peer, HSM_CONF_MAGIC_OPAQUE, timeout) {
        Ok(snap) => {
            ctx.expect(snap.hart_id == peer, "hsm_handoff_a0_hart_id");
            ctx.expect(
                snap.opaque == HSM_CONF_MAGIC_OPAQUE,
                "hsm_handoff_a1_opaque",
            );
            ctx.expect(snap.satp == 0, "hsm_handoff_satp_bare");
            ctx.expect((snap.sstatus & (1 << 1)) == 0, "hsm_handoff_sie_cleared");
        }
        Err(err) => ctx.record_fail("hsm_secondary_handoff", err),
    }

    match env.probe_secondary_suspend(
        peer,
        sbi::hsm::suspend_type::INVALID_RESERVED,
        SuspendWakeMode::NoWakeExpected,
        timeout,
    ) {
        Ok(probe) => {
            ctx.expect_sbi_err(
                probe.err_code,
                SbiError::InvalidParam.as_code(),
                "hsm_invalid_suspend_type_rejected",
            );
        }
        Err(err) => ctx.record_fail("hsm_invalid_suspend_type", err),
    }

    if !env.caps().extensions.contains_ext(SbiExtensionId::Spi) {
        ctx.observe("hsm_suspend_wake_ipi_unavailable", IssueClass::Unsupported);
        return ctx.finish();
    }

    match env.probe_secondary_suspend(
        peer,
        sbi::hsm::suspend_type::RETENTIVE,
        SuspendWakeMode::WakeViaIpi,
        timeout,
    ) {
        Ok(probe) => {
            if probe.err_code == SbiError::NotSupported.as_code() {
                ctx.observe("hsm_retentive_suspend_optional", IssueClass::Unsupported);
            } else {
                ctx.expect_sbi_err(probe.err_code, 0, "hsm_retentive_suspend_ok");
            }
        }
        Err(err) => ctx.record_fail("hsm_retentive_suspend", err),
    }

    match env.probe_secondary_suspend(
        peer,
        sbi::hsm::suspend_type::NON_RETENTIVE,
        SuspendWakeMode::WakeViaIpi,
        timeout,
    ) {
        Ok(probe) => {
            if probe.err_code == SbiError::NotSupported.as_code() {
                ctx.observe(
                    "hsm_non_retentive_suspend_optional",
                    IssueClass::Unsupported,
                );
            } else {
                ctx.expect_sbi_err(probe.err_code, 0, "hsm_non_retentive_suspend_ok");
                ctx.expect(
                    probe.resumed_via_trampoline,
                    "hsm_non_retentive_resumed_via_entry",
                );
                if probe.resumed_via_trampoline {
                    ctx.expect(
                        probe.resumed_hart_id == peer,
                        "hsm_non_retentive_a0_hart_id",
                    );
                    ctx.expect(
                        probe.resumed_opaque == probe.expected_opaque,
                        "hsm_non_retentive_a1_opaque",
                    );
                    ctx.expect(probe.resumed_satp == 0, "hsm_non_retentive_satp_bare");
                    ctx.expect(
                        (probe.resumed_sstatus & (1 << 1)) == 0,
                        "hsm_non_retentive_sie_cleared",
                    );
                }
            }
        }
        Err(err) => ctx.record_fail("hsm_non_retentive_suspend", err),
    }

    ctx.finish()
}
