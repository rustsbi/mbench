//! SBI Supervisor Software Events (`SSE`, SBI v3.0) state-machine and delivery conformance checks.

use mbench_core::{
    check::{CheckCase, CheckCtx, CheckOutcome},
    engine::Clock,
    record::{CaseFlags, IssueClass, SbiExtensionId},
};

use super::check_case;
use crate::{
    platform::Platform,
    sbi::{self, SbiError},
};

pub(super) static CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/sse",
    Some(SbiExtensionId::Sse),
    1,
    CaseFlags::empty(),
    conf_sse,
)];

fn conf_sse(env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();
    let boot_hart_id = env.info().boot_hart_id;
    let timeout = env.timebase_hz().max(1);

    let bad_evt = env.probe_sse_unknown_event();
    ctx.expect_sbi_err_in(
        sbi::error_code(bad_evt),
        &[
            SbiError::InvalidParam.as_code(),
            SbiError::NotSupported.as_code(),
        ],
        "sse_unknown_event_rejected",
    );

    // Per SBI v3.0 ext-sse.adoc, `sbi_sse_complete` when no event is RUNNING does nothing and returns SBI_SUCCESS.
    let outside_complete = sbi::sse::complete_outside_handler();
    ctx.expect_sbi_err(
        sbi::error_code(outside_complete),
        0,
        "sse_complete_idle_success",
    );

    let bad_reg_evt = env.probe_sse_invalid_register(sbi::sse::EVENT_INVALID, false);
    ctx.expect_sbi_err_in(
        sbi::error_code(bad_reg_evt),
        &[
            SbiError::InvalidParam.as_code(),
            SbiError::NotSupported.as_code(),
        ],
        "sse_register_unknown_event_rejected",
    );

    match env.probe_sse_local_status() {
        Ok(pre_status) => {
            let is_unused =
                (pre_status & sbi::sse::STATUS_STATE_MASK) == sbi::sse::STATUS_STATE_UNUSED;
            ctx.expect(is_unused, "sse_local_software_initially_unused");
            if is_unused {
                let unaligned_pc =
                    env.probe_sse_invalid_register(sbi::sse::EVENT_LOCAL_SOFTWARE, true);
                if unaligned_pc.error == 0 {
                    let _ = sbi::sse::unregister(sbi::sse::EVENT_LOCAL_SOFTWARE);
                }
                ctx.expect_sbi_err(
                    sbi::error_code(unaligned_pc),
                    SbiError::InvalidParam.as_code(),
                    "sse_unaligned_entry_pc_rejected",
                );

                match env.register_local_sse() {
                    Ok(mut session) => {
                        let exp_pc = session.entry_pc();
                        let exp_arg = session.entry_arg();

                        match session.read_attr(sbi::sse::ATTR_STATUS) {
                            Ok(status) => {
                                let state = status & sbi::sse::STATUS_STATE_MASK;
                                let reserved_zero = (status & sbi::sse::STATUS_RESERVED_MASK) == 0;
                                ctx.expect(
                                    state == sbi::sse::STATUS_STATE_REGISTERED && reserved_zero,
                                    "sse_registered_status_valid",
                                );
                            }
                            Err(err) => {
                                ctx.expect_sbi_err(err.as_code(), 0, "sse_read_status");
                            }
                        }

                        let mut packed = [0usize; 6];
                        match session.read_attrs_multi(sbi::sse::ATTR_STATUS, &mut packed) {
                            Ok(()) => {
                                ctx.expect(
                                    packed[4] == exp_pc && packed[5] == exp_arg,
                                    "sse_read_attrs_entry_pc_arg_match",
                                );
                            }
                            Err(err) => {
                                ctx.expect_sbi_err(err.as_code(), 0, "sse_read_attrs_multi");
                            }
                        }

                        let ro_code = match session.write_attr(sbi::sse::ATTR_STATUS, 0) {
                            Ok(()) => 0,
                            Err(err) => err.as_code(),
                        };
                        ctx.expect_sbi_err(
                            ro_code,
                            SbiError::Denied.as_code(),
                            "sse_write_ro_status_rejected",
                        );

                        let inv_code = match session.write_attr(sbi::sse::ATTR_INVALID, 0) {
                            Ok(()) => 0,
                            Err(err) => err.as_code(),
                        };
                        ctx.expect_sbi_err(
                            inv_code,
                            SbiError::BadRange.as_code(),
                            "sse_write_invalid_attr_rejected",
                        );

                        let mut prio_for_enabled_probe = 0usize;
                        match session.read_attr(sbi::sse::ATTR_PRIO) {
                            Ok(orig_prio) => {
                                prio_for_enabled_probe = orig_prio;
                                ctx.record_pass();
                                if let Err(err) = session.write_attr(sbi::sse::ATTR_PRIO, 42) {
                                    ctx.expect_sbi_err(err.as_code(), 0, "sse_write_prio_42");
                                } else {
                                    match session.read_attr(sbi::sse::ATTR_PRIO) {
                                        Ok(got_prio) => {
                                            ctx.expect(got_prio == 42, "sse_prio_roundtrip");
                                        }
                                        Err(err) => {
                                            ctx.expect_sbi_err(
                                                err.as_code(),
                                                0,
                                                "sse_read_prio_after_write",
                                            );
                                        }
                                    }
                                    match session.write_attr(sbi::sse::ATTR_PRIO, orig_prio) {
                                        Ok(()) => ctx.record_pass(),
                                        Err(err) => {
                                            ctx.expect_sbi_err(
                                                err.as_code(),
                                                0,
                                                "sse_restore_prio",
                                            );
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                ctx.expect_sbi_err(err.as_code(), 0, "sse_read_orig_prio");
                            }
                        }

                        let dup_reg = session.probe_double_register();
                        ctx.expect_sbi_err(
                            sbi::error_code(dup_reg),
                            SbiError::InvalidState.as_code(),
                            "sse_double_register_invalid_state",
                        );

                        match session.enable_and_unmask() {
                            Ok(()) => ctx.record_pass(),
                            Err(err) => {
                                ctx.expect_sbi_err(err.as_code(), 0, "sse_enable_unmask");
                            }
                        }

                        match session.read_attr(sbi::sse::ATTR_STATUS) {
                            Ok(enabled_st) => {
                                ctx.expect(
                                    (enabled_st & sbi::sse::STATUS_STATE_MASK)
                                        == sbi::sse::STATUS_STATE_ENABLED,
                                    "sse_enabled_status",
                                );
                            }
                            Err(err) => {
                                ctx.expect_sbi_err(err.as_code(), 0, "sse_read_enabled_status");
                            }
                        }

                        if let Err(err) =
                            session.write_attr(sbi::sse::ATTR_PRIO, prio_for_enabled_probe)
                        {
                            ctx.expect_sbi_err(
                                err.as_code(),
                                SbiError::InvalidState.as_code(),
                                "sse_write_prio_while_enabled_invalid_state",
                            );
                        } else {
                            ctx.expect(false, "sse_write_prio_while_enabled_invalid_state");
                        }

                        let unreg_enabled = sbi::sse::unregister(sbi::sse::EVENT_LOCAL_SOFTWARE);
                        ctx.expect_sbi_err(
                            sbi::error_code(unreg_enabled),
                            SbiError::InvalidState.as_code(),
                            "sse_unregister_while_enabled_invalid_state",
                        );

                        match session.is_injectable() {
                            Ok(true) => match session.inject_and_measure(timeout) {
                                Ok(_) => {
                                    ctx.expect(
                                        session.last_handler_hart_id() == boot_hart_id,
                                        "sse_inject_delivered_with_matching_hart_id",
                                    );
                                }
                                Err(err) => ctx.record_fail("sse_inject_roundtrip", err),
                            },
                            Ok(false) => {
                                ctx.observe(
                                    "sse_event_not_injectable",
                                    IssueClass::PermittedBehavior,
                                );
                            }
                            Err(err) => {
                                ctx.expect_sbi_err(err.as_code(), 0, "sse_read_injectable_status");
                            }
                        }

                        if let Err(err) = session.finish() {
                            ctx.record_fail("sse_disable_unregister", err);
                        }
                    }
                    Err(err) => {
                        ctx.expect_sbi_err(err.as_code(), 0, "sse_register_local_software");
                    }
                }
            }
        }
        Err(SbiError::NotSupported) => {
            ctx.observe("sse_local_software_unsupported", IssueClass::Unsupported);
        }
        Err(err) => {
            ctx.expect_sbi_err(err.as_code(), 0, "sse_probe_local_software_status");
        }
    }

    let inv_fid = sbi::probe_invalid_fid(SbiExtensionId::Sse);
    ctx.expect_sbi_err(
        sbi::error_code(inv_fid),
        SbiError::NotSupported.as_code(),
        "sse_invalid_fid",
    );

    ctx.finish()
}
