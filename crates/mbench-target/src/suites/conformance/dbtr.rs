//! SBI Debug Triggers (`DBTR`, SBI v3.0) lifecycle and quirk-preserving conformance checks.

use mbench_core::{
    check::{CheckCase, CheckCtx, CheckOutcome},
    record::{CaseFlags, IssueClass, SbiExtensionId, SkipReason},
};
use riscv::interrupt::{Exception, Trap};

use super::check_case;
use crate::{
    platform::{
        Platform,
        shmem::{
            DbtrAcquire, DbtrSession, dbtr_exec_target_addr, dbtr_scratch_addr, pick_match_trigger,
            probe_dbtr_exec_target, probe_dbtr_load_scratch,
        },
    },
    sbi::{
        self, SbiError,
        dbtr::{TriggerAccess, TriggerData, tstate},
    },
};

pub(super) static CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/dbtr",
    Some(SbiExtensionId::Dbtr),
    1,
    CaseFlags::empty(),
    conf_dbtr,
)];

fn verify_trigger_lifecycle(
    ctx: &mut CheckCtx,
    session: &mut DbtrSession<'_>,
    trig_max: usize,
    data: TriggerData,
    updated_data: TriggerData,
    probe_fn: fn() -> bool,
) -> bool {
    let idx = match session.install_single(data) {
        Ok(i) => {
            ctx.expect(i < trig_max, "dbtr_installed_idx_in_range");
            i
        }
        Err(err) => {
            ctx.record_fail("dbtr_install_single", err);
            return false;
        }
    };

    if idx + 1 < trig_max {
        let rd = session.read_triggers(idx, 1);
        ctx.expect_sbi_err(sbi::error_code(rd), 0, "dbtr_read_installed");
        if rd.error == 0 {
            let entry = session.read_trigger_data_at(0);
            ctx.expect(
                (entry.tstate & tstate::MAPPED) != 0 && (entry.tstate & tstate::S) != 0,
                "dbtr_tstate_mapped_and_s",
            );
        }
    }

    ctx.expect(probe_fn(), "dbtr_breakpoint_fires_after_install");

    let dis = session.disable_installed(idx);
    ctx.expect_sbi_err(sbi::error_code(dis), 0, "dbtr_disable_installed");
    ctx.expect(!probe_fn(), "dbtr_no_trap_when_disabled");

    let en = session.enable_installed(idx);
    ctx.expect_sbi_err(sbi::error_code(en), 0, "dbtr_enable_installed");
    ctx.expect(probe_fn(), "dbtr_breakpoint_fires_after_enable");

    let dis2 = session.disable_installed(idx);
    ctx.expect_sbi_err(sbi::error_code(dis2), 0, "dbtr_disable_before_update");

    let upd = session.update_single(idx, updated_data);
    ctx.expect_sbi_err(sbi::error_code(upd), 0, "dbtr_update_single");
    let dis3 = session.disable_installed(idx);
    ctx.expect_sbi_err(sbi::error_code(dis3), 0, "dbtr_disable_after_update");

    let bad_upd_idx = session.update_single(trig_max, updated_data);
    ctx.expect_sbi_err(
        sbi::error_code(bad_upd_idx),
        SbiError::InvalidParam.as_code(),
        "dbtr_update_bad_trig_idx",
    );

    if trig_max >= 2 {
        let bad_upd_range = session.update_raw(
            trig_max,
            TriggerData {
                tstate: idx,
                ..updated_data
            },
        );
        ctx.expect_sbi_err(
            sbi::error_code(bad_upd_range),
            SbiError::BadRange.as_code(),
            "dbtr_update_count_bad_range",
        );
    }

    let uninst = session.uninstall_installed(idx);
    ctx.expect_sbi_err(sbi::error_code(uninst), 0, "dbtr_uninstall_installed");
    if uninst.error != 0 {
        return false;
    }

    let double_uninst = sbi::dbtr::uninstall_triggers(idx, 1);
    ctx.expect_sbi_err(
        sbi::error_code(double_uninst),
        SbiError::InvalidParam.as_code(),
        "dbtr_double_uninstall_invalid_param",
    );
    true
}

fn probe_load_trapped_breakpoint() -> bool {
    matches!(
        probe_dbtr_load_scratch(),
        Err(info) if info.cause() == Ok(Trap::Exception(Exception::Breakpoint))
    )
}

fn probe_exec_trapped_breakpoint() -> bool {
    matches!(
        probe_dbtr_exec_target(),
        Err(info) if info.cause() == Ok(Trap::Exception(Exception::Breakpoint))
    )
}

fn conf_dbtr(env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();

    let num_ret = sbi::dbtr::num_triggers(0);
    if !ctx.expect_sbi_err(sbi::error_code(num_ret), 0, "dbtr_num_triggers") {
        return ctx.finish();
    }
    let trig_max = num_ret.value;

    if trig_max == 0 {
        ctx.observe("dbtr_zero_triggers", IssueClass::PermittedBehavior);
        let inv_fid = sbi::probe_invalid_fid(SbiExtensionId::Dbtr);
        ctx.expect_sbi_err(
            sbi::error_code(inv_fid),
            SbiError::NotSupported.as_code(),
            "dbtr_invalid_fid",
        );
        return ctx.finish();
    }

    let mut session = match env.start_dbtr_session() {
        Ok(DbtrAcquire::Active(s)) => s,
        Ok(DbtrAcquire::TooLarge) => {
            return ctx.finish_or_skip(SkipReason::ShmemTooLarge);
        }
        Err(err) => {
            ctx.record_fail("dbtr_start_session", err);
            return ctx.finish();
        }
    };

    // Spec defines no ALREADY_AVAILABLE precondition on `set_shmem`; OpenSBI v1.8.1 rejects active re-register with -6.
    let rereg = session.reregister_shmem();
    ctx.expect_sbi_err_quirk(
        sbi::error_code(rereg),
        0,
        SbiError::AlreadyAvailable.as_code(),
        "opensbi-v1.8.1:dbtr-reregister-already-available",
        "dbtr_shmem_reregister",
    );

    // Spec expects BAD_RANGE (-11) for out-of-range reads; OpenSBI v1.8.1 returns INVALID_PARAM (-3).
    let oob_rd = session.read_triggers(trig_max, 1);
    ctx.expect_sbi_err_quirk(
        sbi::error_code(oob_rd),
        SbiError::BadRange.as_code(),
        SbiError::InvalidParam.as_code(),
        "opensbi-v1.8.1:dbtr-read-bad-range-einval",
        "dbtr_read_oob_bad_range",
    );

    // SBI v3.0 specifies `base + count >= trig_max` and install `count >= trig_max` are out-of-range,
    // so read(0, 1) and install(1) require at least 2 triggers.
    if trig_max < 2 {
        ctx.observe(
            "dbtr_single_trigger_capacity_limit",
            IssueClass::Unsupported,
        );
    } else {
        let dis_shmem = session.disable_shmem();
        ctx.expect_sbi_err(sbi::error_code(dis_shmem), 0, "dbtr_disable_shmem");
        if dis_shmem.error == 0 {
            let no_shmem = session.read_triggers(0, 1);
            ctx.expect_sbi_err(
                sbi::error_code(no_shmem),
                SbiError::NoShmem.as_code(),
                "dbtr_read_no_shmem",
            );
            let en_shmem = session.enable_shmem();
            if !ctx.expect_sbi_err(sbi::error_code(en_shmem), 0, "dbtr_re_enable_shmem") {
                if let Err(err) = session.finish() {
                    ctx.record_fail("dbtr_session_finish", err);
                }
                return ctx.finish();
            }
        }

        let rd_ok = session.read_triggers(0, 1);
        ctx.expect_sbi_err(sbi::error_code(rd_ok), 0, "dbtr_read_valid");

        let mut tested_hw = false;
        let mut can_continue = true;
        match pick_match_trigger(TriggerAccess::Load, dbtr_scratch_addr()) {
            Ok(Some(load_data)) => {
                let updated_load = TriggerData {
                    tdata2: dbtr_scratch_addr() + 4,
                    ..load_data
                };
                can_continue = verify_trigger_lifecycle(
                    &mut ctx,
                    &mut session,
                    trig_max,
                    load_data,
                    updated_load,
                    probe_load_trapped_breakpoint,
                );
                tested_hw = true;
            }
            Ok(None) => {}
            Err(err) => ctx.record_fail("dbtr_pick_load_trigger", err),
        }

        if can_continue {
            match pick_match_trigger(TriggerAccess::Exec, dbtr_exec_target_addr()) {
                Ok(Some(exec_data)) => {
                    let _ = verify_trigger_lifecycle(
                        &mut ctx,
                        &mut session,
                        trig_max,
                        exec_data,
                        exec_data,
                        probe_exec_trapped_breakpoint,
                    );
                    tested_hw = true;
                }
                Ok(None) => {}
                Err(err) => ctx.record_fail("dbtr_pick_exec_trigger", err),
            }
        }

        if !tested_hw {
            ctx.observe("dbtr_no_smode_match_trigger", IssueClass::Unsupported);
        }
    }

    if let Err(err) = session.finish() {
        ctx.record_fail("dbtr_session_finish", err);
    }

    let inv_fid = sbi::probe_invalid_fid(SbiExtensionId::Dbtr);
    ctx.expect_sbi_err(
        sbi::error_code(inv_fid),
        SbiError::NotSupported.as_code(),
        "dbtr_invalid_fid",
    );

    ctx.finish()
}
