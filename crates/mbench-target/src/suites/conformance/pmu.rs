//! SBI PMU (`PMU`, SBI v3.0) counter, firmware lifecycle, snapshot, and event_get_info checks.

use mbench_core::{
    check::{CheckCase, CheckCtx, CheckOutcome},
    record::{CaseFlags, IssueClass, SbiExtensionId},
};

use super::check_case;
use crate::{
    platform::{
        Platform,
        shmem::{ShmemAcquire, ShmemOwner},
    },
    sbi::{
        self, SbiError,
        pmu::{EventInfoEntry, config_flags, start_flags, stop_flags},
    },
    suites::ext_pmu::PmuCounterGuard,
};

pub(super) static CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/pmu",
    Some(SbiExtensionId::Pmu),
    1,
    CaseFlags::empty(),
    conf_pmu,
)];

fn conf_pmu(env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();
    let has_time_ext = env.caps().extensions.contains_ext(SbiExtensionId::Time);

    let num = sbi::pmu::num_counters();
    if ctx
        .require(num.error == 0 && num.value > 0, "pmu_num_counters_pos")
        .is_err()
    {
        return ctx.finish();
    }
    let count = num.value;

    let mut first_hw: Option<usize> = None;
    let mut valid_counters = 0usize;
    for idx in 0..count {
        let info_ret = sbi::pmu::counter_get_info(idx);
        let code = sbi::error_code(info_ret);
        if idx == 0 || idx == 2 {
            ctx.expect_sbi_err(code, 0, "pmu_fixed_counter_get_info");
        } else {
            // Unimplemented HW counter holes (especially `idx == 1` for `time`) return `INVALID_PARAM`.
            ctx.expect_sbi_err_in(
                code,
                &[0, SbiError::InvalidParam.as_code()],
                "pmu_counter_get_info_slot",
            );
        }
        if info_ret.error == 0 {
            valid_counters += 1;
            if !sbi::pmu::info_is_firmware(info_ret.value) {
                if first_hw.is_none() {
                    first_hw = Some(idx);
                }
                let width = sbi::pmu::info_width(info_ret.value);
                let csr = sbi::pmu::info_csr(info_ret.value);
                ctx.expect(
                    (1..=64).contains(&width) && csr >= 0x0c00,
                    "pmu_hw_counter_info_valid",
                );
            }
        }
    }
    ctx.expect(valid_counters > 0, "pmu_has_valid_counter");

    let oob_info = sbi::pmu::counter_get_info(count);
    ctx.expect_sbi_err(
        sbi::error_code(oob_info),
        SbiError::InvalidParam.as_code(),
        "pmu_info_oob_invalid_param",
    );

    if let Some(hw_idx) = first_hw {
        let fw_on_hw = sbi::pmu::counter_fw_read(hw_idx);
        ctx.expect_sbi_err(
            sbi::error_code(fw_on_hw),
            SbiError::InvalidParam.as_code(),
            "pmu_fw_read_on_hw_rejected",
        );
        // OpenSBI v1.8.1 RV64 `sbi_ecall_pmu_handler` hardcodes `out->value = 0` without checking `counter_idx`.
        let fw_hi_on_hw = sbi::pmu::counter_fw_read_hi(hw_idx);
        ctx.expect_sbi_err_quirk(
            sbi::error_code(fw_hi_on_hw),
            SbiError::InvalidParam.as_code(),
            0,
            "opensbi-v1.8.1:pmu-fw-read-hi-skips-cidx-check",
            "pmu_fw_read_hi_on_hw_rejected",
        );
    }

    match PmuCounterGuard::try_configure_firmware(env, sbi::pmu::FW_SET_TIMER) {
        Ok(Some(mut guard)) => {
            let idx = guard.idx();
            let hi = sbi::pmu::counter_fw_read_hi(idx);
            ctx.expect(hi.error == 0 && hi.value == 0, "pmu_fw_read_hi_rv64_zero");

            let st = sbi::pmu::counter_start(idx, 1, start_flags::SET_INIT_VALUE, 100);
            if st.error == 0 {
                guard.mark_running();
            }
            ctx.expect_sbi_err(sbi::error_code(st), 0, "pmu_fw_start_init");

            let dup_st = sbi::pmu::counter_start(idx, 1, 0, 0);
            ctx.expect_sbi_err(
                sbi::error_code(dup_st),
                SbiError::AlreadyStarted.as_code(),
                "pmu_fw_double_start_already_started",
            );

            let r0 = sbi::pmu::counter_fw_read(idx);
            ctx.expect(r0.error == 0 && r0.value >= 100, "pmu_fw_init_value");

            if has_time_ext {
                let _ = sbi::time::set_timer(u64::MAX);
            }
            let r1 = sbi::pmu::counter_fw_read(idx);
            let monotonic =
                r1.error == 0 && (!has_time_ext && r1.value >= r0.value || r1.value > r0.value);
            ctx.expect(monotonic, "pmu_fw_monotonic");

            let sp = sbi::pmu::counter_stop(idx, 1, 0);
            if sp.error == 0 {
                guard.mark_stopped();
            }
            ctx.expect_sbi_err(sbi::error_code(sp), 0, "pmu_fw_stop_ok");

            let dup_sp = sbi::pmu::counter_stop(idx, 1, 0);
            ctx.expect_sbi_err(
                sbi::error_code(dup_sp),
                SbiError::AlreadyStopped.as_code(),
                "pmu_fw_double_stop_already_stopped",
            );

            // Reset firmware counter and test reserved flag bits only if clean reset succeeded.
            if let Err(err) = guard.stop_and_reset() {
                ctx.record_fail("pmu_fw_stop_and_reset", err);
            } else {
                let (bad_cfg_flags, bad_cfg_adopt) = guard.reconfigure_with_flags(
                    config_flags::RESERVED_BIT,
                    sbi::pmu::FW_SET_TIMER,
                    0,
                );
                if bad_cfg_flags.error == 0
                    && let Err(err) = bad_cfg_adopt.and_then(|()| guard.stop_and_reset())
                {
                    ctx.record_fail("pmu_cfg_reserved_flag_reset", err);
                }
                ctx.expect_sbi_err_quirk(
                    sbi::error_code(bad_cfg_flags),
                    SbiError::InvalidParam.as_code(),
                    0,
                    "opensbi-v1.8.1:pmu-ignores-reserved-flags",
                    "pmu_cfg_reserved_flag_rejected",
                );

                if !guard.is_configured() {
                    let (recfg, recfg_adopt) =
                        guard.reconfigure_with_flags(0, sbi::pmu::FW_SET_TIMER, 0);
                    ctx.expect_sbi_err(sbi::error_code(recfg), 0, "pmu_fw_reconfig_after_reset");
                    if recfg.error == 0 {
                        match recfg_adopt {
                            Ok(()) => {
                                let bad_start_flags =
                                    sbi::pmu::counter_start(idx, 1, start_flags::RESERVED_BIT, 0);
                                if bad_start_flags.error == 0 {
                                    guard.mark_running();
                                }
                                ctx.expect_sbi_err_quirk(
                                    sbi::error_code(bad_start_flags),
                                    SbiError::InvalidParam.as_code(),
                                    0,
                                    "opensbi-v1.8.1:pmu-ignores-reserved-flags",
                                    "pmu_start_reserved_flag_rejected",
                                );
                                if bad_start_flags.error != 0 {
                                    let start_ok = sbi::pmu::counter_start(idx, 1, 0, 0);
                                    if start_ok.error == 0 {
                                        guard.mark_running();
                                    }
                                }
                                let bad_stop_flags =
                                    sbi::pmu::counter_stop(idx, 1, stop_flags::RESERVED_BIT);
                                if bad_stop_flags.error == 0 {
                                    guard.mark_stopped();
                                }
                                ctx.expect_sbi_err_quirk(
                                    sbi::error_code(bad_stop_flags),
                                    SbiError::InvalidParam.as_code(),
                                    0,
                                    "opensbi-v1.8.1:pmu-ignores-reserved-flags",
                                    "pmu_stop_reserved_flag_rejected",
                                );
                            }
                            Err(err) => ctx.record_fail("pmu_fw_reconfig_returned_idx", err),
                        }
                    }
                }
            }

            if let Err(err) = guard.finish_reset() {
                ctx.record_fail("pmu_fw_reset_cleanup", err);
            }
        }
        Ok(None) => {
            ctx.observe(
                "pmu_fw_set_timer_unavailable",
                IssueClass::PermittedBehavior,
            );
        }
        Err(err) => {
            ctx.record_fail("pmu_configure_fw_set_timer", err);
        }
    }

    let (oob_cfg, oob_cleanup) = PmuCounterGuard::probe_config_matching_and_cleanup(
        env,
        count,
        1,
        0,
        sbi::pmu::FW_SET_TIMER,
        0,
    );
    ctx.expect_sbi_err(
        sbi::error_code(oob_cfg),
        SbiError::InvalidParam.as_code(),
        "pmu_cfg_oob_invalid_param",
    );
    if let Err(err) = oob_cleanup {
        ctx.record_fail("pmu_cfg_oob_cleanup", err);
    }

    let oob_start = sbi::pmu::counter_start(count, 1, 0, 0);
    ctx.expect_sbi_err(
        sbi::error_code(oob_start),
        SbiError::InvalidParam.as_code(),
        "pmu_oob_start",
    );

    let snap_start_no_shmem = sbi::pmu::counter_start(0, 1, start_flags::INIT_FROM_SNAPSHOT, 0);
    ctx.expect_sbi_err_in(
        sbi::error_code(snap_start_no_shmem),
        &[
            SbiError::NoShmem.as_code(),
            SbiError::InvalidParam.as_code(),
        ],
        "pmu_start_init_snapshot_no_shmem",
    );

    let oob_stop = sbi::pmu::counter_stop(count, 1, 0);
    ctx.expect_sbi_err(
        sbi::error_code(oob_stop),
        SbiError::InvalidParam.as_code(),
        "pmu_oob_stop",
    );

    let snap_stop_no_shmem = sbi::pmu::counter_stop(0, 1, stop_flags::TAKE_SNAPSHOT);
    ctx.expect_sbi_err_in(
        sbi::error_code(snap_stop_no_shmem),
        &[
            SbiError::NoShmem.as_code(),
            SbiError::InvalidParam.as_code(),
        ],
        "pmu_stop_take_snapshot_no_shmem",
    );

    match env.lease_shmem(ShmemOwner::PmuSnapshot) {
        Ok(ShmemAcquire::Leased(lease)) => {
            if let Err(err) = lease.finish() {
                ctx.record_fail("pmu_snapshot_lease_finish", err);
            } else {
                ctx.record_pass();
            }
        }
        Ok(ShmemAcquire::Unsupported) => {
            ctx.observe("pmu_snapshot_optional", IssueClass::Unsupported);
        }
        Ok(ShmemAcquire::TooLarge) => {
            ctx.observe("pmu_snapshot_too_large", IssueClass::Unsupported);
        }
        Err(err) => ctx.record_fail("pmu_snapshot_lease", err),
    }

    let mut entries = [EventInfoEntry {
        event_idx: sbi::pmu::HW_CPU_CYCLES as u32,
        output: 0xDEAD_BEEF,
        event_data: 0,
    }];
    match env.probe_pmu_event_get_info(&mut entries, 0, 0) {
        Ok(ret) => {
            if sbi::error_code(ret) == SbiError::NotSupported.as_code() {
                ctx.observe("pmu_event_get_info_optional", IssueClass::Unsupported);
            } else {
                ctx.expect_sbi_err(sbi::error_code(ret), 0, "pmu_event_get_info_valid");
                if ret.error == 0 {
                    ctx.expect(
                        (entries[0].output >> 1) == 0,
                        "pmu_event_get_info_reserved_output_zero",
                    );
                }

                let mut bad_flag_entries = [EventInfoEntry {
                    event_idx: sbi::pmu::HW_CPU_CYCLES as u32,
                    output: 0,
                    event_data: 0,
                }];
                match env.probe_pmu_event_get_info(&mut bad_flag_entries, 1, 0) {
                    Ok(bad_fl) => {
                        ctx.expect_sbi_err(
                            sbi::error_code(bad_fl),
                            SbiError::InvalidParam.as_code(),
                            "pmu_event_get_info_bad_flags",
                        );
                    }
                    Err(err) => ctx.record_fail("pmu_event_get_info_bad_flags_probe", err),
                }

                match env.probe_pmu_event_get_info(&mut [], 0, 0) {
                    Ok(zero_num) => {
                        let code = sbi::error_code(zero_num);
                        if code == 0 {
                            ctx.observe(
                                "pmu_event_get_info_zero_entries_success",
                                IssueClass::PermittedBehavior,
                            );
                        } else if code == SbiError::InvalidParam.as_code() {
                            ctx.observe(
                                "pmu_event_get_info_zero_entries_invalid_param",
                                IssueClass::PermittedBehavior,
                            );
                        } else {
                            ctx.expect_sbi_err_in(
                                code,
                                &[0, SbiError::InvalidParam.as_code()],
                                "pmu_event_get_info_zero_entries",
                            );
                        }
                    }
                    Err(err) => ctx.record_fail("pmu_event_get_info_zero_entries_probe", err),
                }

                let mut reserved_idx_entries = [EventInfoEntry {
                    event_idx: (sbi::pmu::HW_CPU_CYCLES as u32) | sbi::pmu::EVENT_IDX_RESERVED_BIT,
                    output: 0,
                    event_data: 0,
                }];
                match env.probe_pmu_event_get_info(&mut reserved_idx_entries, 0, 0) {
                    Ok(res_idx) => {
                        // OpenSBI v1.8.1 `sbi_pmu_event_get_info` / `pmu_event_validate` masks off
                        // `event_idx[31:20]` and returns `SBI_SUCCESS`.
                        ctx.expect_sbi_err_quirk(
                            sbi::error_code(res_idx),
                            SbiError::InvalidParam.as_code(),
                            0,
                            "opensbi-v1.8.1:pmu-event-info-ignores-reserved-event-idx",
                            "pmu_event_get_info_reserved_event_idx",
                        );
                    }
                    Err(err) => {
                        ctx.record_fail("pmu_event_get_info_reserved_event_idx_probe", err);
                    }
                }

                let mut unaligned = [EventInfoEntry {
                    event_idx: sbi::pmu::HW_CPU_CYCLES as u32,
                    output: 0,
                    event_data: 0,
                }];
                match env.probe_pmu_event_get_info(&mut unaligned, 0, 8) {
                    Ok(unal_ret) => {
                        ctx.expect_sbi_err(
                            sbi::error_code(unal_ret),
                            SbiError::InvalidParam.as_code(),
                            "pmu_event_get_info_unaligned",
                        );
                    }
                    Err(err) => ctx.record_fail("pmu_event_get_info_unaligned_probe", err),
                }
            }
        }
        Err(err) => ctx.record_fail("pmu_event_get_info_probe", err),
    }

    let inv_fid = sbi::probe_invalid_fid(SbiExtensionId::Pmu);
    ctx.expect_sbi_err(
        sbi::error_code(inv_fid),
        SbiError::NotSupported.as_code(),
        "pmu_invalid_fid",
    );

    ctx.finish()
}
