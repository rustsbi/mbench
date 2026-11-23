//! Non-destructive conformance checks for `SRST`, `SUSP`, `CPPC`, `NACL`, `STA`, `MPXY`, and legacy EIDs.

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
    sbi::{self, SbiError},
};

pub(super) static CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/system",
    Some(SbiExtensionId::Base),
    1,
    CaseFlags::empty(),
    conf_system,
)];

fn conf_system(env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();
    let exts = env.caps().extensions;

    if exts.contains_ext(SbiExtensionId::Srst) {
        let bad_type = sbi::srst::probe_invalid_reset(sbi::srst::InvalidResetProbe::ReservedType);
        ctx.expect_sbi_err(
            sbi::error_code(bad_type),
            SbiError::InvalidParam.as_code(),
            "srst_reserved_type_invalid_param",
        );
        let bad_reason =
            sbi::srst::probe_invalid_reset(sbi::srst::InvalidResetProbe::ReservedReason);
        ctx.expect_sbi_err(
            sbi::error_code(bad_reason),
            SbiError::InvalidParam.as_code(),
            "srst_reserved_reason_invalid_param",
        );
    }

    if exts.contains_ext(SbiExtensionId::Susp) {
        match env.probe_invalid_sleep_type() {
            Ok(code) => {
                ctx.expect_sbi_err(
                    code,
                    SbiError::InvalidParam.as_code(),
                    "susp_reserved_sleep_type_invalid_param",
                );
            }
            Err(err) => ctx.record_fail("susp_reserved_sleep_type_invalid_param", err),
        }
    }

    if exts.contains_ext(SbiExtensionId::Cppc) {
        let p_high = sbi::cppc::probe(sbi::cppc::REG_HIGHEST_PERF);
        ctx.expect_sbi_err(sbi::error_code(p_high), 0, "cppc_probe_highest_perf");
        let p_bad = sbi::cppc::probe(sbi::cppc::REG_INVALID_RESERVED);
        ctx.expect_sbi_err(
            sbi::error_code(p_bad),
            SbiError::InvalidParam.as_code(),
            "cppc_probe_reserved_invalid_param",
        );
        let r_bad = sbi::cppc::read(sbi::cppc::REG_INVALID_RESERVED);
        ctx.expect_sbi_err(
            sbi::error_code(r_bad),
            SbiError::InvalidParam.as_code(),
            "cppc_read_reserved_invalid_param",
        );
        if p_high.error == 0 && p_high.value > 0 {
            let rd = sbi::cppc::read(sbi::cppc::REG_HIGHEST_PERF);
            ctx.expect_sbi_err(sbi::error_code(rd), 0, "cppc_read_highest_perf");
            let rd_hi = sbi::cppc::read_hi(sbi::cppc::REG_HIGHEST_PERF);
            ctx.expect(
                rd_hi.error == 0 && rd_hi.value == 0,
                "cppc_read_hi_rv64_zero",
            );
        } else {
            ctx.observe("cppc_highest_perf_unimplemented", IssueClass::Unsupported);
        }
    }

    if exts.contains_ext(SbiExtensionId::Nacl) {
        for feat in [
            sbi::nacl::FEAT_SYNC_CSR,
            sbi::nacl::FEAT_SYNC_HFENCE,
            sbi::nacl::FEAT_SYNC_SRET,
            sbi::nacl::FEAT_AUTOSWAP_CSR,
        ] {
            let ret = sbi::nacl::probe_feature(feat);
            ctx.expect(
                ret.error == 0 && ret.value <= 1,
                "nacl_probe_feature_bool_ret",
            );
        }
    }

    if exts.contains_ext(SbiExtensionId::Mpxy) {
        let size_ret = sbi::mpxy::get_shmem_size();
        ctx.expect(
            size_ret.error == 0 && size_ret.value >= 4096 && size_ret.value.is_multiple_of(4096),
            "mpxy_shmem_size_page_aligned",
        );

        match env.lease_shmem(ShmemOwner::Mpxy) {
            Ok(ShmemAcquire::Leased(lease)) => {
                let ch_ret = lease.mpxy_get_channel_ids(0);
                let code = sbi::error_code(ch_ret);
                if code == 0 {
                    let hdr = lease.read_mpxy_channel_ids_header();
                    let needed_bytes = (hdr.returned as usize)
                        .checked_mul(size_of::<u32>())
                        .and_then(|n| n.checked_add(size_of::<sbi::mpxy::MpxyChannelIdsHeader>()));
                    ctx.expect(
                        ch_ret.value == 0
                            && needed_bytes.is_some_and(|b| b <= lease.registered_len()),
                        "mpxy_channel_ids_header_bounded",
                    );
                } else if code == SbiError::Failed.as_code() {
                    ctx.observe("mpxy_get_channel_ids_failed", IssueClass::PermittedBehavior);
                } else {
                    ctx.expect_sbi_err(code, 0, "mpxy_get_channel_ids");
                }
                if let Err(err) = lease.finish() {
                    ctx.record_fail("mpxy_lease_finish", err);
                }
            }
            Ok(ShmemAcquire::TooLarge) => {
                ctx.observe("mpxy_shmem_exceeds_pool", IssueClass::Unsupported);
            }
            Ok(ShmemAcquire::Unsupported) => {
                ctx.observe("mpxy_set_shmem_unsupported", IssueClass::Unsupported);
            }
            Err(err) => ctx.record_fail("mpxy_lease_acquire", err),
        }
    }

    let legacy_present = sbi::legacy::probe_legacy_eids();
    if !legacy_present.iter().any(|&p| p) {
        ctx.observe("legacy_v01_eids_absent", IssueClass::PermittedBehavior);
    } else {
        ctx.record_pass();
    }

    ctx.finish()
}
