//! SBI Base extension (`EID = 0x10`) and ABI register-preservation conformance checks.

use mbench_core::{
    check::{CheckCase, CheckCtx, CheckOutcome},
    record::{CaseFlags, SbiExtensionId},
};

use super::check_case;
use crate::{
    platform::Platform,
    sbi::{self, SbiError},
};

pub(super) static CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/base",
    Some(SbiExtensionId::Base),
    1,
    CaseFlags::empty(),
    conf_base,
)];

fn conf_base(env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();
    ctx.expect(env.caps().base_probe_errors == 0, "base_caps_probe_clean");

    let spec = sbi::base::get_spec_version();
    ctx.expect_sbi_err(sbi::error_code(spec), 0, "base_get_spec_version");
    let spec_reserved_zero = (spec.value >> 31) == 0;
    let spec_nonzero = (spec.value & 0x7fff_ffff) >= 2;
    ctx.expect(
        spec_reserved_zero && spec_nonzero,
        "base_spec_version_format",
    );

    for (ret, label) in [
        (sbi::base::get_impl_id(), "base_get_impl_id"),
        (sbi::base::get_impl_version(), "base_get_impl_version"),
        (sbi::base::get_mvendorid(), "base_get_mvendorid"),
        (sbi::base::get_marchid(), "base_get_marchid"),
        (sbi::base::get_mimpid(), "base_get_mimpid"),
    ] {
        ctx.expect_sbi_err(sbi::error_code(ret), 0, label);
    }

    let probe_base = sbi::base::probe_extension(sbi::base::EID);
    ctx.expect(
        probe_base.error == 0 && probe_base.value != 0,
        "base_probe_base_present",
    );

    let probe_unknown = sbi::base::probe_extension(0x7FFF_FFFF);
    ctx.expect(
        probe_unknown.error == 0 && probe_unknown.value == 0,
        "base_probe_unknown_zero",
    );

    let bad_eid = sbi::probe_invalid_eid();
    ctx.expect_sbi_err(
        sbi::error_code(bad_eid),
        SbiError::NotSupported.as_code(),
        "base_unassigned_eid_not_supported",
    );

    let (abi_ok_ret, abi_ok_preserved) = sbi::base::check_abi_preservation();
    ctx.expect_sbi_err(sbi::error_code(abi_ok_ret), 0, "base_abi_ok_ret");
    ctx.expect(abi_ok_preserved, "base_abi_ok_preserved");

    let (abi_err_ret, abi_err_preserved) = sbi::base::check_abi_preservation_on_error();
    ctx.expect_sbi_err(
        sbi::error_code(abi_err_ret),
        SbiError::NotSupported.as_code(),
        "base_abi_err_ret",
    );
    ctx.expect(abi_err_preserved, "base_abi_err_preserved");

    for ext in SbiExtensionId::ALL {
        if !env.caps().extensions.contains_ext(ext) {
            continue;
        }
        let (inv_fid, preserved) = sbi::probe_invalid_fid_abi(ext);
        ctx.expect_sbi_err(
            sbi::error_code(inv_fid),
            SbiError::NotSupported.as_code(),
            invalid_fid_label(ext),
        );
        ctx.expect(preserved, invalid_fid_abi_label(ext));
    }

    ctx.finish()
}

const fn invalid_fid_label(ext: SbiExtensionId) -> &'static str {
    match ext {
        SbiExtensionId::Base => "base_invalid_fid_not_supported",
        SbiExtensionId::Time => "time_ext_invalid_fid",
        SbiExtensionId::Spi => "spi_ext_invalid_fid",
        SbiExtensionId::Rfnc => "rfnc_ext_invalid_fid",
        SbiExtensionId::Hsm => "hsm_ext_invalid_fid",
        SbiExtensionId::Srst => "srst_ext_invalid_fid",
        SbiExtensionId::Pmu => "pmu_ext_invalid_fid",
        SbiExtensionId::Dbcn => "dbcn_ext_invalid_fid",
        SbiExtensionId::Susp => "susp_ext_invalid_fid",
        SbiExtensionId::Cppc => "cppc_ext_invalid_fid",
        SbiExtensionId::Nacl => "nacl_ext_invalid_fid",
        SbiExtensionId::Sta => "sta_ext_invalid_fid",
        SbiExtensionId::Sse => "sse_ext_invalid_fid",
        SbiExtensionId::Fwft => "fwft_ext_invalid_fid",
        SbiExtensionId::Dbtr => "dbtr_ext_invalid_fid",
        SbiExtensionId::Mpxy => "mpxy_ext_invalid_fid",
    }
}

const fn invalid_fid_abi_label(ext: SbiExtensionId) -> &'static str {
    match ext {
        SbiExtensionId::Base => "base_invalid_fid_abi",
        SbiExtensionId::Time => "time_invalid_fid_abi",
        SbiExtensionId::Spi => "spi_invalid_fid_abi",
        SbiExtensionId::Rfnc => "rfnc_invalid_fid_abi",
        SbiExtensionId::Hsm => "hsm_invalid_fid_abi",
        SbiExtensionId::Srst => "srst_invalid_fid_abi",
        SbiExtensionId::Pmu => "pmu_invalid_fid_abi",
        SbiExtensionId::Dbcn => "dbcn_invalid_fid_abi",
        SbiExtensionId::Susp => "susp_invalid_fid_abi",
        SbiExtensionId::Cppc => "cppc_invalid_fid_abi",
        SbiExtensionId::Nacl => "nacl_invalid_fid_abi",
        SbiExtensionId::Sta => "sta_invalid_fid_abi",
        SbiExtensionId::Sse => "sse_invalid_fid_abi",
        SbiExtensionId::Fwft => "fwft_invalid_fid_abi",
        SbiExtensionId::Dbtr => "dbtr_invalid_fid_abi",
        SbiExtensionId::Mpxy => "mpxy_invalid_fid_abi",
    }
}
