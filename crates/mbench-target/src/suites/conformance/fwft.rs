//! SBI Firmware Features (`FWFT`, SBI v3.0) conformance checks.

use mbench_core::{
    check::{CheckCase, CheckCtx, CheckOutcome},
    record::{CaseFlags, IssueClass, SbiExtensionId},
};

use super::check_case;
use crate::{
    platform::Platform,
    sbi::{self, SbiError, fwft::FwftFeatureId},
};

pub(super) static CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/fwft",
    Some(SbiExtensionId::Fwft),
    1,
    CaseFlags::empty(),
    conf_fwft,
)];

fn conf_fwft(_env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();

    for (feat, label_get, label_set) in [
        (
            sbi::fwft::FEAT_LOCAL_RESERVED,
            "fwft_reserved_local_get_denied",
            "fwft_reserved_local_set_denied",
        ),
        (
            sbi::fwft::FEAT_GLOBAL_RESERVED,
            "fwft_reserved_global_get_denied",
            "fwft_reserved_global_set_denied",
        ),
    ] {
        let g = sbi::fwft::get(feat);
        ctx.expect_sbi_err(sbi::error_code(g), SbiError::Denied.as_code(), label_get);
        let s = sbi::fwft::set(feat, 0, 0);
        ctx.expect_sbi_err(sbi::error_code(s), SbiError::Denied.as_code(), label_set);
    }

    let mut supported_first: Option<(FwftFeatureId, usize)> = None;
    let mut misalign_orig: Option<usize> = None;

    for feat in FwftFeatureId::ALL {
        let g = sbi::fwft::get(feat.as_usize());
        let code = sbi::error_code(g);
        ctx.expect(
            code == 0 || code == SbiError::NotSupported.as_code(),
            "fwft_defined_feature_get_status",
        );
        if code == 0 {
            if supported_first.is_none() {
                supported_first = Some((feat, g.value));
            }
            if feat == FwftFeatureId::MisalignedExcDeleg {
                misalign_orig = Some(g.value);
            }
        }
    }

    if let Some((feat, orig_val)) = supported_first {
        let id = feat.as_usize();
        let idem = sbi::fwft::set(id, orig_val, 0);
        let idem_code = sbi::error_code(idem);
        let mut confirmed_writable = false;
        if idem_code == SbiError::DeniedLocked.as_code() {
            ctx.observe("fwft_feature_locked", IssueClass::PermittedBehavior);
        } else if idem_code == SbiError::Denied.as_code() {
            ctx.observe("fwft_feature_policy_denied", IssueClass::PermittedBehavior);
        } else if ctx.expect_sbi_err(idem_code, 0, "fwft_idempotent_set") {
            confirmed_writable = true;
        }

        if confirmed_writable {
            let bad_flags = sbi::fwft::set(id, orig_val, sbi::fwft::FLAG_INVALID_RESERVED);
            ctx.expect_sbi_err(
                sbi::error_code(bad_flags),
                SbiError::InvalidParam.as_code(),
                "fwft_reserved_flag_rejected",
            );

            if matches!(
                feat,
                FwftFeatureId::MisalignedExcDeleg
                    | FwftFeatureId::LandingPad
                    | FwftFeatureId::ShadowStack
                    | FwftFeatureId::DoubleTrap
                    | FwftFeatureId::PteAdHwUpdating
            ) {
                let bad_val = sbi::fwft::set(id, 2, 0);
                ctx.expect_sbi_err(
                    sbi::error_code(bad_val),
                    SbiError::InvalidParam.as_code(),
                    "fwft_invalid_bool_value_rejected",
                );
            }
        }
    } else {
        ctx.observe("fwft_no_supported_features", IssueClass::PermittedBehavior);
    }

    if let Some(orig) = misalign_orig {
        let toggled = orig ^ 1;
        let set_tog = sbi::fwft::set(sbi::fwft::FEAT_MISALIGNED_EXC_DELEG, toggled, 0);
        let code = sbi::error_code(set_tog);
        if code == 0 {
            let after = sbi::fwft::get(sbi::fwft::FEAT_MISALIGNED_EXC_DELEG);
            ctx.expect(
                after.error == 0 && after.value == toggled,
                "fwft_misalign_toggle_reflected",
            );
            let restore = sbi::fwft::set(sbi::fwft::FEAT_MISALIGNED_EXC_DELEG, orig, 0);
            ctx.expect_sbi_err(sbi::error_code(restore), 0, "fwft_misalign_restored");
        } else if code == SbiError::DeniedLocked.as_code()
            || code == SbiError::Denied.as_code()
            || code == SbiError::NotSupported.as_code()
        {
            ctx.observe("fwft_misalign_immutable", IssueClass::PermittedBehavior);
        } else {
            ctx.expect_sbi_err(code, 0, "fwft_misalign_toggle");
        }
    }

    let inv_fid = sbi::probe_invalid_fid(SbiExtensionId::Fwft);
    ctx.expect_sbi_err(
        sbi::error_code(inv_fid),
        SbiError::NotSupported.as_code(),
        "fwft_invalid_fid",
    );

    ctx.finish()
}
