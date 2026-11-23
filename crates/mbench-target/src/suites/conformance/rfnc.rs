//! SBI Remote Fence (`RFNC`) single-hart edge cases and SMP TLB shootdown visibility checks.

use mbench_core::{
    check::{CheckCase, CheckCtx, CheckOutcome},
    engine::HartCoordinator,
    record::{CaseFlags, SbiExtensionId, SkipReason},
};

use super::check_case;
use crate::{
    platform::Platform,
    sbi::{self, SbiError},
};

pub(super) static SINGLE_CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/rfnc",
    Some(SbiExtensionId::Rfnc),
    1,
    CaseFlags::empty(),
    conf_rfnc_single,
)];

pub(super) static MULTI_CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/rfnc_smp",
    Some(SbiExtensionId::Rfnc),
    2,
    CaseFlags::empty(),
    conf_rfnc_smp,
)];

fn conf_rfnc_single(env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();

    ctx.expect_sbi_err(
        sbi::error_code(sbi::rfnc::remote_fence_i(0, 0)),
        0,
        "rfnc_empty_fence_i",
    );
    ctx.expect_sbi_err(
        sbi::error_code(sbi::rfnc::remote_sfence_vma(0, 0, 0, 0)),
        0,
        "rfnc_empty_sfence_vma",
    );
    ctx.expect_sbi_err(
        sbi::error_code(sbi::rfnc::remote_sfence_vma_asid(0, 0, 0, 0, 1)),
        0,
        "rfnc_empty_sfence_vma_asid",
    );

    let has_h_ext = env.info().has_h_ext;
    let sv39 = match env.enable_sv39() {
        Ok(g) => g,
        Err(err) => {
            ctx.record_fail("rfnc_sv39_enable", err);
            return ctx.finish();
        }
    };
    let (mask, base) = sv39.self_hart_mask();
    let page = sv39.target_page_addr();
    let asid = sv39.sv39_asid();

    ctx.expect_sbi_err(
        sbi::error_code(sbi::rfnc::remote_fence_i(mask, base)),
        0,
        "rfnc_self_fence_i",
    );

    for (start, sz, label) in [
        (0, 0, "rfnc_sfence_all_zero_size"),
        (page, 4096, "rfnc_sfence_page"),
        (page, 16 * 4096, "rfnc_sfence_range_16"),
        (0, usize::MAX, "rfnc_sfence_full_max_size"),
        (page, usize::MAX, "rfnc_sfence_full_nonzero_start"),
    ] {
        let ret = sbi::rfnc::remote_sfence_vma(mask, base, start, sz);
        ctx.expect_sbi_err(sbi::error_code(ret), 0, label);
    }

    for (start, sz, label) in [
        (0, 0, "rfnc_sfence_asid_all_zero_size"),
        (page, 4096, "rfnc_sfence_asid_page"),
        (page, usize::MAX, "rfnc_sfence_asid_nonzero_start"),
    ] {
        let ret = sbi::rfnc::remote_sfence_vma_asid(mask, base, start, sz, asid);
        ctx.expect_sbi_err(sbi::error_code(ret), 0, label);
    }

    let bad_base = sbi::rfnc::remote_sfence_vma(1, usize::MAX - 1, page, 4096);
    ctx.expect_sbi_err(
        sbi::error_code(bad_base),
        SbiError::InvalidParam.as_code(),
        "rfnc_invalid_hart_mask_base",
    );

    if has_h_ext {
        ctx.expect_sbi_err(
            sbi::error_code(sbi::rfnc::remote_hfence_gvma(mask, base, 0, usize::MAX)),
            0,
            "rfnc_hfence_gvma",
        );
        ctx.expect_sbi_err(
            sbi::error_code(sbi::rfnc::remote_hfence_gvma_vmid(
                mask,
                base,
                0,
                usize::MAX,
                0,
            )),
            0,
            "rfnc_hfence_gvma_vmid",
        );
        ctx.expect_sbi_err(
            sbi::error_code(sbi::rfnc::remote_hfence_vvma(mask, base, 0, usize::MAX)),
            0,
            "rfnc_hfence_vvma",
        );
        ctx.expect_sbi_err(
            sbi::error_code(sbi::rfnc::remote_hfence_vvma_asid(
                mask,
                base,
                0,
                usize::MAX,
                0,
            )),
            0,
            "rfnc_hfence_vvma_asid",
        );
    }

    if let Err(err) = sv39.finish() {
        ctx.record_fail("rfnc_sv39_teardown", err);
    }

    let inv_fid = sbi::probe_invalid_fid(SbiExtensionId::Rfnc);
    ctx.expect_sbi_err(
        sbi::error_code(inv_fid),
        SbiError::NotSupported.as_code(),
        "rfnc_invalid_fid",
    );

    ctx.finish()
}

fn conf_rfnc_smp(env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();
    if env.online_harts() < 2 {
        return ctx.finish_or_skip(SkipReason::SingleHartOnly);
    }
    let Some((mask, base)) = env.workers_hart_mask() else {
        return ctx.finish_or_skip(SkipReason::SingleHartOnly);
    };

    let fence_i = sbi::rfnc::remote_fence_i(mask, base);
    ctx.expect_sbi_err(sbi::error_code(fence_i), 0, "rfnc_smp_fence_i");

    match env.probe_remote_sfence_visibility(false) {
        Ok((ret, visible)) => {
            ctx.expect_sbi_err(sbi::error_code(ret), 0, "rfnc_smp_sfence_vma_ret");
            ctx.expect(visible, "rfnc_smp_sfence_vma_tlb_visibility");
        }
        Err(err) => ctx.record_fail("rfnc_smp_sfence_vma_visibility", err),
    }

    match env.probe_remote_sfence_visibility(true) {
        Ok((ret, visible)) => {
            ctx.expect_sbi_err(sbi::error_code(ret), 0, "rfnc_smp_sfence_vma_asid_ret");
            ctx.expect(visible, "rfnc_smp_sfence_vma_asid_tlb_visibility");
        }
        Err(err) => ctx.record_fail("rfnc_smp_sfence_vma_asid_visibility", err),
    }

    ctx.finish()
}
