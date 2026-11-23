//! SBI Debug Console (`DBCN`) functional conformance checks (non-printing in default mode).

use mbench_core::{
    check::{CheckCase, CheckCtx, CheckOutcome},
    record::{CaseFlags, IssueClass, SbiExtensionId},
};

use super::check_case;
use crate::{
    platform::Platform,
    sbi::{self, SbiError},
};

pub(super) static CASES: &[CheckCase<Platform>] = &[check_case(
    "conformance/dbcn",
    Some(SbiExtensionId::Dbcn),
    1,
    CaseFlags::empty(),
    conf_dbcn,
)];

fn conf_dbcn(_env: &mut Platform) -> CheckOutcome {
    let mut ctx = CheckCtx::new();

    let zero_wr = sbi::dbcn::write_slice(&[]);
    ctx.expect(zero_wr.error == 0 && zero_wr.value == 0, "dbcn_zero_write");

    let mut empty_buf = [0u8; 0];
    let zero_rd = sbi::dbcn::read_slice(&mut empty_buf);
    ctx.expect(zero_rd.error == 0 && zero_rd.value == 0, "dbcn_zero_read");

    let mut rx = [0u8; 8];
    let rd = sbi::dbcn::read_slice(&mut rx);
    ctx.expect(rd.error == 0 && rd.value <= rx.len(), "dbcn_read_bounded");

    // Per SBI v3.0 binary-encoding.adoc shared-memory physical address validation, `INVALID_PARAM`,
    // `INVALID_ADDRESS`, and `FAILED` (address limit restrictions such as `base_addr_hi != 0` in
    // OpenSBI v1.8.1) are permitted rejections.
    let bad_hi = sbi::dbcn::probe_invalid_phys_hi();
    let bad_hi_code = sbi::error_code(bad_hi);
    ctx.expect_sbi_err_in(
        bad_hi_code,
        &[
            SbiError::InvalidParam.as_code(),
            SbiError::InvalidAddress.as_code(),
            SbiError::Failed.as_code(),
        ],
        "dbcn_rejects_bad_phys_hi",
    );
    if bad_hi_code == SbiError::Failed.as_code() {
        ctx.observe(
            "dbcn_bad_phys_hi_failed_permitted",
            IssueClass::PermittedBehavior,
        );
    }

    let inv_fid = sbi::probe_invalid_fid(SbiExtensionId::Dbcn);
    ctx.expect_sbi_err(
        sbi::error_code(inv_fid),
        SbiError::NotSupported.as_code(),
        "dbcn_invalid_fid",
    );

    ctx.finish()
}
