//! Non-short-circuiting shared-memory boundary and security probes.

use mbench_core::{check::CheckCtx, record::FailReason};

use super::{PAGE_SIZE, ShmemOwner};
use crate::{
    platform::Platform,
    sbi::{self, SbiError},
};

/// Runs non-short-circuiting shared-memory boundary & security checks for `target`.
///
/// Returns `Ok(true)` if skipped because firmware requires more shared memory than `SHMEM_POOL` provides.
pub(in crate::platform) fn probe_security(
    platform: &mut Platform,
    target: ShmemOwner,
    mmode_addr: Option<usize>,
    ctx: &mut CheckCtx,
) -> Result<bool, FailReason> {
    platform.shmem.ensure_idle()?;
    if target == ShmemOwner::Mpxy {
        let size_ret = sbi::mpxy::get_shmem_size();
        if !ctx.expect_sbi_err(sbi::error_code(size_ret), 0, "mpxy_get_shmem_size") {
            return Ok(false);
        }
        let needed = size_ret.value;
        if !ctx.expect(
            needed >= PAGE_SIZE && needed.is_multiple_of(PAGE_SIZE),
            "mpxy_valid_shmem_size",
        ) {
            return Ok(false);
        }
        if needed > platform.shmem.len() {
            return Ok(true);
        }
    }

    let valid_addr = platform.shmem.base();

    if target == ShmemOwner::Mpxy {
        platform.shmem.zero_all();
        let owret = target.set_raw(valid_addr, 0, sbi::mpxy::FLAG_OVERWRITE_RETURN);
        if owret.error == 0 {
            platform.shmem.set_registered(target);
            platform.shmem.unregister_and_release(target)?;
        }
        ctx.expect_sbi_err(sbi::error_code(owret), 0, "mpxy_overwrite_return_accepted");
    }

    let bad_flags = target.set_raw(valid_addr, 0, target.invalid_flags());
    if bad_flags.error == 0 {
        platform.shmem.set_registered(target);
        platform.shmem.unregister_and_release(target)?;
    }
    if target == ShmemOwner::Dbtr {
        ctx.expect_sbi_err_quirk(
            sbi::error_code(bad_flags),
            SbiError::InvalidParam.as_code(),
            0,
            "opensbi-v1.8.1:dbtr-ignores-shmem-flags",
            target.flags_label(),
        );
    } else {
        ctx.expect_sbi_err(
            sbi::error_code(bad_flags),
            SbiError::InvalidParam.as_code(),
            target.flags_label(),
        );
    }

    let unaligned = target.set_raw(valid_addr + 1, 0, 0);
    if unaligned.error == 0 {
        platform.shmem.set_registered(target);
        platform.shmem.unregister_and_release(target)?;
    }
    ctx.expect_sbi_err(
        sbi::error_code(unaligned),
        SbiError::InvalidParam.as_code(),
        target.unaligned_label(),
    );

    let bad_hi = target.set_raw(valid_addr, usize::MAX, 0);
    if bad_hi.error == 0 {
        platform.shmem.set_registered(target);
        platform.shmem.unregister_and_release(target)?;
    }
    ctx.expect_sbi_err_in(
        sbi::error_code(bad_hi),
        &[
            SbiError::InvalidAddress.as_code(),
            SbiError::InvalidParam.as_code(),
            SbiError::Failed.as_code(),
        ],
        target.phys_hi_label(),
    );

    if let Some(maddr) = mmode_addr {
        let mmode_ret = target.set_raw(maddr, 0, 0);
        if mmode_ret.error == 0 {
            platform.shmem.set_registered(target);
            platform.shmem.unregister_and_release(target)?;
            ctx.record_fail(
                target.mmode_label(),
                FailReason::SecurityViolation(target.mmode_label()),
            );
        } else {
            ctx.expect_sbi_err_in(
                sbi::error_code(mmode_ret),
                &[
                    SbiError::InvalidAddress.as_code(),
                    SbiError::Denied.as_code(),
                    SbiError::InvalidParam.as_code(),
                    SbiError::Failed.as_code(),
                ],
                target.mmode_label(),
            );
        }
    }

    platform.shmem.unregister_and_release(target)?;
    Ok(false)
}
