//! Split shared-memory boundary & M-mode isolation security checks (`STA`, `NACL`, `DBTR`, `MPXY`).

use mbench_core::{
    check::{CheckCase, CheckCtx, CheckOutcome},
    record::{CaseFlags, SbiExtensionId, SkipReason},
};

use super::check_case;
use crate::platform::{Platform, shmem::ShmemOwner};

pub(super) static CASES: &[CheckCase<Platform>] = &[
    check_case(
        "conformance/shmem_security.sta",
        Some(SbiExtensionId::Sta),
        1,
        CaseFlags::empty(),
        conf_shmem_sta,
    ),
    check_case(
        "conformance/shmem_security.nacl",
        Some(SbiExtensionId::Nacl),
        1,
        CaseFlags::empty(),
        conf_shmem_nacl,
    ),
    check_case(
        "conformance/shmem_security.dbtr",
        Some(SbiExtensionId::Dbtr),
        1,
        CaseFlags::empty(),
        conf_shmem_dbtr,
    ),
    check_case(
        "conformance/shmem_security.mpxy",
        Some(SbiExtensionId::Mpxy),
        1,
        CaseFlags::empty(),
        conf_shmem_mpxy,
    ),
];

fn run_shmem_target(env: &mut Platform, owner: ShmemOwner) -> CheckOutcome {
    let mut ctx = CheckCtx::new();
    match env.probe_shmem_security(owner, &mut ctx) {
        Ok(true) => ctx.finish_or_skip(SkipReason::ShmemTooLarge),
        Ok(false) => ctx.finish(),
        Err(err) => {
            ctx.record_fail("shmem_security_probe", err);
            ctx.finish()
        }
    }
}

fn conf_shmem_sta(env: &mut Platform) -> CheckOutcome {
    run_shmem_target(env, ShmemOwner::Sta)
}

fn conf_shmem_nacl(env: &mut Platform) -> CheckOutcome {
    run_shmem_target(env, ShmemOwner::Nacl)
}

fn conf_shmem_dbtr(env: &mut Platform) -> CheckOutcome {
    run_shmem_target(env, ShmemOwner::Dbtr)
}

fn conf_shmem_mpxy(env: &mut Platform) -> CheckOutcome {
    run_shmem_target(env, ShmemOwner::Mpxy)
}
