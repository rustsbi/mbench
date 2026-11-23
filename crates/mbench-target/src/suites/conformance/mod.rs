//! Modular SBI v3.0 functional conformance checks (`suites/conformance/`).

mod base;
mod dbcn;
mod time;
mod traps;

use mbench_core::{
    check::{CheckCase, CheckGroup, CheckMeta, CheckOutcome},
    record::{CaseFlags, SbiExtensionId},
};

use crate::platform::Platform;

pub(super) const fn check_case(
    id: &'static str,
    required_ext: Option<SbiExtensionId>,
    min_harts: usize,
    flags: CaseFlags,
    run: fn(&mut Platform) -> CheckOutcome,
) -> CheckCase<Platform> {
    CheckCase {
        meta: CheckMeta::new(id, required_ext, min_harts, flags),
        run,
    }
}

/// Conformance groups executed while secondary harts are stopped (single-hart BSP state).
pub(crate) static SINGLE_HART_GROUPS: &[CheckGroup<'static, Platform>] = &[
    CheckGroup {
        name: "base",
        cases: base::CASES,
    },
    CheckGroup {
        name: "time",
        cases: time::CASES,
    },
    CheckGroup {
        name: "dbcn",
        cases: dbcn::CASES,
    },
    CheckGroup {
        name: "traps",
        cases: traps::CASES,
    },
];

/// Conformance groups executed once the Phase 3 SMP worker pool is online.
pub(crate) static MULTI_HART_GROUPS: &[CheckGroup<'static, Platform>] = &[];

/// HSM conformance checks executed while secondary harts are `STOPPED` (Phase 4).
pub(crate) static HSM_GROUPS: &[CheckGroup<'static, Platform>] = &[];
