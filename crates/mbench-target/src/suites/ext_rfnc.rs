//! SBI RFNC extension benchmarks with all-hart Sv39 identity 4 KiB PTEs active (`rfnc/*`).

use mbench_core::{
    engine::{
        BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, FinishedBench, HartCoordinator,
    },
    record::{BenchGroup, FailReason, SbiExtensionId, SkipReason},
};

use crate::{
    mbench_loop,
    platform::Platform,
    sbi::{self, SbiError, SbiRet},
};

/// Declarative SBI RFNC benchmark suite (13 specs).
pub(crate) static SPECS: &[BenchSpec<Platform>] = &[
    BenchSpec {
        meta: BenchMeta {
            id: "rfnc/sfence_vma.empty",
            group: BenchGroup::Rfnc,
            unit: "call",
            required_ext: Some(SbiExtensionId::Rfnc),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_rfence_empty,
    },
    rfnc_spec("rfnc/fence_i.self", 1, run_fence_i_self),
    rfnc_spec("rfnc/fence_i.all", 2, run_fence_i_all),
    rfnc_spec("rfnc/sfence_vma.page.self", 1, run_sfence_page_self),
    rfnc_spec("rfnc/sfence_vma.page.all", 2, run_sfence_page_all),
    rfnc_spec("rfnc/sfence_vma.range.all", 2, run_sfence_range_all),
    rfnc_spec("rfnc/sfence_vma.all", 2, run_sfence_all),
    rfnc_spec("rfnc/sfence_vma_asid.page.all", 2, run_sfence_asid_page_all),
    rfnc_spec("rfnc/sfence_vma_asid.all", 2, run_sfence_asid_all),
    rfnc_spec("rfnc/hfence_gvma", 2, run_hfence_gvma),
    rfnc_spec("rfnc/hfence_gvma_vmid", 2, run_hfence_gvma_vmid),
    rfnc_spec("rfnc/hfence_vvma", 2, run_hfence_vvma),
    rfnc_spec("rfnc/hfence_vvma_asid", 2, run_hfence_vvma_asid),
];

const fn rfnc_spec(
    id: &'static str,
    min_harts: usize,
    run: fn(&mut Platform, BenchRun<'_, '_, '_, '_>) -> FinishedBench,
) -> BenchSpec<Platform> {
    BenchSpec {
        meta: BenchMeta {
            id,
            group: BenchGroup::Rfnc,
            unit: "call",
            required_ext: Some(SbiExtensionId::Rfnc),
            min_harts,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run,
    }
}

#[derive(Clone, Copy)]
enum RfenceKind {
    FenceI,
    SfencePage,
    SfenceRange16,
    SfenceAll,
    SfenceAsidPage,
    SfenceAsidAll,
    HfenceGvma,
    HfenceGvmaVmid,
    HfenceVvma,
    HfenceVvmaAsid,
}

#[derive(Clone, Copy)]
enum TargetScope {
    SelfHart,
    AllRemote,
}

fn run_rfence_empty(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::rfnc::remote_sfence_vma(0, 0, 0, 0);
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::rfnc::remote_sfence_vma(0, 0, 0, 0);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_rfence_case(
    env: &mut Platform,
    run: BenchRun<'_, '_, '_, '_>,
    kind: RfenceKind,
    scope: TargetScope,
    needs_sv39: bool,
    needs_h: bool,
) -> FinishedBench {
    if needs_h && !env.info().has_h_ext {
        return run.skip(SkipReason::ExtensionUnsupported);
    }
    let Some((mask, base)) = (match scope {
        TargetScope::SelfHart => Some(env.self_hart_mask()),
        TargetScope::AllRemote => env.all_remote_hart_mask(),
    }) else {
        return if env.online_harts() < 2 {
            run.skip(SkipReason::SingleHartOnly)
        } else {
            run.skip(SkipReason::NoUsableResource)
        };
    };

    if needs_sv39 {
        let mut sv39 = match env.enable_sv39() {
            Ok(g) => g,
            Err(err) => return run.fail(err),
        };
        let target_page = sv39.target_page_addr();
        let asid = sv39.sv39_asid();
        let ret = dispatch_rfence(kind, mask, base, target_page, asid);
        if needs_h && sbi::error_code(ret) == SbiError::NotSupported.as_code() {
            if let Err(err) = sv39.finish() {
                return run.fail(err);
            }
            return run.skip(SkipReason::FunctionUnsupported);
        }
        if ret.error != 0 {
            let _ = sv39.finish();
            return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }
        let pending = run.measure_batched(&mut sv39, |_g, iters| {
            let mut errors = 0usize;
            mbench_loop!(iters, {
                let ret = dispatch_rfence(kind, mask, base, target_page, asid);
                errors |= ret.error;
            });
            BatchOutcome::from_errors(errors, iters)
        });
        return pending.finish_with(sv39.finish());
    }

    let target_page = env.target_page_addr();
    let asid = env.sv39_asid();
    let ret = dispatch_rfence(kind, mask, base, target_page, asid);
    if needs_h && sbi::error_code(ret) == SbiError::NotSupported.as_code() {
        return run.skip(SkipReason::FunctionUnsupported);
    }
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = dispatch_rfence(kind, mask, base, target_page, asid);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

#[inline(always)]
fn dispatch_rfence(
    kind: RfenceKind,
    mask: usize,
    base: usize,
    target_page: usize,
    asid: usize,
) -> SbiRet {
    match kind {
        RfenceKind::FenceI => sbi::rfnc::remote_fence_i(mask, base),
        RfenceKind::SfencePage => sbi::rfnc::remote_sfence_vma(mask, base, target_page, 4096),
        RfenceKind::SfenceRange16 => {
            sbi::rfnc::remote_sfence_vma(mask, base, target_page, 16 * 4096)
        }
        RfenceKind::SfenceAll => sbi::rfnc::remote_sfence_vma(mask, base, 0, usize::MAX),
        RfenceKind::SfenceAsidPage => {
            sbi::rfnc::remote_sfence_vma_asid(mask, base, target_page, 4096, asid)
        }
        RfenceKind::SfenceAsidAll => {
            sbi::rfnc::remote_sfence_vma_asid(mask, base, 0, usize::MAX, asid)
        }
        RfenceKind::HfenceGvma => sbi::rfnc::remote_hfence_gvma(mask, base, 0, usize::MAX),
        RfenceKind::HfenceGvmaVmid => {
            sbi::rfnc::remote_hfence_gvma_vmid(mask, base, 0, usize::MAX, 0)
        }
        RfenceKind::HfenceVvma => sbi::rfnc::remote_hfence_vvma(mask, base, 0, usize::MAX),
        RfenceKind::HfenceVvmaAsid => {
            sbi::rfnc::remote_hfence_vvma_asid(mask, base, 0, usize::MAX, 0)
        }
    }
}

fn run_fence_i_self(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_rfence_case(
        env,
        run,
        RfenceKind::FenceI,
        TargetScope::SelfHart,
        false,
        false,
    )
}

fn run_fence_i_all(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_rfence_case(
        env,
        run,
        RfenceKind::FenceI,
        TargetScope::AllRemote,
        false,
        false,
    )
}

fn run_sfence_page_self(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_rfence_case(
        env,
        run,
        RfenceKind::SfencePage,
        TargetScope::SelfHart,
        true,
        false,
    )
}

fn run_sfence_page_all(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_rfence_case(
        env,
        run,
        RfenceKind::SfencePage,
        TargetScope::AllRemote,
        true,
        false,
    )
}

fn run_sfence_range_all(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_rfence_case(
        env,
        run,
        RfenceKind::SfenceRange16,
        TargetScope::AllRemote,
        true,
        false,
    )
}

fn run_sfence_all(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_rfence_case(
        env,
        run,
        RfenceKind::SfenceAll,
        TargetScope::AllRemote,
        true,
        false,
    )
}

fn run_sfence_asid_page_all(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_rfence_case(
        env,
        run,
        RfenceKind::SfenceAsidPage,
        TargetScope::AllRemote,
        true,
        false,
    )
}

fn run_sfence_asid_all(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_rfence_case(
        env,
        run,
        RfenceKind::SfenceAsidAll,
        TargetScope::AllRemote,
        true,
        false,
    )
}

fn run_hfence_gvma(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_rfence_case(
        env,
        run,
        RfenceKind::HfenceGvma,
        TargetScope::AllRemote,
        false,
        true,
    )
}

fn run_hfence_gvma_vmid(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_rfence_case(
        env,
        run,
        RfenceKind::HfenceGvmaVmid,
        TargetScope::AllRemote,
        false,
        true,
    )
}

fn run_hfence_vvma(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_rfence_case(
        env,
        run,
        RfenceKind::HfenceVvma,
        TargetScope::AllRemote,
        false,
        true,
    )
}

fn run_hfence_vvma_asid(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_rfence_case(
        env,
        run,
        RfenceKind::HfenceVvmaAsid,
        TargetScope::AllRemote,
        false,
        true,
    )
}
