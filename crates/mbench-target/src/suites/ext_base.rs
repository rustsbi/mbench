//! SBI Base extension and cold-I-cache privilege crossing microbenchmarks (`base/*`).

use mbench_core::{
    engine::{BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, FinishedBench},
    record::{BenchGroup, FailReason, SbiExtensionId},
};

use crate::{
    mbench_loop,
    platform::{Platform, icache},
    sbi::{self, SbiError, SbiRet, SbiVersion},
};

/// Declarative SBI Base benchmark suite (10 specs).
pub(crate) static SPECS: &[BenchSpec<Platform>] = &[
    base_spec("base/get_spec_version", run_get_spec_version),
    base_spec("base/probe.hit", run_probe_hit),
    base_spec("base/probe.miss", run_probe_miss),
    base_spec("base/invalid_eid", run_invalid_eid),
    base_spec("base/get_spec_version.cold", run_get_spec_version_cold),
    base_spec("base/get_impl_id", run_get_impl_id),
    base_spec("base/get_impl_version", run_get_impl_version),
    base_spec("base/get_mvendorid", run_get_mvendorid),
    base_spec("base/get_marchid", run_get_marchid),
    base_spec("base/get_mimpid", run_get_mimpid),
];

const fn base_spec(
    id: &'static str,
    run: fn(&mut Platform, BenchRun<'_, '_, '_, '_>) -> FinishedBench,
) -> BenchSpec<Platform> {
    BenchSpec {
        meta: BenchMeta {
            id,
            group: BenchGroup::Base,
            unit: "call",
            required_ext: Some(SbiExtensionId::Base),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run,
    }
}

fn run_get_spec_version(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::base::get_spec_version();
    let ver = SbiVersion::from_raw(ret.value);
    if ret.error != 0 || (ver.major(), ver.minor()) < (0, 2) {
        return run.fail(FailReason::VerificationMismatch);
    }
    let (abi_ret, abi_ok) = sbi::base::check_abi_preservation();
    if abi_ret.error != 0 || !abi_ok {
        return run.fail(FailReason::AbiRegClobbered);
    }

    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::base::get_spec_version();
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_probe_hit(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::base::probe_extension(SbiExtensionId::Base.eid());
    if ret.error != 0 || ret.value == 0 {
        return run.fail(FailReason::VerificationMismatch);
    }

    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::base::probe_extension(SbiExtensionId::Base.eid());
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_probe_miss(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::base::probe_extension(0xDEAD_BEEF);
    if ret.error != 0 || ret.value != 0 {
        return run.fail(FailReason::VerificationMismatch);
    }

    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::base::probe_extension(0xDEAD_BEEF);
            errors |= ret.error | ret.value;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_invalid_eid(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::probe_invalid_eid();
    let expected_code = SbiError::NotSupported.as_code();
    if sbi::error_code(ret) != expected_code {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    let expected = expected_code as usize;

    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::probe_invalid_eid();
            errors |= ret.error ^ expected;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_get_spec_version_cold(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::base::get_spec_version();
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }

    run.measure_batched_with_preamble(
        env,
        |_env, iters| {
            mbench_loop!(iters, {
                icache::thrash();
            });
        },
        |_env, iters| {
            let mut errors = 0usize;
            mbench_loop!(iters, {
                icache::thrash();
                let ret = sbi::base::get_spec_version();
                errors |= ret.error;
            });
            BatchOutcome::from_errors(errors, iters)
        },
    )
    .commit()
}

fn run_getter_case(
    env: &mut Platform,
    run: BenchRun<'_, '_, '_, '_>,
    call: fn() -> SbiRet,
) -> FinishedBench {
    let ret = call();
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = call();
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_get_impl_id(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_getter_case(env, run, sbi::base::get_impl_id)
}

fn run_get_impl_version(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_getter_case(env, run, sbi::base::get_impl_version)
}

fn run_get_mvendorid(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_getter_case(env, run, sbi::base::get_mvendorid)
}

fn run_get_marchid(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_getter_case(env, run, sbi::base::get_marchid)
}

fn run_get_mimpid(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_getter_case(env, run, sbi::base::get_mimpid)
}
