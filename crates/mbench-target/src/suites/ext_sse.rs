//! SBI Supervisor Software Events (`SSE`, SBI v3.0) benchmarks (`sse/*`).

use mbench_core::{
    engine::{BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, FinishedBench},
    record::{BenchGroup, FailReason, SbiExtensionId, SkipReason},
};

use crate::{
    mbench_loop,
    platform::Platform,
    sbi::{self, SbiError},
};

/// Declarative SBI SSE benchmark suite (3 specs).
pub(crate) static SPECS: &[BenchSpec<Platform>] = &[
    sse_spec("sse/read_attrs", "call", run_sse_read_attrs),
    sse_spec("sse/write_attrs", "call", run_sse_write_attrs),
    sse_spec("sse/inject.roundtrip", "event", run_sse_inject_roundtrip),
];

const fn sse_spec(
    id: &'static str,
    unit: &'static str,
    run: fn(&mut Platform, BenchRun<'_, '_, '_, '_>) -> FinishedBench,
) -> BenchSpec<Platform> {
    BenchSpec {
        meta: BenchMeta {
            id,
            group: BenchGroup::Sse,
            unit,
            required_ext: Some(SbiExtensionId::Sse),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run,
    }
}

fn run_sse_read_attrs(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut session = match env.register_local_sse() {
        Ok(s) => s,
        Err(SbiError::NotSupported) => return run.skip(SkipReason::FunctionUnsupported),
        Err(err) => return run.fail(FailReason::UnexpectedSbiError(err.as_code())),
    };
    if let Err(err) = session.read_attr(sbi::sse::ATTR_STATUS) {
        let _ = session.finish();
        return run.fail(FailReason::UnexpectedSbiError(err.as_code()));
    }

    let pending = run.measure_batched(&mut session, |s, iters| {
        let mut first_err = 0isize;
        mbench_loop!(iters, {
            if let Err(err) = s.read_attr(sbi::sse::ATTR_STATUS)
                && first_err == 0
            {
                first_err = err.as_code();
            }
        });
        BatchOutcome::from_errors(first_err as usize, iters)
    });
    pending.finish_with(session.finish())
}

fn run_sse_write_attrs(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut session = match env.register_local_sse() {
        Ok(s) => s,
        Err(SbiError::NotSupported) => return run.skip(SkipReason::FunctionUnsupported),
        Err(err) => return run.fail(FailReason::UnexpectedSbiError(err.as_code())),
    };
    let orig_prio = match session.read_attr(sbi::sse::ATTR_PRIO) {
        Ok(v) => v,
        Err(err) => {
            let _ = session.finish();
            return run.fail(FailReason::UnexpectedSbiError(err.as_code()));
        }
    };
    if let Err(err) = session.write_attr(sbi::sse::ATTR_PRIO, orig_prio) {
        let _ = session.finish();
        return run.fail(FailReason::UnexpectedSbiError(err.as_code()));
    }

    let pending = run.measure_batched(&mut session, |s, iters| {
        let mut first_err = 0isize;
        mbench_loop!(iters, {
            if let Err(err) = s.write_attr(sbi::sse::ATTR_PRIO, orig_prio)
                && first_err == 0
            {
                first_err = err.as_code();
            }
        });
        BatchOutcome::from_errors(first_err as usize, iters)
    });
    pending.finish_with(session.finish())
}

fn run_sse_inject_roundtrip(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut session = match env.register_local_sse() {
        Ok(s) => s,
        Err(SbiError::NotSupported) => return run.skip(SkipReason::FunctionUnsupported),
        Err(err) => return run.fail(FailReason::UnexpectedSbiError(err.as_code())),
    };
    match session.is_injectable() {
        Ok(true) => {}
        Ok(false) => {
            if let Err(err) = session.finish() {
                return run.fail(err);
            }
            return run.skip(SkipReason::NoUsableResource);
        }
        Err(err) => {
            let _ = session.finish();
            return run.fail(FailReason::UnexpectedSbiError(err.as_code()));
        }
    }
    if let Err(err) = session.enable_and_unmask() {
        let _ = session.finish();
        return run.fail(FailReason::UnexpectedSbiError(err.as_code()));
    }
    let timeout = session.timebase_hz().max(1);
    let pending = run.measure_paired(&mut session, |s| s.inject_and_measure(timeout));
    pending.finish_with(session.finish())
}
