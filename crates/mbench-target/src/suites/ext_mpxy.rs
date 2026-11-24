//! SBI Message Proxy (`MPXY`, SBI v3.0) benchmarks (`mpxy/*`).

use mbench_core::{
    engine::{BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, FinishedBench},
    record::{BenchGroup, FailReason, SbiExtensionId, SkipReason},
};

use super::run_shmem_reregister;
use crate::{
    mbench_loop,
    platform::{
        Platform,
        shmem::{ShmemAcquire, ShmemOwner},
    },
    sbi::{self, SbiError},
};

/// Declarative SBI MPXY benchmark suite (4 specs).
pub(crate) static SPECS: &[BenchSpec<Platform>] = &[
    mpxy_spec("mpxy/get_shmem_size", run_mpxy_shmem_size),
    mpxy_spec("mpxy/set_shmem", run_mpxy_set_shmem),
    mpxy_spec("mpxy/get_channel_ids", run_mpxy_channel_ids),
    mpxy_spec("mpxy/read_attrs", run_mpxy_read_attrs),
];

const fn mpxy_spec(
    id: &'static str,
    run: fn(&mut Platform, BenchRun<'_, '_, '_, '_>) -> FinishedBench,
) -> BenchSpec<Platform> {
    BenchSpec {
        meta: BenchMeta {
            id,
            group: BenchGroup::Mpxy,
            unit: "call",
            required_ext: Some(SbiExtensionId::Mpxy),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run,
    }
}

fn run_mpxy_shmem_size(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::mpxy::get_shmem_size();
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::mpxy::get_shmem_size();
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_mpxy_set_shmem(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    run_shmem_reregister(env, run, ShmemOwner::Mpxy)
}

fn run_mpxy_channel_ids(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut lease = match env.lease_shmem(ShmemOwner::Mpxy) {
        Ok(ShmemAcquire::Leased(l)) => l,
        Ok(ShmemAcquire::Unsupported) => return run.skip(SkipReason::FunctionUnsupported),
        Ok(ShmemAcquire::TooLarge) => return run.skip(SkipReason::ShmemTooLarge),
        Err(err) => return run.fail(err),
    };
    let probe = lease.mpxy_get_channel_ids(0);
    if probe.error != 0 {
        let _ = lease.finish();
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(probe)));
    }

    let pending = run.measure_batched(&mut lease, |l, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = l.mpxy_get_channel_ids(0);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    });
    pending.finish_with(lease.finish())
}

fn run_mpxy_read_attrs(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut lease = match env.lease_shmem(ShmemOwner::Mpxy) {
        Ok(ShmemAcquire::Leased(l)) => l,
        Ok(ShmemAcquire::Unsupported) => return run.skip(SkipReason::FunctionUnsupported),
        Ok(ShmemAcquire::TooLarge) => return run.skip(SkipReason::ShmemTooLarge),
        Err(err) => return run.fail(err),
    };
    let ids = lease.mpxy_get_channel_ids(0);
    if ids.error != 0 {
        let fin = lease.finish();
        return if sbi::error_code(ids) == SbiError::Failed.as_code() {
            if let Err(err) = fin {
                run.fail(err)
            } else {
                run.skip(SkipReason::NoUsableResource)
            }
        } else {
            run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ids)))
        };
    }
    let hdr = lease.read_mpxy_channel_ids_header();
    let needed_bytes = (hdr.returned as usize)
        .checked_mul(size_of::<u32>())
        .and_then(|n| n.checked_add(size_of::<sbi::mpxy::MpxyChannelIdsHeader>()));
    if needed_bytes.is_none_or(|b| b > lease.registered_len()) {
        let _ = lease.finish();
        return run.fail(FailReason::VerificationMismatch);
    }
    let Some(first_id) = (if hdr.returned == 0 {
        None
    } else {
        lease.read_mpxy_channel_id(0)
    }) else {
        if let Err(err) = lease.finish() {
            return run.fail(err);
        }
        return run.skip(SkipReason::NoUsableResource);
    };
    let channel_id = first_id as usize;
    let probe = lease.mpxy_read_attrs(channel_id, 0, 1);
    if probe.error != 0 {
        let _ = lease.finish();
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(probe)));
    }

    let pending = run.measure_batched(&mut lease, |l, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = l.mpxy_read_attrs(channel_id, 0, 1);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    });
    pending.finish_with(lease.finish())
}
