//! Single-hart (`FWFT`, `STA`, `NACL`, `CPPC`) and Phase 5 I/O/destructive (`DBCN`, `SUSP`) suites.

use mbench_core::{
    engine::{
        BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, Clock, CounterSnap, FinishedBench,
    },
    record::{BenchGroup, FailReason, SbiExtensionId, SkipReason},
};

use crate::{
    mbench_loop,
    platform::{
        Platform,
        shmem::{ShmemAcquire, ShmemOwner},
    },
    sbi::{self, SbiError, fwft::FwftFeatureId},
};

/// Declarative Phase 2b single-hart system & virtualization extension suite (7 specs).
pub(crate) static SINGLE_HART_SPECS: &[BenchSpec<Platform>] = &[
    BenchSpec {
        meta: BenchMeta {
            id: "fwft/get",
            group: BenchGroup::Fwft,
            unit: "call",
            required_ext: Some(SbiExtensionId::Fwft),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_fwft_get,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "fwft/set",
            group: BenchGroup::Fwft,
            unit: "call",
            required_ext: Some(SbiExtensionId::Fwft),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_fwft_set,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "sta/set_shmem",
            group: BenchGroup::Sta,
            unit: "call",
            required_ext: Some(SbiExtensionId::Sta),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_sta_set_shmem,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "nacl/probe_feature",
            group: BenchGroup::Nacl,
            unit: "call",
            required_ext: Some(SbiExtensionId::Nacl),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_nacl_probe,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "nacl/set_shmem",
            group: BenchGroup::Nacl,
            unit: "call",
            required_ext: Some(SbiExtensionId::Nacl),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_nacl_set_shmem,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "cppc/probe",
            group: BenchGroup::Cppc,
            unit: "call",
            required_ext: Some(SbiExtensionId::Cppc),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_cppc_probe,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "cppc/read",
            group: BenchGroup::Cppc,
            unit: "call",
            required_ext: Some(SbiExtensionId::Cppc),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_cppc_read,
    },
];

/// Declarative Phase 5 opt-in console I/O (`io=1`) and system suspend (`destructive=1`) suite (4 specs).
pub(crate) static IO_DESTRUCTIVE_SPECS: &[BenchSpec<Platform>] = &[
    BenchSpec {
        meta: BenchMeta {
            id: "dbcn/write.16b",
            group: BenchGroup::Dbcn,
            unit: "call",
            required_ext: Some(SbiExtensionId::Dbcn),
            min_harts: 1,
            flags: BenchFlags::IO_BOUND,
            max_batch_iters: Some(16),
        },
        run: run_dbcn_write_16b,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "dbcn/write_byte",
            group: BenchGroup::Dbcn,
            unit: "byte",
            required_ext: Some(SbiExtensionId::Dbcn),
            min_harts: 1,
            flags: BenchFlags::IO_BOUND,
            max_batch_iters: Some(16),
        },
        run: run_dbcn_write_byte,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "dbcn/read.nonblock",
            group: BenchGroup::Dbcn,
            unit: "call",
            required_ext: Some(SbiExtensionId::Dbcn),
            min_harts: 1,
            flags: BenchFlags::IO_BOUND,
            max_batch_iters: None,
        },
        run: run_dbcn_read_nonblock,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "susp/system_suspend",
            group: BenchGroup::Susp,
            unit: "suspend",
            required_ext: Some(SbiExtensionId::Susp),
            min_harts: 1,
            flags: BenchFlags::DESTRUCTIVE,
            max_batch_iters: Some(1),
        },
        run: run_system_suspend,
    },
];

fn find_readable_fwft_feature() -> Result<Option<(usize, usize)>, FailReason> {
    for feat in FwftFeatureId::ALL {
        let id = feat.as_usize();
        let ret = sbi::fwft::get(id);
        if ret.error == 0 {
            return Ok(Some((id, ret.value)));
        }
        let code = sbi::error_code(ret);
        if code != SbiError::NotSupported.as_code() {
            return Err(FailReason::UnexpectedSbiError(code));
        }
    }
    Ok(None)
}

fn run_fwft_get(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let feat = match find_readable_fwft_feature() {
        Ok(Some((f, _))) => f,
        Ok(None) => return run.skip(SkipReason::NoUsableResource),
        Err(err) => return run.fail(err),
    };
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::fwft::get(feat);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_fwft_set(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut saw_locked = false;
    for feat_id in FwftFeatureId::ALL {
        let feat = feat_id.as_usize();
        let g = sbi::fwft::get(feat);
        if g.error != 0 {
            let code = sbi::error_code(g);
            if code == SbiError::NotSupported.as_code() {
                continue;
            }
            return run.fail(FailReason::UnexpectedSbiError(code));
        }
        let s = sbi::fwft::set(feat, g.value, 0);
        if s.error == 0 {
            let val = g.value;
            let pending = run.measure_batched(env, |_env, iters| {
                let mut errors = 0usize;
                mbench_loop!(iters, {
                    let ret = sbi::fwft::set(feat, val, 0);
                    errors |= ret.error;
                });
                BatchOutcome::from_errors(errors, iters)
            });
            let restore = sbi::fwft::set(feat, val, 0);
            return pending.finish_with(if restore.error != 0 {
                Err(FailReason::UnexpectedSbiError(sbi::error_code(restore)))
            } else {
                Ok(())
            });
        }
        let set_code = sbi::error_code(s);
        if set_code == SbiError::DeniedLocked.as_code() || set_code == SbiError::Denied.as_code() {
            saw_locked = true;
        } else if set_code != SbiError::NotSupported.as_code() {
            return run.fail(FailReason::UnexpectedSbiError(set_code));
        }
    }
    if saw_locked {
        run.skip(SkipReason::FeatureLocked)
    } else {
        run.skip(SkipReason::NoUsableResource)
    }
}

fn run_sta_set_shmem(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut lease = match env.lease_shmem(ShmemOwner::Sta) {
        Ok(ShmemAcquire::Leased(l)) => l,
        Ok(ShmemAcquire::Unsupported) => return run.skip(SkipReason::FunctionUnsupported),
        Ok(ShmemAcquire::TooLarge) => return run.skip(SkipReason::ShmemTooLarge),
        Err(err) => return run.fail(err),
    };
    let pending = run.measure_batched(&mut lease, |l, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = l.reregister();
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    });
    pending.finish_with(lease.finish())
}

fn run_nacl_probe(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::nacl::probe_feature(sbi::nacl::FEAT_SYNC_CSR);
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::nacl::probe_feature(sbi::nacl::FEAT_SYNC_CSR);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_nacl_set_shmem(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut lease = match env.lease_shmem(ShmemOwner::Nacl) {
        Ok(ShmemAcquire::Leased(l)) => l,
        Ok(ShmemAcquire::Unsupported) => return run.skip(SkipReason::FunctionUnsupported),
        Ok(ShmemAcquire::TooLarge) => return run.skip(SkipReason::ShmemTooLarge),
        Err(err) => return run.fail(err),
    };
    let pending = run.measure_batched(&mut lease, |l, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = l.reregister();
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    });
    pending.finish_with(lease.finish())
}

fn run_cppc_probe(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::cppc::probe(sbi::cppc::REG_HIGHEST_PERF);
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::cppc::probe(sbi::cppc::REG_HIGHEST_PERF);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_cppc_read(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let probe = sbi::cppc::probe(sbi::cppc::REG_HIGHEST_PERF);
    if probe.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(probe)));
    }
    if probe.value == 0 {
        return run.skip(SkipReason::NoUsableResource);
    }
    let ret = sbi::cppc::read(sbi::cppc::REG_HIGHEST_PERF);
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::cppc::read(sbi::cppc::REG_HIGHEST_PERF);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_dbcn_write_16b(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    const PAYLOAD: &[u8; 16] = b"................";
    let ret = sbi::dbcn::write_slice(PAYLOAD);
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    if ret.value > PAYLOAD.len() {
        return run.fail(FailReason::VerificationMismatch);
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::dbcn::write_slice(PAYLOAD);
            errors |= ret.error;
            if ret.value > PAYLOAD.len() {
                errors |= 1;
            }
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_dbcn_write_byte(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::dbcn::write_byte(b'.');
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::dbcn::write_byte(b'.');
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_dbcn_read_nonblock(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut probe = [0u8; 64];
    let ret = sbi::dbcn::read_slice(&mut probe);
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut buf = [0u8; 64];
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::dbcn::read_slice(&mut buf);
            errors |= ret.error;
        });
        core::hint::black_box(buf[0]);
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_system_suspend(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    if !env.availability().has_any() {
        return run.skip(SkipReason::CounterUnavailable);
    }
    if let Err(skip) = env.arm_system_suspend_wake_source() {
        return run.skip(skip);
    }
    let probe = match env.system_suspend(sbi::susp::SLEEP_TYPE_SUSPEND_TO_RAM) {
        Ok(r) => r,
        Err(err) => return run.fail(err),
    };
    if probe == SbiError::NotSupported.as_code() {
        return run.skip(SkipReason::FunctionUnsupported);
    }
    if probe != 0 {
        return run.fail(FailReason::UnexpectedSbiError(probe));
    }

    run.measure_paired(env, |env| {
        let t0 = env.snap_begin();
        let ret = env.system_suspend(sbi::susp::SLEEP_TYPE_SUSPEND_TO_RAM)?;
        let t1 = env.snap_end();
        if ret != 0 {
            return Err(FailReason::UnexpectedSbiError(ret));
        }
        Ok(CounterSnap::delta(t1, t0))
    })
    .commit()
}
