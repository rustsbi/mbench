//! SBI Debug Triggers (`DBTR`, SBI v3.0) benchmarks (`dbtr/*`).

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
        shmem::{DbtrAcquire, dbtr_exec_target_addr, dbtr_scratch_addr},
    },
    sbi::{
        self, SbiError,
        dbtr::{TriggerAccess, TriggerData, TriggerKind, build_smode_match_tdata1},
    },
};

/// Declarative SBI DBTR benchmark suite (5 specs).
pub(crate) static SPECS: &[BenchSpec<Platform>] = &[
    dbtr_spec("dbtr/num_triggers", run_dbtr_num),
    dbtr_spec("dbtr/set_shmem", run_dbtr_set_shmem),
    dbtr_spec("dbtr/read_triggers", run_dbtr_read_triggers),
    dbtr_spec("dbtr/install_uninstall", run_dbtr_install_uninstall),
    dbtr_spec("dbtr/enable_disable", run_dbtr_enable_disable),
];

const fn dbtr_spec(
    id: &'static str,
    run: fn(&mut Platform, BenchRun<'_, '_, '_, '_>) -> FinishedBench,
) -> BenchSpec<Platform> {
    BenchSpec {
        meta: BenchMeta {
            id,
            group: BenchGroup::Dbtr,
            unit: "call",
            required_ext: Some(SbiExtensionId::Dbtr),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run,
    }
}

fn run_dbtr_num(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::dbtr::num_triggers(0);
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_batched(env, |_env, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = sbi::dbtr::num_triggers(0);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    })
    .commit()
}

fn run_dbtr_set_shmem(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut session = match env.start_dbtr_session() {
        Ok(DbtrAcquire::Active(s)) => s,
        Ok(DbtrAcquire::TooLarge) => return run.skip(SkipReason::ShmemTooLarge),
        Err(err) => return run.fail(err),
    };
    let pending = run.measure_paired(&mut session, |s| {
        let dis = s.disable_shmem();
        if dis.error != 0 && sbi::error_code(dis) != SbiError::NoShmem.as_code() {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(dis)));
        }
        let t0 = s.snap_begin();
        let en = s.enable_shmem();
        let t1 = s.snap_end();
        if en.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(en)));
        }
        Ok(CounterSnap::delta(t1, t0))
    });
    pending.finish_with(session.finish())
}

fn run_dbtr_read_triggers(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let num_ret = sbi::dbtr::num_triggers(0);
    if num_ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(num_ret)));
    }
    if num_ret.value < 2 {
        return run.skip(SkipReason::NoUsableResource);
    }
    let mut session = match env.start_dbtr_session() {
        Ok(DbtrAcquire::Active(s)) => s,
        Ok(DbtrAcquire::TooLarge) => return run.skip(SkipReason::ShmemTooLarge),
        Err(err) => return run.fail(err),
    };
    let probe = session.read_triggers(0, 1);
    if probe.error != 0 {
        let _ = session.finish();
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(probe)));
    }

    let pending = run.measure_batched(&mut session, |s, iters| {
        let mut errors = 0usize;
        mbench_loop!(iters, {
            let ret = s.read_triggers(0, 1);
            errors |= ret.error;
        });
        BatchOutcome::from_errors(errors, iters)
    });
    pending.finish_with(session.finish())
}

fn sample_match_trigger_data() -> Result<Option<TriggerData>, FailReason> {
    for (access, addr) in [
        (TriggerAccess::Load, dbtr_scratch_addr()),
        (TriggerAccess::Exec, dbtr_exec_target_addr()),
    ] {
        for kind in [TriggerKind::Mcontrol6, TriggerKind::Mcontrol] {
            let tdata1 = build_smode_match_tdata1(kind, access);
            let ret = sbi::dbtr::num_triggers(tdata1);
            if ret.error != 0 {
                return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
            }
            if ret.value > 0 {
                return Ok(Some(TriggerData {
                    tstate: 0,
                    tdata1,
                    tdata2: addr,
                    tdata3: 0,
                }));
            }
        }
    }
    Ok(None)
}

fn run_dbtr_install_uninstall(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let num_ret = sbi::dbtr::num_triggers(0);
    if num_ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(num_ret)));
    }
    if num_ret.value < 2 {
        return run.skip(SkipReason::NoUsableResource);
    }
    let data = match sample_match_trigger_data() {
        Ok(Some(d)) => d,
        Ok(None) => return run.skip(SkipReason::NoUsableResource),
        Err(err) => return run.fail(err),
    };
    let mut session = match env.start_dbtr_session() {
        Ok(DbtrAcquire::Active(s)) => s,
        Ok(DbtrAcquire::TooLarge) => return run.skip(SkipReason::ShmemTooLarge),
        Err(err) => return run.fail(err),
    };
    let pending = run.measure_paired(&mut session, |s| {
        let t0 = s.snap_begin();
        let idx = s.install_single(data)?;
        let un = s.uninstall_installed(idx);
        let t1 = s.snap_end();
        if un.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(un)));
        }
        Ok(CounterSnap::delta(t1, t0))
    });
    pending.finish_with(session.finish())
}

fn run_dbtr_enable_disable(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let num_ret = sbi::dbtr::num_triggers(0);
    if num_ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(num_ret)));
    }
    if num_ret.value < 2 {
        return run.skip(SkipReason::NoUsableResource);
    }
    let data = match sample_match_trigger_data() {
        Ok(Some(d)) => d,
        Ok(None) => return run.skip(SkipReason::NoUsableResource),
        Err(err) => return run.fail(err),
    };
    let mut session = match env.start_dbtr_session() {
        Ok(DbtrAcquire::Active(s)) => s,
        Ok(DbtrAcquire::TooLarge) => return run.skip(SkipReason::ShmemTooLarge),
        Err(err) => return run.fail(err),
    };
    let idx = match session.install_single(data) {
        Ok(i) => i,
        Err(err) => {
            let _ = session.finish();
            return run.fail(err);
        }
    };
    let pre_dis = session.disable_installed(idx);
    if pre_dis.error != 0 {
        let _ = session.finish();
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(pre_dis)));
    }
    let pending = run.measure_paired(&mut session, |s| {
        let t0 = s.snap_begin();
        let en = s.enable_installed(idx);
        let dis = s.disable_installed(idx);
        let t1 = s.snap_end();
        if en.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(en)));
        }
        if dis.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(dis)));
        }
        Ok(CounterSnap::delta(t1, t0))
    });
    pending.finish_with(session.finish())
}
