//! Multi-hart scalability sweeps (`scale/*`) exposing M-mode firmware lock contention.

use mbench_core::{
    engine::{
        BenchFlags, BenchMeta, BenchRun, BenchSpec, CounterSnap, FinishedBench, ParallelSample,
    },
    record::{BenchGroup, FailReason, SbiExtensionId},
};

use crate::{
    mbench_loop,
    platform::{Platform, mmu, smp},
    sbi,
};

/// Declarative multi-hart scalability sweep suite (2 specs).
pub(crate) static SPECS: &[BenchSpec<Platform>] = &[
    BenchSpec {
        meta: BenchMeta {
            id: "scale/base_ecall",
            group: BenchGroup::Scale,
            unit: "call",
            required_ext: Some(SbiExtensionId::Base),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_scale_base_ecall,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "scale/sfence_vma",
            group: BenchGroup::Scale,
            unit: "call",
            required_ext: Some(SbiExtensionId::Rfnc),
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_scale_sfence_vma,
    },
];

fn run_scale_base_ecall(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let ret = sbi::base::get_spec_version();
    if ret.error != 0 {
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    run.measure_parallel_sweep(env, ecall_par_worker).commit()
}

fn ecall_par_worker(_slot: usize, _parallel: usize, iters: u64) -> ParallelSample {
    let mut errors = 0usize;
    let b = smp::worker_snap_begin();
    mbench_loop!(iters, {
        let ret = sbi::base::get_spec_version();
        errors |= ret.error;
    });
    let a = smp::worker_snap_end();
    ParallelSample {
        delta: CounterSnap::delta(a, b),
        error_bits: errors,
    }
}

fn run_scale_sfence_vma(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut sv39 = match env.enable_sv39() {
        Ok(g) => g,
        Err(err) => return run.fail(err),
    };
    let (mask, base) = sv39.self_hart_mask();
    let ret = sbi::rfnc::remote_sfence_vma(mask, base, sv39.target_page_addr(), 4096);
    if ret.error != 0 {
        let _ = sv39.finish();
        return run.fail(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    let pending = run.measure_parallel_sweep(&mut sv39, rfence_par_worker);
    pending.finish_with(sv39.finish())
}

fn rfence_par_worker(slot: usize, parallel: usize, iters: u64) -> ParallelSample {
    let target_slot = if parallel >= 2 {
        usize::from(slot == 0)
    } else {
        0
    };
    let target_hid = smp::slot_hart_id(target_slot);
    let (mask, base) = Platform::hart_mask_single(target_hid);
    let addr = mmu::target_page_addr();

    let mut errors = 0usize;
    let b = smp::worker_snap_begin();
    mbench_loop!(iters, {
        let ret = sbi::rfnc::remote_sfence_vma(mask, base, addr, 4096);
        errors |= ret.error;
    });
    let a = smp::worker_snap_end();
    ParallelSample {
        delta: CounterSnap::delta(a, b),
        error_bits: errors,
    }
}
