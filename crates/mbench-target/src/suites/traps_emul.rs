//! Implicit M-mode trap-and-emulate benchmarks (`trap/*`).

use mbench_core::{
    engine::{
        BatchOutcome, BenchFlags, BenchMeta, BenchRun, BenchSpec, Clock, CounterSnap, FinishedBench,
    },
    record::{BenchGroup, FailReason, SbiExtensionId, SkipReason},
};
use riscv::interrupt::{Exception, Trap};

use crate::{
    mbench_loop,
    platform::{
        Platform,
        misalign::{self, MisalignOp, MisalignProbe, OffsetKind},
        pmu::PmuCounterGuard,
        trap,
    },
    sbi,
};

/// Declarative implicit trap-and-emulate benchmark suite.
pub(crate) static SPECS: &[BenchSpec<Platform>] = &[
    BenchSpec {
        meta: BenchMeta {
            id: "trap/illegal_csr",
            group: BenchGroup::TrapEmul,
            unit: "trap",
            required_ext: None,
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_illegal_csr,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "trap/misaligned_load",
            group: BenchGroup::TrapEmul,
            unit: "load",
            required_ext: None,
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_misaligned_load,
    },
    BenchSpec {
        meta: BenchMeta {
            id: "trap/misaligned_store",
            group: BenchGroup::TrapEmul,
            unit: "store",
            required_ext: None,
            min_harts: 1,
            flags: BenchFlags::empty(),
            max_batch_iters: None,
        },
        run: run_misaligned_store,
    },
];

fn run_illegal_csr(env: &mut Platform, run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let guard = match trap::IllegalCsrHookGuard::install(env.availability()) {
        Ok(g) => g,
        Err(err) => return run.fail(err),
    };
    guard.reset_flag();
    guard.exec_illegal_csr();
    if guard.read_flag() != 1 {
        return run.fail(FailReason::VerificationMismatch);
    }
    guard.reset_flag();

    run.measure_batched(env, |_env, iters| {
        mbench_loop!(iters, {
            guard.exec_illegal_csr();
        });
        BatchOutcome::ok(iters)
    })
    .commit()
}

fn run_misaligned_load(env: &mut Platform, mut run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut probe = env.misalign_probe();
    probe.write_odd_pattern(&[0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8]);
    let loaded = match probe.probe_ld_64() {
        Ok(val) => val,
        Err(info) if info.cause() == Ok(Trap::Exception(Exception::LoadMisaligned)) => {
            return run.delegated_to_s();
        }
        Err(info) if info.cause() == Ok(Trap::Exception(Exception::LoadFault)) => {
            return run.skip(SkipReason::NoUsableResource);
        }
        Err(info) => return run.fail(FailReason::UnexpectedTrap(info.scause)),
    };
    if loaded != 0xF8E7_D6C5_B4A3_9281 {
        return run.fail(FailReason::VerificationMismatch);
    }

    match classify_emulation_vs_native(&mut probe, MisalignOp::Load) {
        Classification::Emulated(note) | Classification::UnverifiedNoPmu(note) => {
            run.set_note(note);
            run.measure_batched(&mut probe, |p, iters| {
                let _ = p.run_load_batch(iters);
                BatchOutcome::ok(iters)
            })
            .commit()
        }
        Classification::HwNative(sample) => {
            run.set_note("pmu-verified-hw-native");
            run.hw_native(&probe, sample)
        }
        Classification::Skipped(reason) => run.skip(reason),
        Classification::Failed(reason) => run.fail(reason),
    }
}

fn run_misaligned_store(env: &mut Platform, mut run: BenchRun<'_, '_, '_, '_>) -> FinishedBench {
    let mut probe = env.misalign_probe();
    let sentinel = 0xDEAD_BEEF_CAFE_BABEu64;
    probe.write_odd_pattern(&[0xA5; 8]);
    match probe.probe_sd_64(sentinel) {
        Ok(()) => {}
        Err(info) if info.cause() == Ok(Trap::Exception(Exception::StoreMisaligned)) => {
            return run.delegated_to_s();
        }
        Err(info) if info.cause() == Ok(Trap::Exception(Exception::StoreFault)) => {
            return run.skip(SkipReason::NoUsableResource);
        }
        Err(info) => return run.fail(FailReason::UnexpectedTrap(info.scause)),
    };
    if probe.read_odd_u64_le() != sentinel
        || !probe.verify_odd_bytes_and_canaries(&sentinel.to_le_bytes())
    {
        return run.fail(FailReason::VerificationMismatch);
    }

    match classify_emulation_vs_native(&mut probe, MisalignOp::Store) {
        Classification::Emulated(note) | Classification::UnverifiedNoPmu(note) => {
            run.set_note(note);
            run.measure_batched(&mut probe, |p, iters| {
                p.run_store_batch(iters);
                BatchOutcome::ok(iters)
            })
            .commit()
        }
        Classification::HwNative(sample) => {
            run.set_note("pmu-verified-hw-native");
            run.hw_native(&probe, sample)
        }
        Classification::Skipped(reason) => run.skip(reason),
        Classification::Failed(reason) => run.fail(reason),
    }
}

enum Classification {
    Emulated(&'static str),
    HwNative(CounterSnap),
    UnverifiedNoPmu(&'static str),
    Skipped(SkipReason),
    Failed(FailReason),
}

fn classify_emulation_vs_native(probe: &mut MisalignProbe<'_>, op: MisalignOp) -> Classification {
    if probe.caps().extensions.contains_ext(SbiExtensionId::Pmu) {
        let event = match op {
            MisalignOp::Load => sbi::pmu::FW_MISALIGNED_LOAD,
            MisalignOp::Store => sbi::pmu::FW_MISALIGNED_STORE,
        };
        let mut pmu_guard =
            match PmuCounterGuard::try_configure_firmware(probe.platform_mut(), event) {
                Ok(g) => g,
                Err(err) => return Classification::Failed(err),
            };
        if let Some(mut guard) = pmu_guard.take() {
            let idx = guard.idx();
            let start_ret = sbi::pmu::counter_start(idx, 1, 1, 0);
            if start_ret.error != 0 {
                let _ = guard.finish_reset();
                return Classification::Failed(FailReason::UnexpectedSbiError(sbi::error_code(
                    start_ret,
                )));
            }
            guard.mark_running();
            let b = guard.snap_begin();
            for _ in 0..8 {
                misalign::run_single(op, OffsetKind::Odd);
            }
            let a = guard.snap_end();
            let read_ret = sbi::pmu::counter_fw_read(idx);
            let stop_res = guard.finish_running();
            if read_ret.error != 0 {
                return Classification::Failed(FailReason::UnexpectedSbiError(sbi::error_code(
                    read_ret,
                )));
            }
            if let Err(err) = stop_res {
                return Classification::Failed(err);
            }
            if read_ret.value > 0 {
                return Classification::Emulated("pmu-verified-m-emul");
            }
            let avg = CounterSnap {
                cycles: a.cycles.wrapping_sub(b.cycles) / 8,
                instret: a.instret.wrapping_sub(b.instret) / 8,
                ticks: a.ticks.wrapping_sub(b.ticks) / 8,
            };
            return Classification::HwNative(avg);
        }
    }

    let avail = probe.availability();
    if !avail.has_any() {
        return Classification::Skipped(SkipReason::CounterUnavailable);
    }
    if !avail.has_cycle && !avail.has_instret {
        return Classification::UnverifiedNoPmu("unverified-no-pmu:time-only");
    }

    let ba = probe.snap_begin();
    for _ in 0..32 {
        probe.run_single(op, OffsetKind::Aligned);
    }
    let aa = probe.snap_end();
    let aligned_d = CounterSnap::delta(aa, ba);

    let bm = probe.snap_begin();
    for _ in 0..32 {
        probe.run_single(op, OffsetKind::Odd);
    }
    let am = probe.snap_end();
    let mis_d = CounterSnap::delta(am, bm);

    let looks_emulated = if avail.has_cycle {
        mis_d.cycles
            > aligned_d
                .cycles
                .saturating_mul(3)
                .max(aligned_d.cycles + 640)
    } else {
        mis_d.instret
            > aligned_d
                .instret
                .saturating_mul(3)
                .max(aligned_d.instret + 256)
    };

    if looks_emulated {
        Classification::UnverifiedNoPmu("unverified-no-pmu:heuristic-looks-emulated")
    } else {
        Classification::UnverifiedNoPmu("unverified-no-pmu:heuristic-looks-native")
    }
}
