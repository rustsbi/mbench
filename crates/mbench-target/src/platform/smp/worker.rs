//! Secondary worker entry and command loop.

use core::sync::atomic::Ordering;

use mbench_core::{engine::ParallelWorkFn, record::CounterAvailability};
use riscv::register::{sie, sip, sstatus};

use super::{
    CMD_READ_TARGET_PAGE, CMD_RUN_PARALLEL, CMD_SET_IPI_MODE, CMD_SET_SATP, CMD_STOP,
    START_BARRIER, SV39_CFG, WORKER_PARKED, barrier_decode, slot_ref,
};
use crate::{
    platform::{
        boot::MAX_HARTS,
        mmu::{self, SatpTarget},
        trap::{self, TrapHookMode},
    },
    sbi,
};

/// Secondary worker loop entered from [`crate::platform::boot::mbench_ap_start`] with
/// `a0 = hart_id` and `a1 = slot_idx`.
///
/// # Safety
///
/// Must be entered only once per secondary hart start with a unique `slot_idx` in `1..MAX_HARTS`.
#[unsafe(no_mangle)]
unsafe extern "C" fn mbench_ap_rust_entry(_hart_id: usize, slot_idx: usize) -> ! {
    assert!(slot_idx < MAX_HARTS, "worker slot index out of bounds");
    // SAFETY: `mbench_ap_start` initialized `tp` to `&HART_LOCALS[slot_idx]`.
    unsafe { trap::init_on_current_hart() };
    let slot = slot_ref(slot_idx);
    let mut seen_epoch = slot.epoch.load(Ordering::Acquire);
    slot.state.store(WORKER_PARKED, Ordering::Release);

    loop {
        let ep = loop {
            let cur = slot.epoch.load(Ordering::Acquire);
            if cur != seen_epoch {
                break cur;
            }
            core::hint::spin_loop();
        };
        seen_epoch = ep;

        match slot.cmd.load(Ordering::Relaxed) {
            CMD_RUN_PARALLEL => {
                let fn_addr = slot.param0.load(Ordering::Relaxed);
                let iters = slot.param1.load(Ordering::Relaxed) as u64;
                let parallel = slot.param2.load(Ordering::Relaxed);
                const _: () = {
                    assert!(size_of::<ParallelWorkFn>() == size_of::<usize>());
                    assert!(align_of::<ParallelWorkFn>() <= align_of::<usize>());
                };
                #[expect(
                    clippy::disallowed_methods,
                    reason = "worker handoff passes a ParallelWorkFn pointer as usize across the atomic slot ABI"
                )]
                let work_fn: ParallelWorkFn = {
                    // SAFETY: `fn_addr` was written by BSP from a valid `ParallelWorkFn`; the epoch
                    // handshake keeps the callable alive for the duration of this command.
                    // CAST: function pointers are published as register-width addresses.
                    unsafe { core::mem::transmute(fn_addr) }
                };

                super::READY_BARRIER.fetch_add(1, Ordering::AcqRel);
                let (_, cancelled) = loop {
                    let cur = START_BARRIER.load(Ordering::Acquire);
                    let decoded = barrier_decode(cur);
                    if decoded.0 == ep {
                        break decoded;
                    }
                    core::hint::spin_loop();
                };
                if cancelled {
                    slot.done_epoch.store(ep, Ordering::Release);
                    continue;
                }

                let sample = work_fn(slot_idx, parallel, iters);
                slot.sample_cycles
                    .store(sample.delta.cycles, Ordering::Relaxed);
                slot.sample_instret
                    .store(sample.delta.instret, Ordering::Relaxed);
                slot.sample_ticks
                    .store(sample.delta.ticks, Ordering::Relaxed);
                slot.sample_errors
                    .store(sample.error_bits, Ordering::Relaxed);
                slot.done_epoch.store(ep, Ordering::Release);
            }
            CMD_SET_SATP => {
                let target = if slot.param0.load(Ordering::Relaxed) == 0 {
                    SatpTarget::Bare
                } else {
                    // SAFETY: `SV39_CFG` was initialized by BSP prior to starting secondary harts.
                    let cfg = unsafe { (*SV39_CFG.get()).expect("SV39_CFG initialized at boot") };
                    SatpTarget::Sv39(cfg)
                };
                let _ = mmu::apply(target);
                slot.done_epoch.store(ep, Ordering::Release);
            }
            CMD_SET_IPI_MODE => {
                let mode = TrapHookMode::from_usize(slot.param0.load(Ordering::Relaxed));
                let bounce_target = slot.param2.load(Ordering::Relaxed);
                let mask_val = slot.param1.load(Ordering::Relaxed);
                let avail = CounterAvailability {
                    has_cycle: (mask_val & 1) != 0,
                    has_instret: (mask_val & 2) != 0,
                    has_time: (mask_val & 4) != 0,
                    is_rdtime_emulated: false,
                    is_pmu_gated: false,
                };
                // SAFETY: `tp` is valid and owned exclusively by this worker hart with IRQs disabled first.
                unsafe {
                    sstatus::clear_sie();
                    sie::write(sie::Sie::from_bits(0));
                    sip::clear_ssoft();
                    trap::set_hook_raw(mode, avail, bounce_target);
                    if mode != TrapHookMode::None {
                        sie::set_ssoft();
                        sstatus::set_sie();
                    }
                }
                slot.done_epoch.store(ep, Ordering::Release);
            }
            CMD_STOP => {
                // SAFETY: Disable interrupts and trap hooks before relinquishing hart to SBI HSM.
                unsafe {
                    sstatus::clear_sie();
                    sie::write(sie::Sie::from_bits(0));
                    sip::clear_ssoft();
                    trap::set_hook_raw(TrapHookMode::None, CounterAvailability::default(), 0);
                    let _ = sbi::hsm::hart_stop();
                }
                loop {
                    riscv::asm::wfi();
                }
            }
            CMD_READ_TARGET_PAGE => {
                let addr = slot.param0.load(Ordering::Relaxed);
                // SAFETY: BSP passes identity/Sv39-mapped `RFENCE_TARGET_PAGE` address under `Sv39Guard`.
                // CAST: the numeric address is a valid `*const u64` while the guard is active.
                let val = unsafe { core::ptr::read_volatile(addr as *const u64) };
                slot.probe_val.store(val, Ordering::Release);
                slot.done_epoch.store(ep, Ordering::Release);
            }
            _ => {
                slot.done_epoch.store(ep, Ordering::Release);
            }
        }
    }
}
