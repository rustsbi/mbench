//! Single-owner SBI Hart State Management (`HSM`) lifecycle probes and suspend worker.
//!
//! The module-level atomics publish a one-producer/one-consumer handshake between BSP and the
//! dedicated worker hart. `HSM_*_EPOCH` values are written by BSP and acknowledged by the worker;
//! the `Release`/`Acquire` pairs form the synchronization edge for the associated plain fields.

use core::sync::atomic::{AtomicBool, AtomicUsize};

use mbench_core::record::FailReason;
use riscv::register::{sie, sip, sstatus};

use crate::{platform::counters, sbi};

pub(super) const MAX_SPIN_POLLS: u64 = 50_000_000;
const HART_MASK_BITS: usize = usize::BITS as usize;
const HART_MASK_MASK: usize = HART_MASK_BITS - 1;

pub(super) static HSM_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
pub(super) static HSM_SUSPEND_EPOCH: AtomicUsize = AtomicUsize::new(0);
pub(super) static HSM_DONE_EPOCH: AtomicUsize = AtomicUsize::new(0);
pub(super) static HSM_ERR: AtomicUsize = AtomicUsize::new(0);
pub(super) static HSM_SUSPEND_TYPE: AtomicUsize = AtomicUsize::new(0);
pub(super) static HSM_RESUME_READY: AtomicUsize = AtomicUsize::new(0);
pub(super) static HSM_PROBE_ACK: AtomicUsize = AtomicUsize::new(0);

pub(super) static HSM_CONF_DONE: AtomicUsize = AtomicUsize::new(0);
pub(super) static HSM_CONF_HART: AtomicUsize = AtomicUsize::new(0);
pub(super) static HSM_CONF_OPAQUE: AtomicUsize = AtomicUsize::new(0);
pub(super) static HSM_CONF_SATP: AtomicUsize = AtomicUsize::new(usize::MAX);
pub(super) static HSM_CONF_SSTATUS: AtomicUsize = AtomicUsize::new(usize::MAX);

pub(super) static HSM_RESUME_VIA: AtomicUsize = AtomicUsize::new(0);
pub(super) static HSM_RESUME_HART: AtomicUsize = AtomicUsize::new(0);
pub(super) static HSM_RESUME_OPAQUE: AtomicUsize = AtomicUsize::new(0);
pub(super) static HSM_RESUME_SATP: AtomicUsize = AtomicUsize::new(usize::MAX);
pub(super) static HSM_RESUME_SSTATUS: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Captured S-mode entry state observed on a newly started secondary hart.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HsmHandoffSnapshot {
    pub(crate) hart_id: usize,
    pub(crate) opaque: usize,
    pub(crate) satp: usize,
    pub(crate) sstatus: usize,
}

mod handoff;
mod start_stop;
mod suspend;

pub(crate) use handoff::{probe_duplicate_start_boot_hart, probe_secondary_handoff};
pub(crate) use start_stop::probe_start_stop_sample;
pub(crate) use suspend::{
    HsmSuspendProbe, HsmSuspendWorker, SuspendWakeMode, probe_secondary_suspend,
};

/// Polls `sbi_hart_get_status(hart_id)` until the hart reaches `wanted` state or times out.
pub(crate) fn wait_hart_state(
    hart_id: usize,
    wanted: usize,
    has_time: bool,
    timeout_ticks: u64,
) -> Result<(), FailReason> {
    let start = if has_time {
        counters::read_time_raw()
    } else {
        0
    };
    let mut spins = 0u64;
    loop {
        let ret = sbi::hsm::hart_get_status(hart_id);
        if ret.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }
        if ret.value == wanted {
            return Ok(());
        }
        if has_time {
            if counters::read_time_raw().wrapping_sub(start) > timeout_ticks {
                return Err(FailReason::Timeout);
            }
        } else {
            spins += 1;
            if spins > MAX_SPIN_POLLS {
                return Err(FailReason::Timeout);
            }
        }
        core::hint::spin_loop();
    }
}

/// Sends a single-hart SBI IPI to `hart_id`.
pub(super) fn send_ipi_single(hart_id: usize) -> sbi::SbiRet {
    // CAST: RISC-V hart masks are register-wide bitsets; hart IDs above the mask width are
    // represented by the second `hart_mask_base` argument.
    sbi::spi::send_ipi(
        1usize << (hart_id & HART_MASK_MASK),
        hart_id & !HART_MASK_MASK,
    )
}

/// Stops the dedicated worker hart and parks forever.
pub(super) fn stop_current_worker_hart() -> ! {
    // SAFETY: Running exclusively on the dedicated worker hart right before calling `hart_stop`.
    unsafe {
        sstatus::clear_sie();
        sie::write(sie::Sie::from_bits(0));
        sip::clear_ssoft();
        let _ = sbi::hsm::hart_stop();
    }
    loop {
        riscv::asm::wfi();
    }
}

const _: () = assert!(HART_MASK_BITS == 64);
