//! HSM M-to-S handoff probe and its naked entry trampoline.

use core::{arch::naked_asm, sync::atomic::Ordering};

use mbench_core::{engine::Clock, record::FailReason};

use super::{
    HSM_CONF_DONE, HSM_CONF_HART, HSM_CONF_OPAQUE, HSM_CONF_SATP, HSM_CONF_SSTATUS,
    HsmHandoffSnapshot, MAX_SPIN_POLLS, wait_hart_state,
};
use crate::{
    platform::{Platform, boot, counters},
    sbi,
};

/// Probes duplicate `sbi_hart_start` on the already-running boot hart (`AlreadyAvailable`).
pub(crate) fn probe_duplicate_start_boot_hart(platform: &mut Platform) -> sbi::SbiRet {
    let boot_hart_id = platform.info().boot_hart_id;
    // SAFETY: `boot_hart_id` is already STARTED, so M-mode rejects starting it with `AlreadyAvailable`;
    // `mbench_hsm_conf_entry` is a valid S-mode entry symbol.
    // CAST: RISC-V entry PC is a `usize`; the symbol is a valid executable S-mode address.
    unsafe { sbi::hsm::hart_start(boot_hart_id, mbench_hsm_conf_entry as *const () as usize, 0) }
}

/// Starts `peer_hart_id` with `magic_opaque`, captures its initial S-mode registers, and waits for `STOPPED`.
pub(crate) fn probe_secondary_handoff(
    platform: &mut Platform,
    peer_hart_id: usize,
    magic_opaque: usize,
    timeout_ticks: u64,
) -> Result<HsmHandoffSnapshot, FailReason> {
    if platform.harts.is_poisoned()
        || platform.harts.online_harts_count() != 1
        || platform.harts.dedicated_worker_active()
    {
        return Err(FailReason::HardwareInconsistent);
    }
    let has_time = platform.availability().has_time;
    wait_hart_state(
        peer_hart_id,
        sbi::hsm::state::STOPPED,
        has_time,
        timeout_ticks,
    )?;
    platform.harts.claim_dedicated_worker(peer_hart_id)?;
    HSM_CONF_DONE.store(0, Ordering::Release);

    // SAFETY: `peer_hart_id` is verified `STOPPED` and exclusively claimed; stack slot 1 is owned until `STOPPED`.
    // CAST: RISC-V entry PC is a `usize`; the symbol is a valid executable S-mode address.
    let ret = unsafe {
        sbi::hsm::hart_start(
            peer_hart_id,
            mbench_hsm_conf_entry as *const () as usize,
            magic_opaque,
        )
    };
    if ret.error != 0 {
        platform.harts.release_dedicated_worker();
        return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }

    if let Err(err) = counters::wait_until(has_time, timeout_ticks, MAX_SPIN_POLLS, || {
        HSM_CONF_DONE.load(Ordering::Acquire) == 1
    }) {
        platform.harts.mark_poisoned();
        return Err(err);
    }
    if let Err(err) = wait_hart_state(
        peer_hart_id,
        sbi::hsm::state::STOPPED,
        has_time,
        timeout_ticks,
    ) {
        platform.harts.mark_poisoned();
        return Err(err);
    }
    platform.harts.release_dedicated_worker();

    Ok(HsmHandoffSnapshot {
        hart_id: HSM_CONF_HART.load(Ordering::Acquire),
        opaque: HSM_CONF_OPAQUE.load(Ordering::Acquire),
        satp: HSM_CONF_SATP.load(Ordering::Acquire),
        sstatus: HSM_CONF_SSTATUS.load(Ordering::Acquire),
    })
}

/// Naked entry point verifying SBI M->S handoff CSR/ABI state (`satp`, `sstatus`, `a0`, `a1`).
///
/// # Safety
///
/// Must only be invoked by SBI `hart_start` during [`probe_secondary_handoff`] when slot 1 stack
/// (`2 * HART_STACK_SIZE`) is exclusively available.
#[unsafe(naked)]
unsafe extern "C" fn mbench_hsm_conf_entry(_hart_id: usize, _opaque: usize) -> ! {
    naked_asm!(
        "csrr a2, satp",
        "csrr a3, sstatus",
        "la   sp, {worker_stacks} + {offset}",
        "j    {rust_fn}",
        worker_stacks = sym boot::WORKER_STACKS,
        offset = const 2 * boot::HART_STACK_SIZE,
        rust_fn = sym hsm_conf_rust,
    );
}

extern "C" fn hsm_conf_rust(hart_id: usize, opaque: usize, satp: usize, sstatus_bits: usize) -> ! {
    // INVARIANT: The plain fields are published before `HSM_CONF_DONE`; BSP reads them only
    // after an `Acquire` load observes `HSM_CONF_DONE == 1`.
    HSM_CONF_HART.store(hart_id, Ordering::Relaxed);
    HSM_CONF_OPAQUE.store(opaque, Ordering::Relaxed);
    HSM_CONF_SATP.store(satp, Ordering::Relaxed);
    HSM_CONF_SSTATUS.store(sstatus_bits, Ordering::Relaxed);
    HSM_CONF_DONE.store(1, Ordering::Release);
    super::stop_current_worker_hart()
}
