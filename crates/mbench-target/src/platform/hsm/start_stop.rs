//! HSM `hart_start`/`hart_stop` latency probe and its naked entry trampoline.

use core::{arch::naked_asm, sync::atomic::Ordering};

use mbench_core::{
    engine::{Clock, CounterSnap},
    record::FailReason,
};

use super::{HSM_PROBE_ACK, MAX_SPIN_POLLS, wait_hart_state};
use crate::{
    platform::{Platform, boot, counters},
    sbi,
};

/// Measures one `sbi_hart_start` -> secondary entry acknowledgement cycle and waits for `STOPPED`.
pub(crate) fn probe_start_stop_sample(
    platform: &mut Platform,
    peer_hart_id: usize,
    timeout_ticks: u64,
) -> Result<CounterSnap, FailReason> {
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
    HSM_PROBE_ACK.store(0, Ordering::Release);
    let stack_top = boot::worker_stack_top(1);

    let t0 = platform.snap_begin();
    // SAFETY: `peer_hart_id` is STOPPED and `stack_top` (slot 1) is exclusively claimed via `HsmHartPool`.
    // CAST: RISC-V entry PC is a `usize`; the symbol is a valid executable S-mode address.
    let ret = unsafe {
        sbi::hsm::hart_start(
            peer_hart_id,
            mbench_hsm_probe_entry as *const () as usize,
            stack_top,
        )
    };
    if ret.error != 0 {
        platform.harts.release_dedicated_worker();
        return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
    }
    if let Err(err) = counters::wait_until(has_time, timeout_ticks, MAX_SPIN_POLLS, || {
        HSM_PROBE_ACK.load(Ordering::Acquire) == 1
    }) {
        platform.harts.mark_poisoned();
        return Err(err);
    }
    let t1 = platform.snap_end();
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
    Ok(CounterSnap::delta(t1, t0))
}

/// Naked secondary entry point for short start/stop latency probing.
///
/// # Safety
///
/// Must only be invoked by SBI `hart_start(peer_hart_id, entry, stack_top)` with a valid
/// slot-1 stack top in `a1` while BSP holds exclusive ownership of `HSM_PROBE_ACK`.
#[unsafe(naked)]
unsafe extern "C" fn mbench_hsm_probe_entry(_hart_id: usize, stack_top: usize) -> ! {
    naked_asm!(
        "mv sp, a1",
        "csrci sstatus, 2",
        "csrw sie, zero",
        "j {rust_fn}",
        rust_fn = sym hsm_probe_rust,
    );
}

extern "C" fn hsm_probe_rust() -> ! {
    HSM_PROBE_ACK.store(1, Ordering::Release);
    super::stop_current_worker_hart()
}
