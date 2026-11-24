//! HSM secondary-hart suspend probes and the single-owner suspend worker.

use core::{arch::naked_asm, sync::atomic::Ordering};

use mbench_core::{
    engine::{Clock, CounterSnap},
    record::FailReason,
};
use riscv::register::{sie, sip};

use super::{
    HSM_DONE_EPOCH, HSM_ERR, HSM_RESUME_HART, HSM_RESUME_OPAQUE, HSM_RESUME_READY, HSM_RESUME_SATP,
    HSM_RESUME_SSTATUS, HSM_RESUME_VIA, HSM_STOP_REQUESTED, HSM_SUSPEND_EPOCH, HSM_SUSPEND_TYPE,
    MAX_SPIN_POLLS, send_ipi_single, stop_current_worker_hart, wait_hart_state,
};
use crate::{
    platform::{Platform, boot, counters, impl_platform_clock_topology},
    sbi,
};

/// Wakeup expectation for secondary `sbi_hart_suspend` probes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SuspendWakeMode {
    NoWakeExpected,
    WakeViaIpi,
}

/// Outcome and resume CSR/register verification of a single `sbi_hart_suspend` probe.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HsmSuspendProbe {
    pub(crate) err_code: isize,
    pub(crate) resumed_via_trampoline: bool,
    pub(crate) resumed_hart_id: usize,
    pub(crate) resumed_opaque: usize,
    pub(crate) resumed_satp: usize,
    pub(crate) resumed_sstatus: usize,
    pub(crate) expected_opaque: usize,
}

/// Single-instance RAII secondary worker for retentive / non-retentive `sbi_hart_suspend` benchmarks.
///
/// Holds `&mut Platform` exclusively so no concurrent HSM probes or parallel workers can contend for slot 1.
#[clippy::has_significant_drop]
#[must_use = "HsmSuspendWorker should be finished explicitly to report worker teardown errors"]
pub(crate) struct HsmSuspendWorker<'a> {
    platform: &'a mut Platform,
    peer_hart_id: usize,
    timeout_ticks: u64,
    has_time: bool,
    next_epoch: usize,
    active: bool,
}

impl<'a> HsmSuspendWorker<'a> {
    /// Starts and probes `peer_hart_id` for `suspend_type`; returns `Ok(None)` if `SUSPENDED` is unsupported.
    pub(crate) fn start(
        platform: &'a mut Platform,
        peer_hart_id: usize,
        suspend_type: u32,
        timeout_ticks: u64,
    ) -> Result<Option<Self>, FailReason> {
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

        HSM_STOP_REQUESTED.store(false, Ordering::Release);
        HSM_SUSPEND_EPOCH.store(0, Ordering::Release);
        HSM_DONE_EPOCH.store(0, Ordering::Release);
        HSM_ERR.store(0, Ordering::Release);
        HSM_RESUME_READY.store(0, Ordering::Release);
        HSM_SUSPEND_TYPE.store(suspend_type as usize, Ordering::Release);

        let stack_top = boot::worker_stack_top(1);
        // SAFETY: `peer_hart_id` is STOPPED and slot 1 / HSM statics are exclusively claimed via `HsmHartPool`.
        // CAST: RISC-V entry PC is a `usize`; the symbol is a valid executable S-mode address.
        let ret = unsafe {
            sbi::hsm::hart_start(
                peer_hart_id,
                mbench_hsm_suspend_entry as *const () as usize,
                stack_top,
            )
        };
        if ret.error != 0 {
            platform.harts.release_dedicated_worker();
            return Err(FailReason::SecondaryHartError(sbi::error_code(ret)));
        }

        let mut worker = Self {
            platform,
            peer_hart_id,
            timeout_ticks,
            has_time,
            next_epoch: 0,
            active: true,
        };

        if let Err(err) = counters::wait_until(has_time, timeout_ticks, MAX_SPIN_POLLS, || {
            HSM_RESUME_READY.load(Ordering::Acquire) == 1
        }) {
            let _ = worker.teardown_inner();
            return Err(err);
        }

        // Poll until either the worker hart enters SUSPENDED or reports an early return from `hart_suspend`.
        worker.next_epoch = 1;
        HSM_SUSPEND_EPOCH.store(worker.next_epoch, Ordering::Release);
        let mut saw_suspended = false;
        let _ = counters::wait_until(has_time, timeout_ticks / 4, MAX_SPIN_POLLS, || {
            if HSM_DONE_EPOCH.load(Ordering::Acquire) == worker.next_epoch {
                return true;
            }
            let st = sbi::hsm::hart_get_status(peer_hart_id);
            if st.error == 0 && st.value == sbi::hsm::state::SUSPENDED {
                saw_suspended = true;
                return true;
            }
            false
        });

        if !saw_suspended && HSM_DONE_EPOCH.load(Ordering::Acquire) != worker.next_epoch {
            let _ = worker.teardown_inner();
            return Err(FailReason::Timeout);
        }

        if saw_suspended {
            let ipi = send_ipi_single(peer_hart_id);
            if ipi.error != 0 {
                let _ = worker.teardown_inner();
                return Err(FailReason::UnexpectedSbiError(sbi::error_code(ipi)));
            }
            if let Err(err) = counters::wait_until(has_time, timeout_ticks, MAX_SPIN_POLLS, || {
                HSM_DONE_EPOCH.load(Ordering::Acquire) == worker.next_epoch
            }) {
                let _ = worker.teardown_inner();
                return Err(err);
            }
        }

        let err = HSM_ERR.load(Ordering::Acquire) as isize;
        if err == sbi::SbiError::NotSupported.as_code() {
            worker.teardown_inner()?;
            return Ok(None);
        }
        if err != 0 {
            let _ = worker.teardown_inner();
            return Err(FailReason::SecondaryHartError(err));
        }

        Ok(Some(worker))
    }

    /// Suspends the secondary hart, sends a wakeup IPI, and captures the wake-to-S-mode delta.
    pub(crate) fn measure_wake_sample(&mut self) -> Result<CounterSnap, FailReason> {
        self.next_epoch = self.next_epoch.wrapping_add(1);
        let ep = self.next_epoch;
        // INVARIANT: `wrapping_add` is intentional; the epoch compares fully, and only its exact
        // value is used to match a single suspend/wake round.
        HSM_SUSPEND_EPOCH.store(ep, Ordering::Release);
        wait_hart_state(
            self.peer_hart_id,
            sbi::hsm::state::SUSPENDED,
            self.has_time,
            self.timeout_ticks,
        )?;

        let t0 = self.platform.snap_begin();
        let ret = send_ipi_single(self.peer_hart_id);
        if ret.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }
        counters::wait_until(self.has_time, self.timeout_ticks, MAX_SPIN_POLLS, || {
            HSM_DONE_EPOCH.load(Ordering::Acquire) == ep
        })?;
        let t1 = self.platform.snap_end();

        let err = HSM_ERR.load(Ordering::Acquire);
        if err != 0 {
            return Err(FailReason::SecondaryHartError(err as isize));
        }
        Ok(CounterSnap::delta(t1, t0))
    }

    /// Stops the suspend worker and verifies it reaches [`sbi::hsm::state::STOPPED`].
    pub(crate) fn finish(mut self) -> Result<(), FailReason> {
        let res = self.teardown_inner();
        self.active = false;
        res
    }

    fn teardown_inner(&mut self) -> Result<(), FailReason> {
        if !self.active {
            return Ok(());
        }
        HSM_STOP_REQUESTED.store(true, Ordering::Release);
        let _ = send_ipi_single(self.peer_hart_id);
        let res = wait_hart_state(
            self.peer_hart_id,
            sbi::hsm::state::STOPPED,
            self.has_time,
            self.timeout_ticks,
        );
        self.active = false;
        if res.is_ok() {
            self.platform.harts.release_dedicated_worker();
        } else {
            self.platform.harts.mark_poisoned();
        }
        res
    }
}

impl Drop for HsmSuspendWorker<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.teardown_inner();
        }
    }
}

impl_platform_clock_topology!(HsmSuspendWorker<'_>);

/// Probes a single `sbi_hart_suspend` invocation on `peer_hart_id` and returns observed wakeup state.
pub(crate) fn probe_secondary_suspend(
    platform: &mut Platform,
    peer_hart_id: usize,
    suspend_type: u32,
    wake_mode: SuspendWakeMode,
    timeout_ticks: u64,
) -> Result<HsmSuspendProbe, FailReason> {
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

    HSM_STOP_REQUESTED.store(false, Ordering::Release);
    HSM_SUSPEND_EPOCH.store(0, Ordering::Release);
    HSM_DONE_EPOCH.store(0, Ordering::Release);
    HSM_ERR.store(0, Ordering::Release);
    HSM_RESUME_READY.store(0, Ordering::Release);
    HSM_RESUME_VIA.store(0, Ordering::Release);
    HSM_RESUME_HART.store(usize::MAX, Ordering::Release);
    HSM_RESUME_OPAQUE.store(0, Ordering::Release);
    HSM_RESUME_SATP.store(usize::MAX, Ordering::Release);
    HSM_RESUME_SSTATUS.store(usize::MAX, Ordering::Release);
    HSM_SUSPEND_TYPE.store(suspend_type as usize, Ordering::Release);

    let stack_top = boot::worker_stack_top(1);
    // SAFETY: `peer_hart_id` is STOPPED and slot 1 is exclusively claimed via `HsmHartPool`.
    // CAST: RISC-V entry PC is a `usize`; the symbol is a valid executable S-mode address.
    let start_ret = unsafe {
        sbi::hsm::hart_start(
            peer_hart_id,
            mbench_hsm_suspend_entry as *const () as usize,
            stack_top,
        )
    };
    if start_ret.error != 0 {
        platform.harts.release_dedicated_worker();
        return Err(FailReason::SecondaryHartError(sbi::error_code(start_ret)));
    }

    let wait_ready = counters::wait_until(has_time, timeout_ticks, MAX_SPIN_POLLS, || {
        HSM_RESUME_READY.load(Ordering::Acquire) == 1
    });
    if wait_ready.is_err() {
        HSM_STOP_REQUESTED.store(true, Ordering::Release);
        let _ = send_ipi_single(peer_hart_id);
        let _ = wait_hart_state(
            peer_hart_id,
            sbi::hsm::state::STOPPED,
            has_time,
            timeout_ticks,
        );
        platform.harts.mark_poisoned();
        return Err(FailReason::Timeout);
    }

    HSM_SUSPEND_EPOCH.store(1, Ordering::Release);
    let mut wake_ipi_err: Option<FailReason> = None;
    if wake_mode == SuspendWakeMode::WakeViaIpi {
        let mut saw_suspended = false;
        let _ = counters::wait_until(has_time, timeout_ticks / 4, MAX_SPIN_POLLS, || {
            if HSM_DONE_EPOCH.load(Ordering::Acquire) == 1 {
                return true;
            }
            let st = sbi::hsm::hart_get_status(peer_hart_id);
            if st.error == 0 && st.value == sbi::hsm::state::SUSPENDED {
                saw_suspended = true;
                return true;
            }
            false
        });
        if saw_suspended {
            let ipi = send_ipi_single(peer_hart_id);
            if ipi.error != 0 {
                wake_ipi_err = Some(FailReason::UnexpectedSbiError(sbi::error_code(ipi)));
            }
        }
    }

    let wait_done = if wake_ipi_err.is_some() {
        Err(FailReason::Timeout)
    } else {
        counters::wait_until(has_time, timeout_ticks, MAX_SPIN_POLLS, || {
            HSM_DONE_EPOCH.load(Ordering::Acquire) == 1
        })
    };
    let err_code = HSM_ERR.load(Ordering::Acquire) as isize;
    // INVARIANT: The resume fields are written before `HSM_RESUME_VIA` (Release) and read
    // after the corresponding `Acquire` in `hsm_resumed_rust` / below.
    let probe = HsmSuspendProbe {
        err_code,
        resumed_via_trampoline: HSM_RESUME_VIA.load(Ordering::Acquire) == 1,
        resumed_hart_id: HSM_RESUME_HART.load(Ordering::Acquire),
        resumed_opaque: HSM_RESUME_OPAQUE.load(Ordering::Acquire),
        resumed_satp: HSM_RESUME_SATP.load(Ordering::Acquire),
        resumed_sstatus: HSM_RESUME_SSTATUS.load(Ordering::Acquire),
        expected_opaque: stack_top,
    };

    HSM_STOP_REQUESTED.store(true, Ordering::Release);
    let _ = send_ipi_single(peer_hart_id);
    let stopped_ok = wait_hart_state(
        peer_hart_id,
        sbi::hsm::state::STOPPED,
        has_time,
        timeout_ticks,
    )
    .is_ok();
    if let Some(err) = wake_ipi_err {
        if stopped_ok {
            platform.harts.release_dedicated_worker();
        } else {
            platform.harts.mark_poisoned();
        }
        return Err(err);
    }
    if wait_done.is_err() || !stopped_ok {
        platform.harts.mark_poisoned();
        return Err(FailReason::Timeout);
    }
    platform.harts.release_dedicated_worker();
    Ok(probe)
}

/// Naked secondary entry point launching [`hsm_suspend_worker_rust`].
///
/// # Safety
///
/// Must only be invoked by SBI `hart_start` while BSP holds an active [`HsmSuspendWorker`].
#[unsafe(naked)]
unsafe extern "C" fn mbench_hsm_suspend_entry(_hart_id: usize, stack_top: usize) -> ! {
    naked_asm!(
        "mv sp, a1",
        "csrci sstatus, 2",
        "csrw sie, zero",
        "j {rust_fn}",
        rust_fn = sym hsm_suspend_worker_rust,
    );
}

/// Naked non-retentive suspend resume trampoline capturing entry CSRs/regs and restoring `sp`.
///
/// # Safety
///
/// Invoked by M-mode firmware upon non-retentive wakeup with `a1 = boot::worker_stack_top(1)`.
#[unsafe(naked)]
unsafe extern "C" fn mbench_hsm_resume_entry(_hart_id: usize, stack_top: usize) -> ! {
    naked_asm!(
        "csrr t0, satp",
        "csrr t1, sstatus",
        "mv   sp, a1",
        "csrci sstatus, 2",
        "csrw sie, zero",
        "mv   a2, t0",
        "mv   a3, t1",
        "j {rust_fn}",
        rust_fn = sym hsm_resumed_rust,
    );
}

extern "C" fn hsm_resumed_rust(
    hart_id: usize,
    opaque: usize,
    satp: usize,
    sstatus_bits: usize,
) -> ! {
    HSM_RESUME_HART.store(hart_id, Ordering::Relaxed);
    HSM_RESUME_OPAQUE.store(opaque, Ordering::Relaxed);
    HSM_RESUME_SATP.store(satp, Ordering::Relaxed);
    HSM_RESUME_SSTATUS.store(sstatus_bits, Ordering::Relaxed);
    HSM_RESUME_VIA.store(1, Ordering::Release);
    // SAFETY: Running on worker hart with `sstatus.SIE == 0`.
    unsafe { sip::clear_ssoft() };
    let ep = HSM_SUSPEND_EPOCH.load(Ordering::Acquire);
    HSM_DONE_EPOCH.store(ep, Ordering::Release);
    hsm_suspend_loop(ep)
}

extern "C" fn hsm_suspend_worker_rust() -> ! {
    HSM_RESUME_READY.store(1, Ordering::Release);
    hsm_suspend_loop(0)
}

fn hsm_suspend_loop(mut seen_epoch: usize) -> ! {
    loop {
        if HSM_STOP_REQUESTED.load(Ordering::Acquire) {
            stop_current_worker_hart();
        }
        let ep = HSM_SUSPEND_EPOCH.load(Ordering::Acquire);
        if ep != seen_epoch {
            seen_epoch = ep;
            let stype = HSM_SUSPEND_TYPE.load(Ordering::Acquire) as u32;
            let stack_top = boot::worker_stack_top(1);
            // SAFETY: Keep `sstatus.SIE == 0` and arm `sie.SSIE` so wake IPI exits `hart_suspend` without trapping.
            unsafe {
                sip::clear_ssoft();
                sie::set_ssoft();
            }
            // SAFETY: `mbench_hsm_resume_entry` and `stack_top` (slot 1) remain valid until stop.
            // CAST: RISC-V resume PC is a `usize`; the symbol is a valid executable S-mode address.
            let ret = unsafe {
                sbi::hsm::hart_suspend(
                    stype,
                    mbench_hsm_resume_entry as *const () as usize,
                    stack_top,
                )
            };
            // SAFETY: Disarms `sie` and clears `sip.SSIP` on retentive wakeup.
            unsafe {
                sip::clear_ssoft();
                sie::write(sie::Sie::from_bits(0));
            }
            if ret.error != 0 {
                HSM_ERR.store(ret.error, Ordering::Release);
            }
            HSM_DONE_EPOCH.store(ep, Ordering::Release);
        }
        core::hint::spin_loop();
    }
}
