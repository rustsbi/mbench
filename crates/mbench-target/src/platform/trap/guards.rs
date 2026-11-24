//! Save/restore IRQ and trap-hook guards, plus the fixed-probe recovery boundary.

use core::{arch::asm, marker::PhantomData, sync::atomic::Ordering};

use mbench_core::{
    engine::CounterSnap,
    record::{CounterAvailability, FailReason},
};
use riscv::register::{sie, sip, sstatus, stvec};

use super::{
    TrapHookMode, TrapInfo, counter_mask, current_local_ptr, mbench_trap_entry,
    mbench_try_catch_call,
};
use crate::platform::timer;

/// Save/restore RAII guard disabling `sstatus.SIE` on the current hart (OSTD pattern).
#[clippy::has_significant_drop]
#[must_use = "DisabledLocalIrqGuard restores SIE on drop"]
pub(crate) struct DisabledLocalIrqGuard {
    was_sie: bool,
    _not_send_sync: PhantomData<*mut ()>,
}

/// Disables local supervisor interrupts on the current hart and restores prior state on [`Drop`].
pub(crate) fn disable_local_irqs() -> DisabledLocalIrqGuard {
    let was_sie = sstatus::read().sie();
    if was_sie {
        // SAFETY: Clearing `sstatus.SIE` on the current hart protects short critical sections.
        unsafe { sstatus::clear_sie() };
    }
    DisabledLocalIrqGuard {
        was_sie,
        _not_send_sync: PhantomData,
    }
}

impl Drop for DisabledLocalIrqGuard {
    fn drop(&mut self) {
        if self.was_sie {
            // SAFETY: Restores `sstatus.SIE` only when it was enabled upon guard acquisition.
            unsafe { sstatus::set_sie() };
        }
    }
}

/// Low-level fixed-probe trap recovery boundary.
///
/// # Safety
///
/// 1. `target(ctx)` MUST NOT hold any live values with non-trivial [`Drop`] across a potentially
///    trapping instruction, because trap recovery restores `sp` and jumps out immediately.
/// 2. Must not be called nested within another [`try_catch_raw`] on the same hart, and must run
///    while no fast-path [`TrapHookMode`] is active.
/// 3. `tp` must point to this hart's valid [`super::HartLocal`] and `stvec` must point to `mbench_trap_entry`.
pub(crate) unsafe fn try_catch_raw(
    ctx: *mut u8,
    target: unsafe extern "C" fn(*mut u8),
) -> Result<(), TrapInfo> {
    let _irq = disable_local_irqs();
    // SAFETY: Caller guarantees `tp` points to this hart's valid `HartLocal`.
    let local = unsafe { current_local_ptr() };
    // SAFETY: Interrupts are locally disabled, preventing re-entrant trap writes to `HartLocal`.
    let active_try_pc = unsafe { core::ptr::read_volatile(&raw const (*local).try_catch_pc) };
    assert!(active_try_pc == 0, "nested try_catch_raw is forbidden");
    // SAFETY: `local` is exclusively accessed by the current hart with local IRQs disabled.
    let active_hook = unsafe { core::ptr::read_volatile(&raw const (*local).hook_mode) };
    assert!(
        active_hook == TrapHookMode::None as usize,
        "try_catch_raw cannot run while a fast-path trap hook is active"
    );

    // SAFETY: `mbench_try_catch_call` saves callee-saved registers and recovers cleanly if `target` traps.
    let trapped = unsafe { mbench_try_catch_call(ctx, target) };
    if trapped == 0 {
        Ok(())
    } else {
        // SAFETY: Trap handler populated `trap_*` fields prior to jumping to `mbench_try_catch_recover`.
        unsafe {
            Err(TrapInfo {
                scause: core::ptr::read_volatile(&raw const (*local).trap_scause),
                stval: core::ptr::read_volatile(&raw const (*local).trap_stval),
                sepc: core::ptr::read_volatile(&raw const (*local).trap_sepc),
            })
        }
    }
}

/// Internal non-reentrant, save/restore guard for fast-path S-mode trap hooks on the current hart.
#[clippy::has_significant_drop]
#[must_use = "TrapHookGuard restores stvec and interrupt state on drop"]
struct TrapHookGuard {
    previous_stvec: usize,
    previous_sie: usize,
    was_sstatus_sie: bool,
    _not_send_sync: PhantomData<*mut ()>,
}

impl TrapHookGuard {
    fn install(
        mode: TrapHookMode,
        avail: CounterAvailability,
        bounce_target: usize,
    ) -> Result<Self, FailReason> {
        let was_sstatus_sie = sstatus::read().sie();
        let previous_sie = sie::read().bits();
        let previous_stvec = stvec::read().bits();

        // SAFETY: This block has three independent obligations:
        // 1. Local S-mode interrupts are disabled before reading/writing hook state.
        // 2. `tp` points to this hart's `HartLocal` (caller is an active platform session).
        // 3. `mbench_trap_entry` is a 4-byte-aligned direct-mode trap vector.
        // CAST: `stvec` stores a register-width virtual PC.
        unsafe {
            sstatus::clear_sie();
            sie::write(sie::Sie::from_bits(0));
            let local = current_local_ptr();
            if core::ptr::read_volatile(&raw const (*local).hook_mode)
                != TrapHookMode::None as usize
            {
                sie::write(sie::Sie::from_bits(previous_sie));
                if was_sstatus_sie {
                    sstatus::set_sie();
                }
                return Err(FailReason::HardwareInconsistent);
            }
            set_hook_raw(mode, avail, bounce_target);
            stvec::write(stvec::Stvec::from_bits(
                mbench_trap_entry as *const () as usize,
            ));
        }

        Ok(Self {
            previous_stvec,
            previous_sie,
            was_sstatus_sie,
            _not_send_sync: PhantomData,
        })
    }

    fn reset_flag(&self) {
        let _irq = disable_local_irqs();
        // SAFETY: `tp` points to this hart's `HartLocal` and interrupts are disabled.
        unsafe {
            let local = current_local_ptr();
            (*local).hook_flag.store(0, Ordering::Release);
        }
    }

    fn read_flag(&self) -> usize {
        // SAFETY: `tp` points to this hart's `HartLocal`; `Acquire` pairs with trap release atomics.
        unsafe {
            let local = current_local_ptr();
            (*local).hook_flag.load(Ordering::Acquire)
        }
    }

    fn read_snap(&self) -> CounterSnap {
        let _irq = disable_local_irqs();
        // SAFETY: Interrupts are locally disabled, preventing ISR tearing across the 3 counter fields.
        unsafe {
            let local = current_local_ptr();
            CounterSnap {
                cycles: core::ptr::read_volatile(&raw const (*local).hook_cycles),
                instret: core::ptr::read_volatile(&raw const (*local).hook_instret),
                ticks: core::ptr::read_volatile(&raw const (*local).hook_ticks),
            }
        }
    }
}

impl Drop for TrapHookGuard {
    fn drop(&mut self) {
        // SAFETY: This block has four obligations:
        // 1. Local interrupts are disabled before mutating hook state.
        // 2. `tp` points to this hart's `HartLocal`.
        // 3. The stored `previous_stvec` and `previous_sie` are the values captured by `install`.
        // 4. `SIE` is restored only if it was enabled before installation.
        unsafe {
            sstatus::clear_sie();
            sie::write(sie::Sie::from_bits(0));
            let local = current_local_ptr();
            core::ptr::write_volatile(&raw mut (*local).hook_mode, TrapHookMode::None as usize);
            (*local).hook_flag.store(0, Ordering::Release);
            stvec::write(stvec::Stvec::from_bits(self.previous_stvec));
            sie::write(sie::Sie::from_bits(self.previous_sie));
            if self.was_sstatus_sie {
                sstatus::set_sie();
            }
        }
    }
}

/// RAII interrupt enable guard tied by lifetime to a matching active trap hook guard.
#[clippy::has_significant_drop]
#[must_use = "EnabledIrqGuard restores sie/SIE on drop"]
pub(crate) struct EnabledIrqGuard<'a> {
    was_sstatus_sie: bool,
    was_sie_bits: usize,
    _hook: PhantomData<&'a TrapHookGuard>,
    _not_send_sync: PhantomData<*mut ()>,
}

impl<'a> EnabledIrqGuard<'a> {
    fn capture_state() -> (bool, usize) {
        (sstatus::read().sie(), sie::read().bits())
    }
}

impl Drop for EnabledIrqGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: Restores prior `sie` and `sstatus.SIE` on current hart while hook guard is still live.
        unsafe {
            sstatus::clear_sie();
            sie::write(sie::Sie::from_bits(self.was_sie_bits));
            if self.was_sstatus_sie {
                sstatus::set_sie();
            }
        }
    }
}

/// Active `ebreak` counting trap hook on the current hart.
#[clippy::has_significant_drop]
#[must_use]
pub(crate) struct EbreakHookGuard(TrapHookGuard);

impl EbreakHookGuard {
    pub(crate) fn install(avail: CounterAvailability) -> Result<Self, FailReason> {
        TrapHookGuard::install(TrapHookMode::EbreakCount, avail, 0).map(Self)
    }

    pub(crate) fn reset_flag(&self) {
        self.0.reset_flag();
    }

    pub(crate) fn read_flag(&self) -> usize {
        self.0.read_flag()
    }

    /// Executes a single 4-byte `ebreak` handled synchronously by `TrapHookMode::EbreakCount`.
    #[inline(always)]
    pub(crate) fn exec_ebreak(&self) {
        // SAFETY: `EbreakHookGuard` keeps `EbreakCount` installed in `stvec` until dropped.
        unsafe {
            asm!(
                ".option push",
                ".option norvc",
                "ebreak",
                ".option pop",
                options(nostack)
            );
        }
    }
}

/// Active illegal-CSR counting trap hook on the current hart.
#[clippy::has_significant_drop]
#[must_use]
pub(crate) struct IllegalCsrHookGuard(TrapHookGuard);

impl IllegalCsrHookGuard {
    pub(crate) fn install(avail: CounterAvailability) -> Result<Self, FailReason> {
        TrapHookGuard::install(TrapHookMode::IllegalCount, avail, 0).map(Self)
    }

    pub(crate) fn reset_flag(&self) {
        self.0.reset_flag();
    }

    pub(crate) fn read_flag(&self) -> usize {
        self.0.read_flag()
    }

    /// Executes a single 4-byte unprivileged custom CSR read caught by `TrapHookMode::IllegalCount`.
    #[inline(always)]
    pub(crate) fn exec_illegal_csr(&self) {
        // SAFETY: `IllegalCsrHookGuard` keeps `IllegalCount` installed in `stvec` until dropped.
        unsafe {
            asm!(
                ".option push",
                ".option norvc",
                "csrrs zero, 0x7c3, zero",
                ".option pop",
                options(nostack)
            );
        }
    }
}

/// Active SBI timer IRQ capture hook on the current hart.
#[clippy::has_significant_drop]
#[must_use]
pub(crate) struct TimerSbiHookGuard(TrapHookGuard);

impl TimerSbiHookGuard {
    pub(crate) fn install(avail: CounterAvailability) -> Result<Self, FailReason> {
        TrapHookGuard::install(TrapHookMode::TimerSbi, avail, 0).map(Self)
    }

    pub(crate) fn reset_flag(&self) {
        self.0.reset_flag();
    }

    pub(crate) fn read_flag(&self) -> usize {
        self.0.read_flag()
    }

    pub(crate) fn read_snap(&self) -> CounterSnap {
        self.0.read_snap()
    }

    /// Enables `sie.STIE` and `sstatus.SIE`, restoring them when the returned guard drops.
    pub(crate) fn enable_stie(&self) -> EnabledIrqGuard<'_> {
        let (was_sstatus_sie, was_sie_bits) = EnabledIrqGuard::capture_state();
        // SAFETY: `TimerSbiHookGuard` handles supervisor timer interrupts cleanly until drop.
        unsafe {
            sie::set_stimer();
            sstatus::set_sie();
        }
        EnabledIrqGuard {
            was_sstatus_sie,
            was_sie_bits,
            _hook: PhantomData,
            _not_send_sync: PhantomData,
        }
    }
}

/// Active `Sstc` timer IRQ capture hook on the current hart.
#[clippy::has_significant_drop]
#[must_use]
pub(crate) struct TimerSstcHookGuard(TrapHookGuard);

impl TimerSstcHookGuard {
    pub(crate) fn install(avail: CounterAvailability, has_sstc: bool) -> Result<Self, FailReason> {
        if !has_sstc {
            return Err(FailReason::HardwareInconsistent);
        }
        TrapHookGuard::install(TrapHookMode::TimerSstc, avail, 0).map(Self)
    }

    pub(crate) fn reset_flag(&self) {
        self.0.reset_flag();
    }

    pub(crate) fn read_flag(&self) -> usize {
        self.0.read_flag()
    }

    pub(crate) fn read_snap(&self) -> CounterSnap {
        self.0.read_snap()
    }

    /// Enables `sie.STIE` + `sstatus.SIE` and arms `stimecmp = 0`; restores state on [`Drop`].
    pub(crate) fn arm_sstc_zero(&self) -> EnabledIrqGuard<'_> {
        let (was_sstatus_sie, was_sie_bits) = EnabledIrqGuard::capture_state();
        // SAFETY: `TimerSstcHookGuard::install` required `has_sstc == true` and catches the timer IRQ.
        unsafe {
            sie::set_stimer();
            sstatus::set_sie();
            timer::write_stimecmp_raw(0);
        }
        EnabledIrqGuard {
            was_sstatus_sie,
            was_sie_bits,
            _hook: PhantomData,
            _not_send_sync: PhantomData,
        }
    }
}

/// Active IPI capture hook on the current hart.
#[clippy::has_significant_drop]
#[must_use]
pub(crate) struct IpiCaptureHookGuard(TrapHookGuard);

impl IpiCaptureHookGuard {
    pub(crate) fn install(avail: CounterAvailability) -> Result<Self, FailReason> {
        TrapHookGuard::install(TrapHookMode::IpiCapture, avail, 0).map(Self)
    }

    pub(crate) fn reset_flag(&self) {
        self.0.reset_flag();
    }

    pub(crate) fn read_flag(&self) -> usize {
        self.0.read_flag()
    }

    pub(crate) fn read_snap(&self) -> CounterSnap {
        self.0.read_snap()
    }

    /// Clears `sip.SSIP` and enables `sie.SSIE` + `sstatus.SIE`; restores state on [`Drop`].
    pub(crate) fn enable_ssie(&self) -> EnabledIrqGuard<'_> {
        let (was_sstatus_sie, was_sie_bits) = EnabledIrqGuard::capture_state();
        // SAFETY: `IpiCaptureHookGuard` handles S-mode software interrupts cleanly until drop.
        unsafe {
            sip::clear_ssoft();
            sie::set_ssoft();
            sstatus::set_sie();
        }
        EnabledIrqGuard {
            was_sstatus_sie,
            was_sie_bits,
            _hook: PhantomData,
            _not_send_sync: PhantomData,
        }
    }
}

/// Sets the fast-path trap hook state on the current hart without creating a guard.
///
/// # Safety
///
/// Caller must ensure interrupts are locally disabled, `tp` points to this hart's `HartLocal`,
/// and hook mode is reset to [`TrapHookMode::None`] before teardown.
pub(crate) unsafe fn set_hook_raw(
    mode: TrapHookMode,
    avail: CounterAvailability,
    bounce_target: usize,
) {
    // SAFETY: Caller guarantees valid `tp` and local IRQ exclusivity on current hart.
    unsafe {
        let local = current_local_ptr();
        core::ptr::write_volatile(&raw mut (*local).hook_mode, mode as usize);
        core::ptr::write_volatile(&raw mut (*local).counter_mask, counter_mask(avail));
        (*local).hook_flag.store(0, Ordering::Release);
        core::ptr::write_volatile(&raw mut (*local).hook_cycles, 0);
        core::ptr::write_volatile(&raw mut (*local).hook_instret, 0);
        core::ptr::write_volatile(&raw mut (*local).hook_ticks, 0);
        core::ptr::write_volatile(&raw mut (*local).bounce_target_hart, bounce_target);
    }
}
