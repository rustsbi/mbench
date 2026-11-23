//! Per-hart trap handling, fixed-instruction exception probing, and save/restore IRQ/hook guards.

use core::{
    arch::{asm, global_asm},
    marker::PhantomData,
    mem::offset_of,
    sync::atomic::{AtomicUsize, Ordering},
};

use mbench_core::{
    engine::CounterSnap,
    record::{CounterAvailability, FailReason},
};
use riscv::{
    interrupt::{Exception, Interrupt, Trap},
    register::{scause::Scause, sie, sip, sstatus, stvec},
};

use crate::{
    platform::{console, timer},
    sbi,
};

/// Fast-path S-mode trap hook modes dispatched in `mbench_trap_entry`.
#[repr(usize)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrapHookMode {
    None = 0,
    EbreakCount = 1,
    TimerSbi = 2,
    TimerSstc = 3,
    IpiCapture = 4,
    IpiBounce = 5,
    IllegalCount = 6,
}

impl TrapHookMode {
    pub(crate) const fn from_usize(raw: usize) -> Self {
        match raw {
            1 => Self::EbreakCount,
            2 => Self::TimerSbi,
            3 => Self::TimerSstc,
            4 => Self::IpiCapture,
            5 => Self::IpiBounce,
            6 => Self::IllegalCount,
            _ => Self::None,
        }
    }
}

/// Captured RISC-V exception details from `try_catch_raw`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TrapInfo {
    pub(crate) scause: usize,
    pub(crate) stval: usize,
    pub(crate) sepc: usize,
}

impl TrapInfo {
    /// Decodes the captured raw `scause` register into typed `riscv` interrupt/exception enums.
    pub(crate) fn cause(&self) -> riscv::result::Result<Trap<Interrupt, Exception>> {
        Scause::from_bits(self.scause).cause().try_into()
    }
}

/// Per-hart trap scratch and hook snapshot block addressed via `tp`.
#[repr(C, align(64))]
pub(crate) struct HartLocal {
    scratch_regs: [usize; 12],
    try_catch_pc: usize,
    saved_sp: usize,
    trap_scause: usize,
    trap_stval: usize,
    trap_sepc: usize,
    hook_mode: usize,
    hook_cycles: u64,
    hook_instret: u64,
    hook_ticks: u64,
    counter_mask: usize,
    hook_flag: AtomicUsize,
    bounce_target_hart: usize,
}

const _: () = assert!(
    size_of::<AtomicUsize>() == size_of::<usize>()
        && align_of::<AtomicUsize>() == align_of::<usize>()
);

impl HartLocal {
    pub(crate) const fn new() -> Self {
        Self {
            scratch_regs: [0; 12],
            try_catch_pc: 0,
            saved_sp: 0,
            trap_scause: 0,
            trap_stval: 0,
            trap_sepc: 0,
            hook_mode: TrapHookMode::None as usize,
            hook_cycles: 0,
            hook_instret: 0,
            hook_ticks: 0,
            counter_mask: 0,
            hook_flag: AtomicUsize::new(0),
            bounce_target_hart: 0,
        }
    }
}

global_asm!(
    include_str!("trap.S"),
    OFF_TRY_CATCH_PC = const offset_of!(HartLocal, try_catch_pc),
    OFF_SAVED_SP = const offset_of!(HartLocal, saved_sp),
    OFF_TRAP_SCAUSE = const offset_of!(HartLocal, trap_scause),
    OFF_TRAP_STVAL = const offset_of!(HartLocal, trap_stval),
    OFF_TRAP_SEPC = const offset_of!(HartLocal, trap_sepc),
    OFF_HOOK_MODE = const offset_of!(HartLocal, hook_mode),
    OFF_HOOK_CYCLES = const offset_of!(HartLocal, hook_cycles),
    OFF_HOOK_INSTRET = const offset_of!(HartLocal, hook_instret),
    OFF_HOOK_TICKS = const offset_of!(HartLocal, hook_ticks),
    OFF_COUNTER_MASK = const offset_of!(HartLocal, counter_mask),
    OFF_HOOK_FLAG = const offset_of!(HartLocal, hook_flag),
    OFF_BOUNCE_TARGET = const offset_of!(HartLocal, bounce_target_hart),
    MODE_EBREAK = const TrapHookMode::EbreakCount as usize,
    MODE_TIMER_SBI = const TrapHookMode::TimerSbi as usize,
    MODE_TIMER_SSTC = const TrapHookMode::TimerSstc as usize,
    MODE_IPI_CAPTURE = const TrapHookMode::IpiCapture as usize,
    MODE_IPI_BOUNCE = const TrapHookMode::IpiBounce as usize,
    MODE_ILLEGAL = const TrapHookMode::IllegalCount as usize,
    EID_TIME = const sbi::time::EID,
    EID_SPI = const sbi::spi::EID,
);

unsafe extern "C" {
    fn mbench_trap_entry();
    fn mbench_try_catch_call(ctx: *mut u8, target: unsafe extern "C" fn(*mut u8)) -> usize;
}

/// Installs `mbench_trap_entry` into `stvec`, disables local interrupts, and resets per-hart hooks.
///
/// # Safety
///
/// Must only be called after `tp` points to this hart's initialized [`HartLocal`].
pub(crate) unsafe fn init_on_current_hart() {
    let entry = mbench_trap_entry as *const () as usize;
    // SAFETY: Caller guarantees `tp` points to this hart's valid `HartLocal`; `mbench_trap_entry` is 4B-aligned.
    unsafe {
        sstatus::clear_sie();
        sie::write(sie::Sie::from_bits(0));
        stvec::write(stvec::Stvec::from_bits(entry));
        let local = current_local_ptr();
        core::ptr::write_volatile(&raw mut (*local).hook_mode, TrapHookMode::None as usize);
        core::ptr::write_volatile(&raw mut (*local).try_catch_pc, 0);
        (*local).hook_flag.store(0, Ordering::Release);
    }
}

/// Encodes counter availability bits for the fast ISR counter capture path.
pub(crate) const fn counter_mask(avail: CounterAvailability) -> usize {
    let mut mask = 0usize;
    if avail.has_cycle {
        mask |= 1;
    }
    if avail.has_instret {
        mask |= 2;
    }
    if avail.has_time {
        mask |= 4;
    }
    mask
}

/// Save/restore RAII guard disabling `sstatus.SIE` on the current hart (OSTD pattern).
#[must_use]
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
/// 3. `tp` must point to this hart's valid [`HartLocal`] and `stvec` must point to `mbench_trap_entry`.
pub(in crate::platform) unsafe fn try_catch_raw(
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
#[must_use]
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

        // SAFETY: Disables S-mode interrupts locally before inspecting and configuring hook state.
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
        // SAFETY: Disables local interrupts, clears hook state, and restores prior `stvec`/`sie`/`SIE`.
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
#[must_use]
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
pub(in crate::platform) unsafe fn set_hook_raw(
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

/// Returns `true` if `stvec` currently points to `mbench_trap_entry`.
pub(crate) fn is_default_stvec() -> bool {
    stvec::read().bits() == (mbench_trap_entry as *const () as usize)
}

/// Clears `sip.SSIP` (bit 1) on the current hart.
pub(crate) fn clear_ssip() {
    // SAFETY: Acknowledges any pending S-mode software interrupt on the current hart.
    unsafe { sip::clear_ssoft() };
}

/// Returns `true` if supervisor software interrupt (`sip.SSIP`) is pending on the current hart.
pub(crate) fn is_ssip_pending() -> bool {
    sip::read().ssoft()
}

/// Reads `hook_flag` from `HART_LOCALS[slot_idx]` on a secondary worker hart using `Acquire` ordering.
pub(in crate::platform) fn read_slot_hook_flag(slot_idx: usize) -> usize {
    assert!(
        slot_idx < crate::platform::boot::MAX_HARTS,
        "hart slot out of bounds"
    );
    // SAFETY: `slot_idx < MAX_HARTS`, `HART_LOCALS` is `'static`, and `trap.S` updates `hook_flag`
    // via RV64A release atomics matching Rust `AtomicUsize::load(Ordering::Acquire)`.
    unsafe {
        (*crate::platform::boot::HART_LOCALS.get())[slot_idx]
            .hook_flag
            .load(Ordering::Acquire)
    }
}

/// Probes whether reading `cycle` executes in S-mode without trapping.
pub(crate) fn probe_csr_cycle() -> bool {
    unsafe extern "C" fn probe(_ctx: *mut u8) {
        let val = riscv::register::cycle::read64();
        core::hint::black_box(val);
    }
    // SAFETY: `probe` holds no `Drop` locals and executes a single CSR read.
    unsafe { try_catch_raw(core::ptr::null_mut(), probe).is_ok() }
}

/// Probes whether reading `instret` executes in S-mode without trapping.
pub(crate) fn probe_csr_instret() -> bool {
    unsafe extern "C" fn probe(_ctx: *mut u8) {
        let val = riscv::register::instret::read64();
        core::hint::black_box(val);
    }
    // SAFETY: `probe` holds no `Drop` locals and executes a single CSR read.
    unsafe { try_catch_raw(core::ptr::null_mut(), probe).is_ok() }
}

/// Probes whether reading `time` executes in S-mode without trapping.
pub(crate) fn probe_csr_time() -> bool {
    unsafe extern "C" fn probe(_ctx: *mut u8) {
        let val = riscv::register::time::read64();
        core::hint::black_box(val);
    }
    // SAFETY: `probe` holds no `Drop` locals and executes a single CSR read.
    unsafe { try_catch_raw(core::ptr::null_mut(), probe).is_ok() }
}

/// Probes a forbidden M-mode or custom CSR read; `Ok(val)` indicates an unexpected privilege leak.
pub(crate) fn probe_forbidden_csr(selector: usize) -> Result<usize, TrapInfo> {
    macro_rules! define_csr_probe {
        ($fn_name:ident, $csr:literal) => {
            unsafe extern "C" fn $fn_name(ctx: *mut u8) {
                let out_ptr = ctx.cast::<usize>();
                let val: usize;
                // SAFETY: Pure CSR read guarded by `try_catch_raw`; `out_ptr` points to caller stack `usize`.
                unsafe {
                    asm!(
                        ".option push",
                        ".option norvc",
                        concat!("csrrs {out}, ", $csr, ", zero"),
                        ".option pop",
                        out = out(reg) val,
                        options(nostack),
                    );
                    out_ptr.write(val);
                }
            }
        };
    }

    define_csr_probe!(p_mstatus, "0x300");
    define_csr_probe!(p_misa, "0x301");
    define_csr_probe!(p_medeleg, "0x302");
    define_csr_probe!(p_mideleg, "0x303");
    define_csr_probe!(p_mie, "0x304");
    define_csr_probe!(p_mtvec, "0x305");
    define_csr_probe!(p_mscratch, "0x340");
    define_csr_probe!(p_mepc, "0x341");
    define_csr_probe!(p_mvendorid, "0xf11");
    define_csr_probe!(p_marchid, "0xf12");
    define_csr_probe!(p_mimpid, "0xf13");
    define_csr_probe!(p_mhartid, "0xf14");
    define_csr_probe!(p_cust0, "0x7c0");
    define_csr_probe!(p_cust1, "0x7c1");
    define_csr_probe!(p_cust2, "0x7c2");
    define_csr_probe!(p_cust3, "0x7c3");

    const TABLE: [unsafe extern "C" fn(*mut u8); 16] = [
        p_mstatus,
        p_misa,
        p_medeleg,
        p_mideleg,
        p_mie,
        p_mtvec,
        p_mscratch,
        p_mepc,
        p_mvendorid,
        p_marchid,
        p_mimpid,
        p_mhartid,
        p_cust0,
        p_cust1,
        p_cust2,
        p_cust3,
    ];

    let mut out_val = 0usize;
    let probe_fn = TABLE[selector % TABLE.len()];
    // SAFETY: Leaf probe writes only to `usize` (`out_val`) and has zero `Drop` locals.
    unsafe { try_catch_raw((&raw mut out_val).cast::<u8>(), probe_fn)? };
    Ok(out_val)
}

/// # Safety
///
/// `tp` must already be initialized to `&HART_LOCALS[slot]` for the executing hart.
unsafe fn current_local_ptr() -> *mut HartLocal {
    let tp: usize;
    // SAFETY: `tp` is reserved by our boot trampolines as the pointer to this hart's `HartLocal`.
    unsafe { asm!("mv {}, tp", out(reg) tp, options(nomem, nostack)) };
    tp as *mut HartLocal
}

#[unsafe(no_mangle)]
extern "C" fn mbench_unhandled_trap(scause: usize, stval: usize, sepc: usize) -> ! {
    console::emergency_unhandled_trap(scause, stval, sepc)
}
