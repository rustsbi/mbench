//! Per-hart trap handling, fixed-instruction exception probing, and save/restore IRQ/hook guards.
//!
//! [`HartLocal`] is the single per-hart scratch block addressed through the `tp` register by
//! `trap.S`. Its field order is an ABI with that assembly file; offsets are asserted at compile time.

use core::{
    arch::global_asm,
    mem::offset_of,
    sync::atomic::{AtomicUsize, Ordering},
};

use mbench_core::record::CounterAvailability;
use riscv::{
    interrupt::{Exception, Interrupt, Trap},
    register::{scause::Scause, sstatus, stvec},
};

use crate::{platform::console, sbi};

mod guards;
mod probes;

pub(crate) use guards::{
    EbreakHookGuard, IllegalCsrHookGuard, IpiCaptureHookGuard, TimerSbiHookGuard,
    TimerSstcHookGuard, set_hook_raw, try_catch_raw,
};
pub(in crate::platform) use probes::read_slot_hook_flag;
pub(crate) use probes::{
    clear_ssip, is_ssip_pending, probe_csr_cycle, probe_csr_instret, probe_csr_time,
    probe_forbidden_csr,
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
///
/// # Invariants
///
/// - `scratch_regs` must remain the first field and contain exactly twelve `usize` slots;
///   `mbench_trap_entry` saves `t0..t3` and `a0..a7` at byte offsets `0..88`.
/// - All later fields are addressed from `trap.S` through the exported `OFF_*` constants.
/// - `hook_flag` is accessed by RV64A release/acquire operations from assembly and Rust.
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
const _: () = assert!(offset_of!(HartLocal, try_catch_pc) == 12 * size_of::<usize>());
const _: () = assert!(align_of::<HartLocal>() == 64);

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
    include_str!("../trap.S"),
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
    // CAST: RISC-V `stvec` stores a virtual PC as a register-width integer.
    let entry = mbench_trap_entry as *const () as usize;
    // SAFETY: Caller guarantees `tp` points to this hart's valid `HartLocal`; `mbench_trap_entry` is 4B-aligned.
    unsafe {
        sstatus::clear_sie();
        riscv::register::sie::write(riscv::register::sie::Sie::from_bits(0));
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

/// Returns `true` if `stvec` currently points to `mbench_trap_entry`.
pub(crate) fn is_default_stvec() -> bool {
    // CAST: `stvec` is a register-width PC integer.
    stvec::read().bits() == (mbench_trap_entry as *const () as usize)
}

/// # Safety
///
/// `tp` must already be initialized to `&HART_LOCALS[slot]` for the executing hart.
unsafe fn current_local_ptr() -> *mut HartLocal {
    let tp: usize;
    // SAFETY: `tp` is reserved by our boot trampolines as the pointer to this hart's `HartLocal`.
    unsafe { core::arch::asm!("mv {}, tp", out(reg) tp, options(nomem, nostack)) };
    // CAST: `tp` is the numeric form of a valid `&mut HartLocal` established by boot.
    tp as *mut HartLocal
}

#[unsafe(no_mangle)]
extern "C" fn mbench_unhandled_trap(scause: usize, stval: usize, sepc: usize) -> ! {
    console::emergency_unhandled_trap(scause, stval, sepc)
}
