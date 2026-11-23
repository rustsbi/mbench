//! Bare-metal RISC-V S-mode entry points, boot image header, per-hart stacks, and `ApBootInfo`.

use core::{
    arch::naked_asm,
    cell::UnsafeCell,
    mem::offset_of,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::platform::trap::HartLocal;

/// Maximum number of harts supported by static stack and slot arrays.
pub(crate) const MAX_HARTS: usize = 64;

/// Size of each per-hart S-mode stack (64 KiB).
pub(crate) const HART_STACK_SIZE: usize = 64 * 1024;

const RISCV_HEADER_VERSION: u32 = 0x2;
const RISCV_IMAGE_MAGIC: u64 = 0x0056_4353_4952; // "RISCV" little-endian
const RISCV_IMAGE_MAGIC2: u32 = 0x0543_5352; // "RSC\x05" little-endian

const fn parse_hex_u64(raw: &str) -> u64 {
    let bytes = raw.as_bytes();
    let mut i = if bytes.len() >= 2 && bytes[0] == b'0' && (bytes[1] == b'x' || bytes[1] == b'X') {
        2
    } else {
        0
    };
    assert!(i < bytes.len(), "empty hexadecimal literal");
    let mut acc = 0u64;
    while i < bytes.len() {
        let digit = match bytes[i] {
            b'0'..=b'9' => (bytes[i] - b'0') as u64,
            b'a'..=b'f' => (bytes[i] - b'a' + 10) as u64,
            b'A'..=b'F' => (bytes[i] - b'A' + 10) as u64,
            _ => panic!("invalid hex digit"),
        };
        acc = acc
            .checked_mul(16)
            .expect("hex literal overflow")
            .checked_add(digit)
            .expect("hex literal overflow");
        i += 1;
    }
    acc
}

/// Configured S-mode physical load address injected by `build.rs`.
pub(crate) const LOAD_ADDR: usize = parse_hex_u64(env!("MBENCH_LOAD_ADDR")) as usize;
const RISCV_TEXT_OFFSET: u64 = parse_hex_u64(env!("MBENCH_TEXT_OFFSET"));

const _: () = assert!(parse_hex_u64("0x80200000") == 0x8020_0000);
const _: () = assert!(parse_hex_u64("0X400000") == 0x40_0000);
const _: () = assert!(LOAD_ADDR != 0 && (LOAD_ADDR & 0xfff) == 0);
const _: () = assert!((RISCV_TEXT_OFFSET & 0xfff) == 0);

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub(crate) struct AlignedStack([u8; HART_STACK_SIZE]);

impl AlignedStack {
    const fn new() -> Self {
        Self([0; HART_STACK_SIZE])
    }
}

/// Typed per-AP boot descriptor passed as `opaque` to `sbi_hart_start` (OSTD `PerApRawInfo` pattern).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ApBootInfo {
    pub(crate) stack_top: usize,
    pub(crate) hart_local: usize,
    pub(crate) slot_idx: usize,
}

impl ApBootInfo {
    const fn zero() -> Self {
        Self {
            stack_top: 0,
            hart_local: 0,
            slot_idx: 0,
        }
    }
}

/// Wrapper for static per-hart storage initialized before secondary harts start.
#[repr(transparent)]
pub(crate) struct SyncUnsafeCell<T>(UnsafeCell<T>);

// SAFETY: Accesses are partitioned by hart index or strictly synchronized at boot/barriers.
unsafe impl<T> Sync for SyncUnsafeCell<T> {}

impl<T> SyncUnsafeCell<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    pub(crate) const fn get(&self) -> *mut T {
        self.0.get()
    }
}

#[unsafe(link_section = ".bss.uninit")]
pub(crate) static BSP_STACK: SyncUnsafeCell<AlignedStack> =
    SyncUnsafeCell::new(AlignedStack::new());

#[unsafe(link_section = ".bss.uninit")]
pub(crate) static WORKER_STACKS: SyncUnsafeCell<[AlignedStack; MAX_HARTS]> =
    SyncUnsafeCell::new([AlignedStack::new(); MAX_HARTS]);

pub(crate) static HART_LOCALS: SyncUnsafeCell<[HartLocal; MAX_HARTS]> =
    SyncUnsafeCell::new([const { HartLocal::new() }; MAX_HARTS]);

static AP_BOOT_INFO: SyncUnsafeCell<[ApBootInfo; MAX_HARTS]> =
    SyncUnsafeCell::new([ApBootInfo::zero(); MAX_HARTS]);

static BOOT_TICKS: AtomicU64 = AtomicU64::new(0);

const _: () = assert!(align_of::<HartLocal>() == 64);

/// Returns the top-of-stack address for secondary worker slot `slot_idx`.
pub(crate) fn worker_stack_top(slot_idx: usize) -> usize {
    assert!(slot_idx < MAX_HARTS, "worker slot index out of bounds");
    (WORKER_STACKS.get().cast::<u8>() as usize) + (slot_idx + 1) * HART_STACK_SIZE
}

/// Initializes `AP_BOOT_INFO[slot_idx]` and returns its physical pointer for `sbi_hart_start`.
///
/// # Safety
///
/// Caller must ensure slot `slot_idx` (`1..MAX_HARTS`) is stopped before updating its boot descriptor.
pub(in crate::platform) unsafe fn prepare_ap_boot_info(slot_idx: usize) -> usize {
    assert!(
        (1..MAX_HARTS).contains(&slot_idx),
        "AP boot slot index must be in 1..MAX_HARTS"
    );
    let hart_local = (HART_LOCALS.get() as usize) + slot_idx.saturating_mul(size_of::<HartLocal>());
    let stack_top = worker_stack_top(slot_idx);
    // SAFETY: Caller guarantees secondary hart `slot_idx` is STOPPED; BSP has exclusive write access.
    unsafe {
        let entry_ptr = &raw mut (*AP_BOOT_INFO.get())[slot_idx];
        entry_ptr.write(ApBootInfo {
            stack_top,
            hart_local,
            slot_idx,
        });
        entry_ptr as usize
    }
}

/// Returns the `rdtime` sample captured at the first instruction of S-mode entry.
pub(crate) fn boot_ticks() -> u64 {
    BOOT_TICKS.load(Ordering::Relaxed)
}

/// Standard 64-byte RISC-V Linux kernel boot header recognized by QEMU `-kernel` and bootloaders.
///
/// # Safety
///
/// Naked boot header placed at the start of `.head.text`; branches straight to `mbench_bsp_start`
/// preserving `a0` (`hart_id`) and `a1` (`dtb_paddr`).
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".head.text")]
unsafe extern "C" fn mbench_boot_header() -> ! {
    naked_asm!(
        ".option push",
        ".option norvc",
        "j mbench_bsp_start",
        ".option pop",
        ".word 0",
        ".balign 8",
        ".dword {text_offset}",
        ".dword __image_end - __image_start",
        ".dword 0",
        ".word {header_version}",
        ".word 0",
        ".dword 0",
        ".dword {magic1}",
        ".balign 4",
        ".word {magic2}",
        ".word 0",
        text_offset = const RISCV_TEXT_OFFSET,
        header_version = const RISCV_HEADER_VERSION,
        magic1 = const RISCV_IMAGE_MAGIC,
        magic2 = const RISCV_IMAGE_MAGIC2,
    );
}

/// Early fallback trap vector skipping a single 4-byte instruction if `rdtime` traps at entry.
///
/// # Safety
///
/// Must only be installed in `stvec` before `.bss` is cleared and normal trap handling starts.
#[unsafe(naked)]
#[unsafe(link_section = ".text.entry")]
unsafe extern "C" fn mbench_early_trap_skip() -> ! {
    naked_asm!(
        ".balign 4",
        "csrr t0, sepc",
        "addi t0, t0, 4",
        "csrw sepc, t0",
        "sret",
    );
}

/// Primary S-mode entry point jumped to from M-mode firmware.
///
/// # Safety
///
/// Called exactly once on the bootstrap hart with `a0 = hart_id` and `a1 = dtb_paddr`.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
unsafe extern "C" fn mbench_bsp_start(hart_id: usize, dtb_paddr: usize) -> ! {
    naked_asm!(
        "la   t0, {early_skip}",
        "csrw stvec, t0",
        "li   t2, 0",
        ".option push",
        ".option norvc",
        "rdtime t2",
        ".option pop",
        "la   t0, __sbss",
        "la   t1, __ebss",
        "1:",
        "bgeu t0, t1, 2f",
        "sd   zero, 0(t0)",
        "addi t0, t0, 8",
        "j    1b",
        "2:",
        "la   sp, {bsp_stack} + {stack_size}",
        "la   tp, {hart_locals}",
        "mv   a2, t2",
        "j    mbench_rust_entry",
        early_skip = sym mbench_early_trap_skip,
        bsp_stack = sym BSP_STACK,
        stack_size = const HART_STACK_SIZE,
        hart_locals = sym HART_LOCALS,
    );
}

/// Secondary worker hart entry trampoline invoked via SBI `hart_start(hart_id, addr, info_ptr)`.
///
/// # Safety
///
/// Called by SBI HSM with `a0 = hart_id` and `a1 = &AP_BOOT_INFO[slot_idx]`.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub(crate) unsafe extern "C" fn mbench_ap_start(hart_id: usize, info_ptr: usize) -> ! {
    naked_asm!(
        "ld   sp, {off_sp}(a1)",
        "ld   tp, {off_tp}(a1)",
        "ld   a1, {off_slot}(a1)",
        "csrci sstatus, 2",
        "csrw sie, zero",
        "j    mbench_ap_rust_entry",
        off_sp = const offset_of!(ApBootInfo, stack_top),
        off_tp = const offset_of!(ApBootInfo, hart_local),
        off_slot = const offset_of!(ApBootInfo, slot_idx),
    );
}

/// Records early boot ticks and forwards to the crate's `mbench_main` entrypoint.
///
/// # Safety
///
/// Must be jumped to only once from `mbench_bsp_start` after `.bss` is zeroed.
#[unsafe(no_mangle)]
unsafe extern "C" fn mbench_rust_entry(hart_id: usize, dtb_paddr: usize, captured_ticks: u64) -> ! {
    BOOT_TICKS.store(captured_ticks, Ordering::Relaxed);
    // SAFETY: Called once on BSP after `.bss` is cleared and `sp`/`tp` are initialized with firmware `(hart_id, dtb_paddr)`.
    let platform = unsafe { crate::platform::Platform::boot(hart_id, dtb_paddr) };
    crate::mbench_main(platform)
}
