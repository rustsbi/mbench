//! Exclusively owned misaligned load/store probe buffer and trap-safe instruction primitives.

use core::arch::asm;

use crate::{
    mbench_loop,
    platform::{Platform, boot::SyncUnsafeCell, impl_platform_clock_topology, trap},
    sbi::SbiCaps,
};

#[repr(C, align(8))]
struct MisalignedBuf([u8; 32]);

static MISALIGN_BUF: SyncUnsafeCell<MisalignedBuf> = SyncUnsafeCell::new(MisalignedBuf([0; 32]));

macro_rules! unaligned_mem_asm {
    ($insn:expr, $($ops:tt)*) => {
        asm!(".option push", ".option norvc", $insn, ".option pop", $($ops)*)
    };
}

macro_rules! load_probe {
    ($name:ident, $insn:literal, $ty:ty) => {
        /// Probes one unaligned load at `base + 1`.
        pub(crate) fn $name(&mut self) -> Result<$ty, trap::TrapInfo> {
            /// Performs an odd-aligned load into caller storage.
            ///
            /// # Safety
            ///
            /// `ctx` must point to valid writable `$ty` storage and run inside
            /// [`trap::try_catch_raw`].
            unsafe extern "C" fn do_load(ctx: *mut u8) {
                let out_ptr = ctx.cast::<$ty>();
                let addr = addr_for(OffsetKind::Odd);
                let loaded: $ty;
                // SAFETY: Leaf probe reading from `MISALIGN_BUF + 1` inside `try_catch_raw`.
                unsafe {
                    unaligned_mem_asm!(
                        concat!($insn, " {out}, 0({addr})"),
                        out = out(reg) loaded,
                        addr = in(reg) addr,
                        options(nostack)
                    );
                    out_ptr.write(loaded);
                }
            }
            let mut val = 0 as $ty;
            // SAFETY: `do_load` holds zero `Drop` locals and writes only primitive `$ty`.
            unsafe { trap::try_catch_raw((&raw mut val).cast::<u8>(), do_load)? };
            Ok(val)
        }
    };
}

macro_rules! store_probe {
    ($name:ident, $insn:literal, $ty:ty) => {
        /// Probes one unaligned store at `base + 1`.
        pub(crate) fn $name(&mut self, val: $ty) -> Result<(), trap::TrapInfo> {
            /// Performs an odd-aligned store from caller storage.
            ///
            /// # Safety
            ///
            /// `ctx` must point to valid readable `$ty` storage and run inside
            /// [`trap::try_catch_raw`].
            unsafe extern "C" fn do_store(ctx: *mut u8) {
                // SAFETY: `ctx` points to caller `$ty`.
                let v = unsafe { ctx.cast::<$ty>().read() } as usize;
                let addr = addr_for(OffsetKind::Odd);
                // SAFETY: Leaf probe storing into `MISALIGN_BUF + 1` inside `try_catch_raw`.
                unsafe {
                    unaligned_mem_asm!(
                        concat!($insn, " {val}, 0({addr})"),
                        val = in(reg) v,
                        addr = in(reg) addr,
                        options(nostack)
                    );
                }
            }
            let mut copy = val;
            // SAFETY: `do_store` holds zero `Drop` locals and accesses only `copy` + `MISALIGN_BUF`.
            unsafe { trap::try_catch_raw((&raw mut copy).cast::<u8>(), do_store) }
        }
    };
}

/// Direction of an unaligned memory probe operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MisalignOp {
    Load,
    Store,
}

/// Offset alignment inside `MISALIGN_BUF` (`+0` aligned or `+1` misaligned).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OffsetKind {
    Aligned,
    Odd,
}

/// Exclusive BSP handle over the static misalignment buffer and probes.
///
/// # Invariants
///
/// - Borrows `Platform` mutably, so no other BSP-side probe can alias `MISALIGN_BUF`.
/// - `MISALIGN_BUF` is only accessed through `base_ptr()`/`addr_for()`; all Rust-side accesses
///   stay within its 32-byte allocation, and assembly probes are bracketed by `try_catch_raw`.
#[must_use = "MisalignProbe borrows the platform exclusively for probe operations"]
pub(crate) struct MisalignProbe<'a> {
    platform: &'a mut Platform,
}

impl<'a> MisalignProbe<'a> {
    pub(in crate::platform) fn new(platform: &'a mut Platform) -> Self {
        Self { platform }
    }

    pub(crate) fn caps(&self) -> &SbiCaps {
        &self.platform.caps
    }

    pub(crate) fn platform_mut(&mut self) -> &mut Platform {
        self.platform
    }

    /// Writes an 8-byte pattern starting at `odd_offset` (`base + 1`) surrounded by `0xA5` canaries.
    pub(crate) fn write_odd_pattern(&mut self, pattern: &[u8; 8]) {
        let raw = base_ptr();
        for i in 0..32 {
            // SAFETY: `i < 32`, strictly inside static `MISALIGN_BUF`.
            unsafe { core::ptr::write_volatile(raw.add(i), 0xA5) };
        }
        let base = base_ptr();
        for (i, &b) in pattern.iter().enumerate() {
            // SAFETY: `1 + i < 9 < 32`, strictly inside static `MISALIGN_BUF`.
            unsafe { core::ptr::write_volatile(base.add(1 + i), b) };
        }
    }

    /// Reads an 8-byte little-endian value starting at `odd_offset` (`base + 1`).
    pub(crate) fn read_odd_u64_le(&self) -> u64 {
        let base = base_ptr();
        let mut bytes = [0u8; 8];
        for (i, slot) in bytes.iter_mut().enumerate() {
            // SAFETY: `1 + i < 9 < 32`, strictly inside static `MISALIGN_BUF`.
            *slot = unsafe { core::ptr::read_volatile(base.add(1 + i)) };
        }
        u64::from_le_bytes(bytes)
    }

    load_probe!(probe_lh, "lh", isize);
    load_probe!(probe_lhu, "lhu", usize);
    load_probe!(probe_lw, "lw", isize);
    load_probe!(probe_lwu, "lwu", usize);
    load_probe!(probe_ld_64, "ld", u64);
    store_probe!(probe_sh, "sh", u16);
    store_probe!(probe_sw, "sw", u32);
    store_probe!(probe_sd_64, "sd", u64);

    /// Reads `len` bytes starting at `base + 1` and verifies adjacent `0xA5` canary bytes stayed intact.
    pub(crate) fn verify_odd_bytes_and_canaries(&self, expected: &[u8]) -> bool {
        let raw = MISALIGN_BUF.get().cast::<u8>();
        let len = expected.len();
        if len == 0 || 1 + len >= 32 {
            return false;
        }
        // SAFETY: All reads stay within 32-byte `MISALIGN_BUF`.
        unsafe {
            if core::ptr::read_volatile(raw) != 0xA5 {
                return false;
            }
            for (i, &exp) in expected.iter().enumerate() {
                if core::ptr::read_volatile(raw.add(1 + i)) != exp {
                    return false;
                }
            }
            core::ptr::read_volatile(raw.add(1 + len)) == 0xA5
        }
    }

    /// Executes one aligned or misaligned 64-bit load/store for native-vs-emulated classification.
    #[inline(always)]
    pub(crate) fn run_single(&mut self, op: MisalignOp, offset: OffsetKind) {
        run_single(op, offset);
    }

    /// Executes `iters` misaligned 64-bit loads at `base + 1`.
    pub(crate) fn run_load_batch(&mut self, iters: u64) -> u64 {
        let addr = addr_for(OffsetKind::Odd);
        let mut acc = 0u64;
        mbench_loop!(iters, {
            let val: u64;
            // SAFETY: Verified non-trapping misaligned load into exclusive `MISALIGN_BUF`.
            unsafe {
                unaligned_mem_asm!("ld {out}, 0({addr})", out = out(reg) val, addr = in(reg) addr, options(nostack));
            }
            acc ^= val;
        });
        core::hint::black_box(acc)
    }

    /// Executes `iters` misaligned 64-bit stores at `base + 1`.
    pub(crate) fn run_store_batch(&mut self, iters: u64) {
        let addr = addr_for(OffsetKind::Odd);
        let val = 0x1234_5678_9ABC_DEF0u64;
        mbench_loop!(iters, {
            // SAFETY: Verified non-trapping misaligned store into exclusive `MISALIGN_BUF`.
            unsafe {
                unaligned_mem_asm!("sd {val}, 0({addr})", val = in(reg) val, addr = in(reg) addr, options(nostack));
            }
        });
    }
}

/// Executes one aligned or misaligned 64-bit load/store against static `MISALIGN_BUF`.
#[inline(always)]
pub(crate) fn run_single(op: MisalignOp, offset: OffsetKind) {
    let addr = addr_for(offset);
    // SAFETY: `addr` points inside static `MISALIGN_BUF`.
    unsafe {
        match op {
            MisalignOp::Load => {
                let out: u64;
                unaligned_mem_asm!("ld {out}, 0({addr})", out = out(reg) out, addr = in(reg) addr, options(nostack));
                core::hint::black_box(out);
            }
            MisalignOp::Store => {
                let val = 0x0102_0304_0506_0708u64;
                unaligned_mem_asm!("sd {val}, 0({addr})", val = in(reg) val, addr = in(reg) addr, options(nostack));
            }
        }
    }
}

fn base_ptr() -> *mut u8 {
    MISALIGN_BUF.get().cast::<u8>()
}

fn addr_for(offset: OffsetKind) -> usize {
    let base = base_ptr();
    // CAST: assembly `in(reg)` operands are register-width integers; the pointer value keeps its
    // provenance for all Rust-side accesses. No integer address is converted back to a Rust pointer.
    let base = base as usize;
    match offset {
        OffsetKind::Aligned => base,
        OffsetKind::Odd => base + 1,
    }
}

impl_platform_clock_topology!(MisalignProbe<'_>);
