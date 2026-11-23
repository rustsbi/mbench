//! Exclusively owned misaligned load/store probe buffer and trap-safe instruction primitives.

use core::arch::asm;

use mbench_core::{
    engine::{Clock, CounterSnap},
    record::{CounterAvailability, HartTopology},
};

use crate::{
    mbench_loop,
    platform::{Platform, boot::SyncUnsafeCell, trap},
    sbi::SbiCaps,
};

#[repr(C, align(8))]
struct MisalignedBuf([u8; 32]);

static MISALIGN_BUF: SyncUnsafeCell<MisalignedBuf> = SyncUnsafeCell::new(MisalignedBuf([0; 32]));

macro_rules! unaligned_mem_asm {
    ($insn:literal, $($ops:tt)*) => {
        asm!(".option push", ".option norvc", $insn, ".option pop", $($ops)*)
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
        let raw = MISALIGN_BUF.get().cast::<u8>();
        for i in 0..32 {
            // SAFETY: `i < 32`, strictly inside static `MISALIGN_BUF`.
            unsafe { core::ptr::write_volatile(raw.add(i), 0xA5) };
        }
        let base = addr_for(OffsetKind::Odd);
        for (i, &b) in pattern.iter().enumerate() {
            // SAFETY: `1 + i < 9 < 32`, strictly inside static `MISALIGN_BUF`.
            unsafe { core::ptr::write_volatile((base + i) as *mut u8, b) };
        }
    }

    /// Reads an 8-byte little-endian value starting at `odd_offset` (`base + 1`).
    pub(crate) fn read_odd_u64_le(&self) -> u64 {
        let base = addr_for(OffsetKind::Odd);
        let mut bytes = [0u8; 8];
        for (i, slot) in bytes.iter_mut().enumerate() {
            // SAFETY: `1 + i < 9 < 32`, strictly inside static `MISALIGN_BUF`.
            *slot = unsafe { core::ptr::read_volatile((base + i) as *const u8) };
        }
        u64::from_le_bytes(bytes)
    }

    /// Probes one unaligned signed 16-bit load (`lh`) at `base + 1`.
    pub(crate) fn probe_lh(&mut self) -> Result<isize, trap::TrapInfo> {
        unsafe extern "C" fn do_load(ctx: *mut u8) {
            let out_ptr = ctx.cast::<isize>();
            let addr = addr_for(OffsetKind::Odd);
            let loaded: isize;
            // SAFETY: Leaf probe reading from `MISALIGN_BUF + 1` inside `try_catch_raw`.
            unsafe {
                unaligned_mem_asm!("lh {out}, 0({addr})", out = out(reg) loaded, addr = in(reg) addr, options(nostack));
                out_ptr.write(loaded);
            }
        }
        let mut val = 0isize;
        // SAFETY: `do_load` holds zero `Drop` locals and writes only primitive `isize`.
        unsafe { trap::try_catch_raw((&raw mut val).cast::<u8>(), do_load)? };
        Ok(val)
    }

    /// Probes one unaligned unsigned 16-bit load (`lhu`) at `base + 1`.
    pub(crate) fn probe_lhu(&mut self) -> Result<usize, trap::TrapInfo> {
        unsafe extern "C" fn do_load(ctx: *mut u8) {
            let out_ptr = ctx.cast::<usize>();
            let addr = addr_for(OffsetKind::Odd);
            let loaded: usize;
            // SAFETY: Leaf probe reading from `MISALIGN_BUF + 1` inside `try_catch_raw`.
            unsafe {
                unaligned_mem_asm!("lhu {out}, 0({addr})", out = out(reg) loaded, addr = in(reg) addr, options(nostack));
                out_ptr.write(loaded);
            }
        }
        let mut val = 0usize;
        // SAFETY: `do_load` holds zero `Drop` locals and writes only primitive `usize`.
        unsafe { trap::try_catch_raw((&raw mut val).cast::<u8>(), do_load)? };
        Ok(val)
    }

    /// Probes one unaligned signed 32-bit load (`lw`) at `base + 1`.
    pub(crate) fn probe_lw(&mut self) -> Result<isize, trap::TrapInfo> {
        unsafe extern "C" fn do_load(ctx: *mut u8) {
            let out_ptr = ctx.cast::<isize>();
            let addr = addr_for(OffsetKind::Odd);
            let loaded: isize;
            // SAFETY: Leaf probe reading from `MISALIGN_BUF + 1` inside `try_catch_raw`.
            unsafe {
                unaligned_mem_asm!("lw {out}, 0({addr})", out = out(reg) loaded, addr = in(reg) addr, options(nostack));
                out_ptr.write(loaded);
            }
        }
        let mut val = 0isize;
        // SAFETY: `do_load` holds zero `Drop` locals and writes only primitive `isize`.
        unsafe { trap::try_catch_raw((&raw mut val).cast::<u8>(), do_load)? };
        Ok(val)
    }

    /// Probes one unaligned unsigned 32-bit load (`lwu`) at `base + 1`.
    pub(crate) fn probe_lwu(&mut self) -> Result<usize, trap::TrapInfo> {
        unsafe extern "C" fn do_load(ctx: *mut u8) {
            let out_ptr = ctx.cast::<usize>();
            let addr = addr_for(OffsetKind::Odd);
            let loaded: usize;
            // SAFETY: Leaf probe reading from `MISALIGN_BUF + 1` inside `try_catch_raw`.
            unsafe {
                unaligned_mem_asm!("lwu {out}, 0({addr})", out = out(reg) loaded, addr = in(reg) addr, options(nostack));
                out_ptr.write(loaded);
            }
        }
        let mut val = 0usize;
        // SAFETY: `do_load` holds zero `Drop` locals and writes only primitive `usize`.
        unsafe { trap::try_catch_raw((&raw mut val).cast::<u8>(), do_load)? };
        Ok(val)
    }

    /// Probes one unaligned 64-bit load at `base + 1` via fixed `try_catch_raw`.
    pub(crate) fn probe_ld_64(&mut self) -> Result<u64, trap::TrapInfo> {
        unsafe extern "C" fn do_load(ctx: *mut u8) {
            let out_ptr = ctx.cast::<u64>();
            let addr = addr_for(OffsetKind::Odd);
            let loaded: u64;
            // SAFETY: Leaf probe reading from `MISALIGN_BUF + 1` inside `try_catch_raw`.
            unsafe {
                unaligned_mem_asm!("ld {out}, 0({addr})", out = out(reg) loaded, addr = in(reg) addr, options(nostack));
                out_ptr.write(loaded);
            }
        }
        let mut val = 0u64;
        // SAFETY: `do_load` holds zero `Drop` locals and writes only primitive `u64`.
        unsafe { trap::try_catch_raw((&raw mut val).cast::<u8>(), do_load)? };
        Ok(val)
    }

    /// Probes one unaligned 16-bit store (`sh`) at `base + 1` via fixed `try_catch_raw`.
    pub(crate) fn probe_sh(&mut self, val: u16) -> Result<(), trap::TrapInfo> {
        unsafe extern "C" fn do_store(ctx: *mut u8) {
            // SAFETY: `ctx` points to caller `u16`.
            let v = unsafe { ctx.cast::<u16>().read() } as usize;
            let addr = addr_for(OffsetKind::Odd);
            // SAFETY: Leaf probe storing into `MISALIGN_BUF + 1` inside `try_catch_raw`.
            unsafe {
                unaligned_mem_asm!("sh {val}, 0({addr})", val = in(reg) v, addr = in(reg) addr, options(nostack));
            }
        }
        let mut copy = val;
        // SAFETY: `do_store` holds zero `Drop` locals and accesses only `copy` + `MISALIGN_BUF`.
        unsafe { trap::try_catch_raw((&raw mut copy).cast::<u8>(), do_store) }
    }

    /// Probes one unaligned 32-bit store (`sw`) at `base + 1` via fixed `try_catch_raw`.
    pub(crate) fn probe_sw(&mut self, val: u32) -> Result<(), trap::TrapInfo> {
        unsafe extern "C" fn do_store(ctx: *mut u8) {
            // SAFETY: `ctx` points to caller `u32`.
            let v = unsafe { ctx.cast::<u32>().read() } as usize;
            let addr = addr_for(OffsetKind::Odd);
            // SAFETY: Leaf probe storing into `MISALIGN_BUF + 1` inside `try_catch_raw`.
            unsafe {
                unaligned_mem_asm!("sw {val}, 0({addr})", val = in(reg) v, addr = in(reg) addr, options(nostack));
            }
        }
        let mut copy = val;
        // SAFETY: `do_store` holds zero `Drop` locals and accesses only `copy` + `MISALIGN_BUF`.
        unsafe { trap::try_catch_raw((&raw mut copy).cast::<u8>(), do_store) }
    }

    /// Probes one unaligned 64-bit store of `val` at `base + 1` via fixed `try_catch_raw`.
    pub(crate) fn probe_sd_64(&mut self, val: u64) -> Result<(), trap::TrapInfo> {
        unsafe extern "C" fn do_store(ctx: *mut u8) {
            // SAFETY: `ctx` points to valid caller `u64`; target holds zero `Drop` locals.
            let v = unsafe { ctx.cast::<u64>().read() };
            let addr = addr_for(OffsetKind::Odd);
            // SAFETY: Leaf probe storing into `MISALIGN_BUF + 1` inside `try_catch_raw`.
            unsafe {
                unaligned_mem_asm!("sd {val}, 0({addr})", val = in(reg) v, addr = in(reg) addr, options(nostack));
            }
        }
        let mut copy = val;
        // SAFETY: `do_store` holds zero `Drop` locals and accesses only `copy` + `MISALIGN_BUF`.
        unsafe { trap::try_catch_raw((&raw mut copy).cast::<u8>(), do_store) }
    }

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

fn addr_for(offset: OffsetKind) -> usize {
    let base = MISALIGN_BUF.get().cast::<u8>() as usize;
    match offset {
        OffsetKind::Aligned => base,
        OffsetKind::Odd => base + 1,
    }
}

impl Clock for MisalignProbe<'_> {
    fn snap_begin(&self) -> CounterSnap {
        self.platform.snap_begin()
    }

    fn snap_end(&self) -> CounterSnap {
        self.platform.snap_end()
    }

    fn read_cycles(&self) -> u64 {
        self.platform.read_cycles()
    }

    fn read_ticks(&self) -> u64 {
        self.platform.read_ticks()
    }

    fn availability(&self) -> CounterAvailability {
        self.platform.availability()
    }

    fn timebase_hz(&self) -> u64 {
        self.platform.timebase_hz()
    }
}

impl HartTopology for MisalignProbe<'_> {
    fn total_harts(&self) -> usize {
        self.platform.total_harts()
    }
}
