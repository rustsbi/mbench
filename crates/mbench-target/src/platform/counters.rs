//! Safe probing, serialized reading, and bounded polling of RISC-V S-mode counters.

use core::arch::asm;

use mbench_core::{
    engine::{Clock, CounterSnap, RDTIME_EMULATED_THRESHOLD_CYCLES},
    record::{CounterAvailability, FailReason, SbiExtensionId},
};

use crate::{platform::trap, sbi::SbiCaps};

/// Probed RISC-V S-mode counter backend implementing [`mbench_core::engine::Clock`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct RiscvCounters {
    avail: CounterAvailability,
    timebase_hz: u64,
}

impl RiscvCounters {
    /// Safely probes `rdcycle`, `rdinstret`, and `rdtime` using fixed instruction probes.
    pub(crate) fn probe(caps: &SbiCaps, timebase_hz: u64) -> Self {
        let has_cycle = trap::probe_csr_cycle();
        let has_instret = trap::probe_csr_instret();
        let has_time = trap::probe_csr_time();

        let is_pmu_gated =
            (!has_cycle || !has_instret) && caps.extensions.contains_ext(SbiExtensionId::Pmu);

        let mut is_rdtime_emulated = false;
        if has_cycle && has_time {
            let mut deltas = [0u64; 9];
            let _ = read_time_raw();
            for slot in &mut deltas {
                // SAFETY: Both counters were verified readable above.
                unsafe { asm!("fence iorw, iorw", options(nostack)) };
                let c0 = read_cycle_raw();
                let t = read_time_raw();
                core::hint::black_box(t);
                let c1 = read_cycle_raw();
                *slot = c1.wrapping_sub(c0);
            }
            deltas.sort_unstable();
            is_rdtime_emulated = deltas[deltas.len() / 2] > RDTIME_EMULATED_THRESHOLD_CYCLES;
        }

        Self {
            avail: CounterAvailability {
                has_cycle,
                has_instret,
                has_time,
                is_rdtime_emulated,
                is_pmu_gated,
            },
            timebase_hz,
        }
    }
}

/// Samples counters ordered at batch entry (`time`, `instret`, `cycle`) using `mask` (`1=cycle`, `2=instret`, `4=time`).
#[inline(always)]
pub(crate) fn snap_begin_with_mask(mask: usize) -> CounterSnap {
    // SAFETY: Serializes preceding memory/I/O operations once at batch entry.
    unsafe { asm!("fence iorw, iorw", options(nostack)) };
    // Read `time` first and `cycle` last so an emulated `rdtime` trap never inflates cycles.
    let ticks = if (mask & 4) != 0 { read_time_raw() } else { 0 };
    let instret = if (mask & 2) != 0 {
        read_instret_raw()
    } else {
        0
    };
    let cycles = if (mask & 1) != 0 { read_cycle_raw() } else { 0 };
    CounterSnap {
        cycles,
        instret,
        ticks,
    }
}

/// Samples counters ordered at batch exit (`cycle`, `instret`, `time`) using `mask` (`1=cycle`, `2=instret`, `4=time`).
#[inline(always)]
pub(crate) fn snap_end_with_mask(mask: usize) -> CounterSnap {
    // SAFETY: Serializes measured memory/I/O operations once at batch exit.
    unsafe { asm!("fence iorw, iorw", options(nostack)) };
    // Read `cycle` first and `time` last so an emulated `rdtime` trap never inflates cycles.
    let cycles = if (mask & 1) != 0 { read_cycle_raw() } else { 0 };
    let instret = if (mask & 2) != 0 {
        read_instret_raw()
    } else {
        0
    };
    let ticks = if (mask & 4) != 0 { read_time_raw() } else { 0 };
    CounterSnap {
        cycles,
        instret,
        ticks,
    }
}

/// Polls `cond` until it returns `true` or `timeout_ticks` (or `max_spins` fallback) expires.
pub(crate) fn wait_until(
    has_time: bool,
    timeout_ticks: u64,
    max_spins: u64,
    mut cond: impl FnMut() -> bool,
) -> Result<(), FailReason> {
    let start = if has_time { read_time_raw() } else { 0 };
    let mut spins = 0u64;
    while !cond() {
        if has_time {
            if read_time_raw().wrapping_sub(start) > timeout_ticks {
                return Err(FailReason::Timeout);
            }
        } else {
            spins += 1;
            if spins > max_spins {
                return Err(FailReason::Timeout);
            }
        }
        core::hint::spin_loop();
    }
    Ok(())
}

impl Clock for RiscvCounters {
    fn snap_begin(&self) -> CounterSnap {
        snap_begin_with_mask(trap::counter_mask(self.avail))
    }

    fn snap_end(&self) -> CounterSnap {
        snap_end_with_mask(trap::counter_mask(self.avail))
    }

    fn read_cycles(&self) -> u64 {
        if self.avail.has_cycle {
            read_cycle_raw()
        } else {
            0
        }
    }

    fn read_ticks(&self) -> u64 {
        if self.avail.has_time {
            read_time_raw()
        } else {
            0
        }
    }

    fn availability(&self) -> CounterAvailability {
        self.avail
    }

    fn timebase_hz(&self) -> u64 {
        self.timebase_hz
    }
}

#[inline(always)]
pub(crate) fn read_cycle_raw() -> u64 {
    riscv::register::cycle::read64()
}

#[inline(always)]
pub(crate) fn read_instret_raw() -> u64 {
    riscv::register::instret::read64()
}

#[inline(always)]
pub(crate) fn read_time_raw() -> u64 {
    riscv::register::time::read64()
}
