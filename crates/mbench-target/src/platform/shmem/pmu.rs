//! PMU event-info probes over the exclusively owned shared-memory pool.

use core::ptr;

use mbench_core::record::FailReason;

use crate::{
    platform::Platform,
    sbi::{self, SbiRet, pmu::EventInfoEntry},
};

/// Invokes `sbi_pmu_event_get_info` on `entries` using exclusively owned scratch memory at `byte_offset`.
pub(in crate::platform) fn probe_pmu_event_get_info(
    platform: &mut Platform,
    entries: &mut [EventInfoEntry],
    flags: usize,
    byte_offset: usize,
) -> Result<SbiRet, FailReason> {
    platform.shmem.ensure_idle()?;
    let bytes = entries.len().saturating_mul(size_of::<EventInfoEntry>());
    let total = byte_offset
        .checked_add(bytes)
        .ok_or(FailReason::HardwareInconsistent)?;
    if total > platform.shmem.len() {
        return Err(FailReason::HardwareInconsistent);
    }
    platform
        .shmem
        .zero_prefix(total.max(size_of::<EventInfoEntry>()));
    let base = platform.shmem.base_ptr();
    // SAFETY: `total <= shmem.len()` and `base` retains the static pool provenance. Byte-wise
    // volatile stores are used because the probe intentionally exercises unaligned offsets.
    unsafe {
        let addr = base.add(byte_offset);
        for (i, &entry) in entries.iter().enumerate() {
            let raw_bytes = entry.to_le_bytes();
            let dst_base = addr.add(i * size_of::<EventInfoEntry>());
            for (b_idx, &byte) in raw_bytes.iter().enumerate() {
                ptr::write_volatile(dst_base.add(b_idx), byte);
            }
        }
        // CAST: SBI consumes the identity-mapped physical address of the pool.
        let ret = sbi::pmu::event_get_info_raw(addr as usize, 0, entries.len(), flags);
        for (i, dst) in entries.iter_mut().enumerate() {
            let src_base = addr.add(i * size_of::<EventInfoEntry>());
            let mut raw_bytes = [0u8; size_of::<EventInfoEntry>()];
            for (b_idx, slot) in raw_bytes.iter_mut().enumerate() {
                *slot = ptr::read_volatile(src_base.add(b_idx));
            }
            *dst = EventInfoEntry::from_le_bytes(raw_bytes);
        }
        platform.shmem.zero_prefix(total);
        Ok(ret)
    }
}
