//! SBI Performance Monitoring Unit extension.

use mbench_core::record::SbiExtensionId;

use super::{SbiRet, raw_ecall};

pub(crate) const EID: usize = SbiExtensionId::Pmu.eid();
const FID_NUM_COUNTERS: usize = sbi_spec::pmu::NUM_COUNTERS;
const FID_SNAPSHOT_SET_SHMEM: usize = sbi_spec::pmu::SNAPSHOT_SET_SHMEM;
const FID_EVENT_GET_INFO: usize = 8;
const PMU_INFO_CSR_MASK: usize = 0x0fff;
const PMU_INFO_WIDTH_MASK: usize = 0x3f;
const PMU_INFO_WIDTH_SHIFT: usize = 12;

pub(crate) const HW_CPU_CYCLES: usize = sbi_spec::pmu::hardware_event::CPU_CYCLES;
pub(crate) const HW_CACHE_REFERENCES: usize = sbi_spec::pmu::hardware_event::CACHE_REFERENCES;
pub(crate) const HW_BRANCH_INSTRUCTIONS: usize = sbi_spec::pmu::hardware_event::BRANCH_INSTRUCTIONS;
pub(crate) const HW_CACHE_BPU_READ_MISS: usize = (sbi_spec::pmu::event_type::HARDWARE_CACHE << 16)
    | (sbi_spec::pmu::cache_event::BPU << 3)
    | (sbi_spec::pmu::cache_operation::READ << 1)
    | sbi_spec::pmu::cache_result::MISS;

const FW_EVENT_BASE: usize = sbi_spec::pmu::event_type::FIRMWARE << 16;
pub(crate) const FW_MISALIGNED_LOAD: usize =
    FW_EVENT_BASE | sbi_spec::pmu::firmware_event::MISALIGNED_LOAD;
pub(crate) const FW_MISALIGNED_STORE: usize =
    FW_EVENT_BASE | sbi_spec::pmu::firmware_event::MISALIGNED_STORE;
pub(crate) const FW_SET_TIMER: usize = FW_EVENT_BASE | sbi_spec::pmu::firmware_event::SET_TIMER;
/// SBI v3.0 `sbi_pmu_event_info.event_idx` bits `[31:20]` are reserved and must be zero.
pub(crate) const EVENT_IDX_RESERVED_BIT: u32 = 1 << 20;

pub(crate) mod config_flags {
    pub(crate) const RESERVED_BIT: usize = 1 << 8;
}

pub(crate) mod start_flags {
    pub(crate) const SET_INIT_VALUE: usize = 1 << 0;
    pub(crate) const INIT_FROM_SNAPSHOT: usize = 1 << 1;
    pub(crate) const RESERVED_BIT: usize = 1 << 2;
}

pub(crate) mod stop_flags {
    pub(crate) const RESET: usize = 1 << 0;
    pub(crate) const TAKE_SNAPSHOT: usize = 1 << 1;
    pub(crate) const RESERVED_BIT: usize = 1 << 2;
}

/// PMU event info query/result entry (`struct sbi_pmu_event_info`, SBI v3.0 FID #8).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EventInfoEntry {
    pub(crate) event_idx: u32,
    pub(crate) output: u32,
    pub(crate) event_data: u64,
}

const _: () = assert!(size_of::<EventInfoEntry>() == 16);

impl EventInfoEntry {
    /// Serializes this entry into its 16-byte little-endian SBI v3.0 wire layout.
    pub(crate) const fn to_le_bytes(self) -> [u8; 16] {
        let idx = self.event_idx.to_le_bytes();
        let out = self.output.to_le_bytes();
        let data = self.event_data.to_le_bytes();
        [
            idx[0], idx[1], idx[2], idx[3], out[0], out[1], out[2], out[3], data[0], data[1],
            data[2], data[3], data[4], data[5], data[6], data[7],
        ]
    }

    /// Deserializes a 16-byte little-endian SBI v3.0 `sbi_pmu_event_info` entry.
    pub(crate) const fn from_le_bytes(bytes: [u8; 16]) -> Self {
        Self {
            event_idx: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            output: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            event_data: u64::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]),
        }
    }
}

/// Returns `true` if `counter_get_info` encodes a firmware counter (MSB set).
#[inline(always)]
pub(crate) const fn info_is_firmware(info: usize) -> bool {
    (info >> (usize::BITS - 1)) != 0
}

/// Returns the CSR number encoded in the lower 12 bits of `counter_get_info`.
#[inline(always)]
pub(crate) const fn info_csr(info: usize) -> usize {
    info & PMU_INFO_CSR_MASK
}

/// Returns counter bit width encoded in `counter_info[17:12]` (`width - 1`).
#[inline(always)]
pub(crate) const fn info_width(info: usize) -> usize {
    ((info >> PMU_INFO_WIDTH_SHIFT) & PMU_INFO_WIDTH_MASK) + 1
}

#[inline(always)]
pub(crate) fn num_counters() -> SbiRet {
    // SAFETY: Read-only PMU counter count query with no pointer arguments.
    unsafe { raw_ecall(EID, FID_NUM_COUNTERS, [0; 6]) }
}

#[inline(always)]
pub(crate) fn counter_get_info(counter_idx: usize) -> SbiRet {
    sbi_rt::pmu_counter_get_info(counter_idx)
}

#[inline(always)]
pub(crate) fn counter_config_matching(
    idx_base: usize,
    idx_mask: usize,
    config_flags: usize,
    event_idx: usize,
    event_data: u64,
) -> SbiRet {
    sbi_rt::pmu_counter_config_matching(idx_base, idx_mask, config_flags, event_idx, event_data)
}

#[inline(always)]
pub(crate) fn counter_start(
    idx_base: usize,
    idx_mask: usize,
    start_flags: usize,
    initial_value: u64,
) -> SbiRet {
    sbi_rt::pmu_counter_start(idx_base, idx_mask, start_flags, initial_value)
}

#[inline(always)]
pub(crate) fn counter_stop(idx_base: usize, idx_mask: usize, stop_flags: usize) -> SbiRet {
    sbi_rt::pmu_counter_stop(idx_base, idx_mask, stop_flags)
}

#[inline(always)]
pub(crate) fn counter_fw_read(counter_idx: usize) -> SbiRet {
    sbi_rt::pmu_counter_fw_read(counter_idx)
}

#[inline(always)]
pub(crate) fn counter_fw_read_hi(counter_idx: usize) -> SbiRet {
    sbi_rt::pmu_counter_fw_read_hi(counter_idx)
}

/// Configures or clears the PMU snapshot shared memory region.
///
/// # Safety
///
/// `(phys_lo, phys_hi)` must be either `(usize::MAX, usize::MAX)` to unregister, a valid
/// 4 KiB-aligned exclusive S-mode buffer, or an intentionally invalid probe parameter that M-mode rejects.
#[inline(always)]
pub(crate) unsafe fn snapshot_set_shmem(phys_lo: usize, phys_hi: usize, flags: usize) -> SbiRet {
    // SAFETY: Caller upholds shared-memory physical address and lifetime contract.
    unsafe {
        raw_ecall(
            EID,
            FID_SNAPSHOT_SET_SHMEM,
            [phys_lo, phys_hi, flags, 0, 0, 0],
        )
    }
}

/// Queries PMU event support info into a 16-byte-aligned buffer of [`EventInfoEntry`].
///
/// # Safety
///
/// `(shmem_lo, shmem_hi)` must be either a writable 16B-aligned exclusive S-mode buffer of
/// at least `num_entries * size_of::<EventInfoEntry>()` bytes or an intentionally invalid probe.
#[inline(always)]
pub(crate) unsafe fn event_get_info_raw(
    shmem_lo: usize,
    shmem_hi: usize,
    num_entries: usize,
    flags: usize,
) -> SbiRet {
    // SAFETY: Caller upholds physical address alignment, length, and exclusivity contract.
    unsafe {
        raw_ecall(
            EID,
            FID_EVENT_GET_INFO,
            [shmem_lo, shmem_hi, num_entries, flags, 0, 0],
        )
    }
}
