//! SBI Message Proxy extension.

use mbench_core::record::SbiExtensionId;

use super::{SbiRet, raw_ecall};

pub(crate) const EID: usize = SbiExtensionId::Mpxy.eid();
const FID_GET_SHMEM_SIZE: usize = 0;
const FID_SET_SHMEM: usize = 1;
const FID_GET_CHANNEL_IDS: usize = 2;
const FID_READ_ATTRS: usize = 3;

pub(crate) const FLAG_OVERWRITE_RETURN: usize = 1;
pub(crate) const FLAG_INVALID_RESERVED: usize = 2;

/// MPXY `get_channel_ids` shared memory header (`REMAINING`, `RETURNED`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MpxyChannelIdsHeader {
    pub(crate) remaining: u32,
    pub(crate) returned: u32,
}

const _: () = assert!(size_of::<MpxyChannelIdsHeader>() == 8);

#[inline(always)]
pub(crate) fn get_shmem_size() -> SbiRet {
    // SAFETY: Side-effect-free MPXY size query.
    unsafe { raw_ecall(EID, FID_GET_SHMEM_SIZE, [0; 6]) }
}

/// Configures or clears the MPXY shared memory region.
///
/// # Safety
///
/// `(phys_lo, phys_hi)` must obey the SBI shared-memory validity and registration lifetime contract.
#[inline(always)]
pub(crate) unsafe fn set_shmem(phys_lo: usize, phys_hi: usize, flags: usize) -> SbiRet {
    // SAFETY: Caller guarantees valid MPXY shmem lifetime or intentional rejection probe.
    unsafe { raw_ecall(EID, FID_SET_SHMEM, [phys_lo, phys_hi, flags, 0, 0, 0]) }
}

/// Reads available MPXY channel IDs into the active MPXY shared memory.
///
/// # Safety
///
/// Caller must hold valid exclusive MPXY shared memory registered for this hart.
#[inline(always)]
pub(crate) unsafe fn get_channel_ids(start_index: usize) -> SbiRet {
    // SAFETY: Caller holds active MPXY shared memory registration.
    unsafe { raw_ecall(EID, FID_GET_CHANNEL_IDS, [start_index, 0, 0, 0, 0, 0]) }
}

/// Reads `attr_count` attributes for `channel_id` into the active MPXY shared memory.
///
/// # Safety
///
/// Caller must hold valid exclusive MPXY shared memory registered for this hart.
#[inline(always)]
pub(crate) unsafe fn read_attrs(
    channel_id: usize,
    base_attr_id: usize,
    attr_count: usize,
) -> SbiRet {
    // SAFETY: Caller holds active MPXY shared memory registration.
    unsafe {
        raw_ecall(
            EID,
            FID_READ_ATTRS,
            [channel_id, base_attr_id, attr_count, 0, 0, 0],
        )
    }
}
