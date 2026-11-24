//! Exclusive shared-memory leases for STA, NACL, PMU snapshot, and MPXY.

use mbench_core::record::FailReason;

use super::{PAGE_SIZE, ShmemOwner};
use crate::{
    platform::{Platform, impl_platform_clock_topology},
    sbi::{self, SbiError, SbiRet, mpxy::MpxyChannelIdsHeader},
};

/// Result of attempting to acquire an exclusive [`ShmemLease`].
pub(crate) enum ShmemAcquire<'a> {
    Leased(ShmemLease<'a>),
    Unsupported,
    TooLarge,
}

/// Exclusive BSP lease registering `SHMEM_POOL` with one SBI shared-memory extension.
///
/// Unregisters firmware shared memory BEFORE zeroing and releasing the pool on `finish`/`Drop`.
///
/// # Invariants
///
/// - `active` is true only while `platform.shmem` records `owner` as registered.
/// - `registered_len` is the exact byte length passed to the SBI call and never exceeds pool length.
#[clippy::has_significant_drop]
#[must_use = "ShmemLease should be finished explicitly to report unregister errors"]
pub(crate) struct ShmemLease<'a> {
    platform: &'a mut Platform,
    owner: ShmemOwner,
    registered_len: usize,
    active: bool,
}

impl<'a> ShmemLease<'a> {
    pub(in crate::platform) fn acquire(
        platform: &'a mut Platform,
        owner: ShmemOwner,
    ) -> Result<ShmemAcquire<'a>, FailReason> {
        if owner == ShmemOwner::Dbtr {
            return Err(FailReason::HardwareInconsistent);
        }
        platform.shmem.ensure_idle()?;

        let mut registered_len = platform.shmem.len();
        if owner == ShmemOwner::Mpxy {
            let size_ret = sbi::mpxy::get_shmem_size();
            if size_ret.error != 0 {
                return Err(FailReason::UnexpectedSbiError(sbi::error_code(size_ret)));
            }
            let needed = size_ret.value;
            if needed < PAGE_SIZE || !needed.is_multiple_of(PAGE_SIZE) {
                return Err(FailReason::HardwareInconsistent);
            }
            if needed > platform.shmem.len() {
                return Ok(ShmemAcquire::TooLarge);
            }
            registered_len = needed;
        }

        platform.shmem.zero_all();
        platform.shmem.set_registered(owner);
        let ret = owner.set_raw(platform.shmem.base(), 0, 0);
        if owner == ShmemOwner::PmuSnapshot
            && sbi::error_code(ret) == SbiError::NotSupported.as_code()
        {
            platform.shmem.clear_registered_and_zero();
            return Ok(ShmemAcquire::Unsupported);
        }
        if ret.error != 0 {
            if sbi::error_code(ret) == SbiError::NotSupported.as_code() {
                platform.shmem.clear_registered_and_zero();
            } else {
                let _ = platform.shmem.unregister_and_release(owner);
            }
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }
        Ok(ShmemAcquire::Leased(Self {
            platform,
            owner,
            registered_len,
            active: true,
        }))
    }

    /// Re-registers the already leased pool address (safe benchmark operation while lease is held).
    #[inline(always)]
    pub(crate) fn reregister(&self) -> SbiRet {
        self.owner.set_raw(self.platform.shmem.base(), 0, 0)
    }

    /// Invokes `sbi_mpxy_get_channel_ids` while owning `ShmemOwner::Mpxy`.
    #[inline(always)]
    pub(crate) fn mpxy_get_channel_ids(&self, start_index: usize) -> SbiRet {
        if self.owner != ShmemOwner::Mpxy {
            return SbiRet::invalid_param();
        }
        // SAFETY: `self` guarantees exclusive registered MPXY shmem ownership.
        unsafe { sbi::mpxy::get_channel_ids(start_index) }
    }

    /// Invokes `sbi_mpxy_read_attrs` while owning `ShmemOwner::Mpxy`.
    #[inline(always)]
    pub(crate) fn mpxy_read_attrs(
        &self,
        channel_id: usize,
        base_attr_id: usize,
        attr_count: usize,
    ) -> SbiRet {
        if self.owner != ShmemOwner::Mpxy {
            return SbiRet::invalid_param();
        }
        // SAFETY: `self` guarantees exclusive registered MPXY shmem ownership.
        unsafe { sbi::mpxy::read_attrs(channel_id, base_attr_id, attr_count) }
    }

    /// Reads the typed header returned in MPXY shared memory after `get_channel_ids`.
    pub(crate) fn read_mpxy_channel_ids_header(&self) -> MpxyChannelIdsHeader {
        MpxyChannelIdsHeader {
            remaining: self.platform.shmem.read_u32_at(0),
            returned: self.platform.shmem.read_u32_at(1),
        }
    }

    /// Reads channel ID at array index `idx` bounded by `self.registered_len`.
    pub(crate) fn read_mpxy_channel_id(&self, idx: usize) -> Option<u32> {
        let word_idx = 2usize.checked_add(idx)?;
        let end_byte = word_idx.checked_add(1)?.checked_mul(size_of::<u32>())?;
        if end_byte > self.registered_len {
            return None;
        }
        Some(self.platform.shmem.read_u32_at(word_idx))
    }

    pub(crate) const fn registered_len(&self) -> usize {
        self.registered_len
    }

    /// Unregisters firmware shared memory BEFORE zeroing the pool and returning any error.
    pub(crate) fn finish(mut self) -> Result<(), FailReason> {
        let res = self.release_inner();
        self.active = false;
        res
    }

    fn release_inner(&mut self) -> Result<(), FailReason> {
        self.platform.shmem.unregister_and_release(self.owner)
    }
}

impl Drop for ShmemLease<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.release_inner();
            self.active = false;
        }
    }
}

impl_platform_clock_topology!(ShmemLease<'_>);
