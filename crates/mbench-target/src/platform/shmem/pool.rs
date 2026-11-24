//! Singleton shared-memory pool and its registration-state machine.

use core::ptr;

use mbench_core::record::FailReason;

use super::PAGE_SIZE;
use crate::{
    platform::boot::SyncUnsafeCell,
    sbi::{self, SbiError, SbiRet, dbtr::TriggerData},
};

/// SBI extension owning the static shared-memory pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShmemOwner {
    Sta,
    Nacl,
    PmuSnapshot,
    Mpxy,
    Dbtr,
}

impl ShmemOwner {
    pub(super) fn set_raw(self, phys_lo: usize, phys_hi: usize, flags: usize) -> SbiRet {
        // SAFETY: Called only with exclusively owned `SHMEM_POOL`, `(MAX, MAX)` unregister,
        // or bounded negative security probes inside `probe_security`.
        unsafe {
            match self {
                Self::Sta => sbi::sta::set_shmem(phys_lo, phys_hi, flags),
                Self::Nacl => sbi::nacl::set_shmem(phys_lo, phys_hi, flags),
                Self::PmuSnapshot => sbi::pmu::snapshot_set_shmem(phys_lo, phys_hi, flags),
                Self::Mpxy => sbi::mpxy::set_shmem(phys_lo, phys_hi, flags),
                Self::Dbtr => sbi::dbtr::set_shmem(phys_lo, phys_hi, flags),
            }
        }
    }

    pub(super) const fn invalid_flags(self) -> usize {
        match self {
            // MPXY flags[1:0] = 0b01 is valid OVERWRITE-RETURN; use reserved encoding 0b10.
            Self::Mpxy => sbi::mpxy::FLAG_INVALID_RESERVED,
            Self::Sta | Self::Nacl | Self::Dbtr | Self::PmuSnapshot => 1,
        }
    }

    pub(super) const fn flags_label(self) -> &'static str {
        match self {
            Self::Sta => "sta_nonzero_flags_rejected",
            Self::Nacl => "nacl_nonzero_flags_rejected",
            Self::Dbtr => "dbtr_nonzero_flags_rejected",
            Self::Mpxy => "mpxy_reserved_flags_rejected",
            Self::PmuSnapshot => "pmu_snapshot_nonzero_flags_rejected",
        }
    }

    pub(super) const fn unaligned_label(self) -> &'static str {
        match self {
            Self::Sta => "sta_unaligned_addr_rejected",
            Self::Nacl => "nacl_unaligned_addr_rejected",
            Self::Dbtr => "dbtr_unaligned_addr_rejected",
            Self::Mpxy => "mpxy_unaligned_addr_rejected",
            Self::PmuSnapshot => "pmu_snapshot_unaligned_addr_rejected",
        }
    }

    pub(super) const fn phys_hi_label(self) -> &'static str {
        match self {
            Self::Sta => "sta_invalid_phys_hi_rejected",
            Self::Nacl => "nacl_invalid_phys_hi_rejected",
            Self::Dbtr => "dbtr_invalid_phys_hi_rejected",
            Self::Mpxy => "mpxy_invalid_phys_hi_rejected",
            Self::PmuSnapshot => "pmu_snapshot_invalid_phys_hi_rejected",
        }
    }

    pub(super) const fn mmode_label(self) -> &'static str {
        match self {
            Self::Sta => "sta_mmode_addr_rejected",
            Self::Nacl => "nacl_mmode_addr_rejected",
            Self::Dbtr => "dbtr_mmode_addr_rejected",
            Self::Mpxy => "mpxy_mmode_addr_rejected",
            Self::PmuSnapshot => "pmu_snapshot_mmode_addr_rejected",
        }
    }
}

const SHMEM_POOL_PAGES: usize = 4;

#[repr(C, align(4096))]
struct AlignedPool([u8; SHMEM_POOL_PAGES * PAGE_SIZE]);

#[unsafe(link_section = ".bss.uninit")]
static SHMEM_POOL: SyncUnsafeCell<AlignedPool> =
    SyncUnsafeCell::new(AlignedPool([0; SHMEM_POOL_PAGES * PAGE_SIZE]));

/// Single-instance token granting controlled access to [`SHMEM_POOL`].
///
/// # Invariants
///
/// - At most one owner is recorded in `registered`.
/// - `dbtr_installed` is `Some` only while a DBTR hardware trigger still points at the pool.
/// - `poisoned` is sticky until platform reset; poisoned pools are never re-registered or zeroed.
pub(in crate::platform) struct ShmemPool {
    registered: Option<ShmemOwner>,
    dbtr_installed: Option<(usize, usize)>,
    poisoned: bool,
}

impl ShmemPool {
    /// Creates the process-wide pool state without touching the shared-memory region.
    ///
    /// # Safety
    ///
    /// Must be constructed exactly once during BSP [`crate::platform::Platform::boot`].
    pub(in crate::platform) unsafe fn take_once() -> Self {
        // INVARIANT: Single BSP construction establishes the one-owner token described above.
        Self {
            registered: None,
            dbtr_installed: None,
            poisoned: false,
        }
    }

    /// Returns the physical identity address passed to SBI shared-memory calls.
    pub(crate) fn base(&self) -> usize {
        // CAST: SBI consumes a physical address; the pointer value is identity-mapped S-mode RAM.
        self.base_ptr() as usize
    }

    /// Returns a provenance-preserving pointer for local pool accesses.
    pub(crate) fn base_ptr(&self) -> *mut u8 {
        SHMEM_POOL.get().cast::<u8>()
    }

    pub(crate) const fn len(&self) -> usize {
        SHMEM_POOL_PAGES * PAGE_SIZE
    }

    pub(crate) const fn is_available(&self) -> bool {
        !self.poisoned && self.registered.is_none() && self.dbtr_installed.is_none()
    }

    pub(crate) const fn is_registered(&self) -> bool {
        self.registered.is_some()
    }

    pub(crate) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) const fn has_leaked_dbtr_trigger(&self) -> bool {
        self.dbtr_installed.is_some()
    }

    pub(crate) const fn dbtr_trigger(&self) -> Option<(usize, usize)> {
        self.dbtr_installed
    }

    pub(crate) fn set_dbtr_trigger(&mut self, base: usize, mask: usize) {
        self.dbtr_installed = Some((base, mask));
    }

    pub(crate) fn clear_dbtr_trigger(&mut self) {
        self.dbtr_installed = None;
    }

    pub(crate) fn mark_poisoned(&mut self) {
        self.poisoned = true;
    }

    pub(crate) fn ensure_idle(&self) -> Result<(), FailReason> {
        if self.is_available() {
            Ok(())
        } else {
            Err(FailReason::HardwareInconsistent)
        }
    }

    pub(crate) fn zero_all(&mut self) {
        self.zero_prefix(self.len());
    }

    pub(crate) fn zero_prefix(&mut self, bytes: usize) {
        let len = bytes.min(self.len());
        let ptr = self.base_ptr();
        // SAFETY: `ptr` starts a 4 KiB-aligned static array of `len()` bytes; `len <= len()`;
        // `&mut self` excludes concurrent pool users. Callers must ensure firmware no longer
        // references the region (guarded by `registered` and `dbtr_installed` state).
        unsafe { ptr::write_bytes(ptr, 0, len) };
    }

    pub(crate) fn set_registered(&mut self, owner: ShmemOwner) {
        self.registered = Some(owner);
    }

    pub(crate) fn clear_registered(&mut self) {
        self.registered = None;
    }

    pub(crate) fn clear_registered_and_zero(&mut self) {
        self.registered = None;
        self.zero_all();
    }

    /// Unregisters `owner`, then zeroes the pool only after firmware ownership is released.
    pub(crate) fn unregister_and_release(&mut self, owner: ShmemOwner) -> Result<(), FailReason> {
        if self.dbtr_installed.is_some() {
            // INVARIANT: A live DBTR trigger still references the pool; clearing it would be unsafe.
            self.poisoned = true;
            return Err(FailReason::HardwareInconsistent);
        }
        let ret = owner.set_raw(usize::MAX, usize::MAX, 0);
        if ret.error == 0 || sbi::error_code(ret) == SbiError::NoShmem.as_code() {
            self.registered = None;
            self.zero_all();
            Ok(())
        } else {
            // Keep `registered = Some(owner)` and poison the pool without zeroing.
            self.poisoned = true;
            Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)))
        }
    }

    pub(crate) fn write_first_usize(&mut self, value: usize) {
        let addr = self.base_ptr().cast::<usize>();
        // SAFETY: Pool is 4 KiB-aligned and >= `size_of::<usize>()` bytes; `&mut self` is exclusive.
        unsafe { ptr::write_volatile(addr, value) };
    }

    pub(crate) fn read_first_usize(&self) -> usize {
        self.read_usize_at(0)
    }

    pub(crate) fn read_usize_at(&self, word_index: usize) -> usize {
        let max_words = self.len() / size_of::<usize>();
        assert!(word_index < max_words, "shmem usize read out of bounds");
        let offset = word_index
            .checked_mul(size_of::<usize>())
            .expect("usize offset checked");
        let addr = self.base_ptr();
        // SAFETY: `word_index < len / size_of::<usize>()` bounds `offset + size_of::<usize>()`;
        // `base_ptr` keeps the static allocation provenance.
        unsafe { addr.add(offset).cast::<usize>().read_volatile() }
    }

    pub(crate) fn write_trigger_data_at(&mut self, entry_index: usize, data: TriggerData) {
        let max_entries = self.len() / size_of::<TriggerData>();
        assert!(
            entry_index < max_entries,
            "dbtr trigger write out of bounds"
        );
        let offset = entry_index
            .checked_mul(size_of::<TriggerData>())
            .expect("trigger offset checked");
        let addr = self.base_ptr();
        // SAFETY: `entry_index < max_entries`; the pool is 4 KiB-aligned and `&mut self` is exclusive.
        unsafe { addr.add(offset).cast::<TriggerData>().write_volatile(data) };
    }

    pub(crate) fn read_trigger_data_at(&self, entry_index: usize) -> TriggerData {
        let max_entries = self.len() / size_of::<TriggerData>();
        assert!(entry_index < max_entries, "dbtr trigger read out of bounds");
        let offset = entry_index
            .checked_mul(size_of::<TriggerData>())
            .expect("trigger offset checked");
        let addr = self.base_ptr();
        // SAFETY: `entry_index < max_entries`; the pool is 4 KiB-aligned and exclusively owned.
        unsafe { addr.add(offset).cast::<TriggerData>().read_volatile() }
    }

    pub(crate) fn read_u32_at(&self, word_index: usize) -> u32 {
        let max_words = self.len() / size_of::<u32>();
        assert!(word_index < max_words, "shmem u32 read out of bounds");
        let offset = word_index
            .checked_mul(size_of::<u32>())
            .expect("word offset checked");
        let addr = self.base_ptr();
        // SAFETY: `word_index < len / 4` bounds `offset + 4` inside the 4 KiB-aligned static pool.
        unsafe { addr.add(offset).cast::<u32>().read_volatile() }
    }
}
