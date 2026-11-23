//! Exclusively owned 4 KiB-aligned shared-memory pool, RAII leases, DBTR session, and security probes.

use core::arch::{asm, global_asm};

use mbench_core::{
    check::CheckCtx,
    engine::{Clock, CounterSnap},
    record::{CounterAvailability, FailReason, HartTopology},
};

use crate::{
    platform::{Platform, boot::SyncUnsafeCell, trap},
    sbi::{
        self, SbiError, SbiRet, dbtr::TriggerData, mpxy::MpxyChannelIdsHeader, pmu::EventInfoEntry,
    },
};

const SHMEM_POOL_PAGES: usize = 4;
const PAGE_SIZE: usize = 4096;

#[repr(C, align(4096))]
struct AlignedPool([u8; SHMEM_POOL_PAGES * PAGE_SIZE]);

#[unsafe(link_section = ".bss.uninit")]
static SHMEM_POOL: SyncUnsafeCell<AlignedPool> =
    SyncUnsafeCell::new(AlignedPool([0; SHMEM_POOL_PAGES * PAGE_SIZE]));

static DBTR_SCRATCH: SyncUnsafeCell<u64> = SyncUnsafeCell::new(0x55AA_55AA_55AA_55AA);

global_asm!(
    r#"
.text

.balign 4
.global mbench_dbtr_exec_target
.type mbench_dbtr_exec_target, @function
mbench_dbtr_exec_target:
    .option push
    .option norvc
    nop
    ret
    .option pop
.size mbench_dbtr_exec_target, . - mbench_dbtr_exec_target
"#
);

unsafe extern "C" {
    fn mbench_dbtr_exec_target();
}

/// Returns the identity physical/virtual address of `DBTR_SCRATCH` for safe match triggers.
pub(crate) fn dbtr_scratch_addr() -> usize {
    DBTR_SCRATCH.get() as usize
}

/// Returns the entry address of the isolated 4-byte `nop; ret` target for execute triggers.
pub(crate) fn dbtr_exec_target_addr() -> usize {
    mbench_dbtr_exec_target as *const () as usize
}

/// Executes a 4-byte load (`ld`) from `DBTR_SCRATCH` inside `try_catch_raw` to probe breakpoint traps.
pub(crate) fn probe_dbtr_load_scratch() -> Result<u64, trap::TrapInfo> {
    unsafe extern "C" fn do_load(ctx: *mut u8) {
        let out_ptr = ctx.cast::<u64>();
        let addr = DBTR_SCRATCH.get();
        let val: u64;
        // SAFETY: Leaf probe reading static `DBTR_SCRATCH` inside `try_catch_raw`.
        unsafe {
            asm!(
                ".option push",
                ".option norvc",
                "ld {out}, 0({addr})",
                ".option pop",
                out = out(reg) val,
                addr = in(reg) addr,
                options(nostack),
            );
            out_ptr.write(val);
        }
    }
    let mut val = 0u64;
    // SAFETY: `do_load` has zero `Drop` locals and writes only to caller stack `u64`.
    unsafe { trap::try_catch_raw((&raw mut val).cast::<u8>(), do_load)? };
    Ok(val)
}

/// Calls isolated `mbench_dbtr_exec_target` inside `try_catch_raw` to probe execute breakpoint traps.
pub(crate) fn probe_dbtr_exec_target() -> Result<(), trap::TrapInfo> {
    unsafe extern "C" fn do_call(_ctx: *mut u8) {
        // SAFETY: `mbench_dbtr_exec_target` is an isolated pure `nop; ret` stub with zero `Drop` locals.
        unsafe { mbench_dbtr_exec_target() };
    }
    // SAFETY: `do_call` has zero `Drop` locals.
    unsafe { trap::try_catch_raw(core::ptr::null_mut(), do_call) }
}

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
    fn set_raw(self, phys_lo: usize, phys_hi: usize, flags: usize) -> SbiRet {
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

    const fn invalid_flags(self) -> usize {
        match self {
            // MPXY flags[1:0] = 0b01 is valid OVERWRITE-RETURN; use reserved encoding 0b10.
            Self::Mpxy => sbi::mpxy::FLAG_INVALID_RESERVED,
            Self::Sta | Self::Nacl | Self::Dbtr | Self::PmuSnapshot => 1,
        }
    }

    const fn flags_label(self) -> &'static str {
        match self {
            Self::Sta => "sta_nonzero_flags_rejected",
            Self::Nacl => "nacl_nonzero_flags_rejected",
            Self::Dbtr => "dbtr_nonzero_flags_rejected",
            Self::Mpxy => "mpxy_reserved_flags_rejected",
            Self::PmuSnapshot => "pmu_snapshot_nonzero_flags_rejected",
        }
    }

    const fn unaligned_label(self) -> &'static str {
        match self {
            Self::Sta => "sta_unaligned_addr_rejected",
            Self::Nacl => "nacl_unaligned_addr_rejected",
            Self::Dbtr => "dbtr_unaligned_addr_rejected",
            Self::Mpxy => "mpxy_unaligned_addr_rejected",
            Self::PmuSnapshot => "pmu_snapshot_unaligned_addr_rejected",
        }
    }

    const fn phys_hi_label(self) -> &'static str {
        match self {
            Self::Sta => "sta_invalid_phys_hi_rejected",
            Self::Nacl => "nacl_invalid_phys_hi_rejected",
            Self::Dbtr => "dbtr_invalid_phys_hi_rejected",
            Self::Mpxy => "mpxy_invalid_phys_hi_rejected",
            Self::PmuSnapshot => "pmu_snapshot_invalid_phys_hi_rejected",
        }
    }

    const fn mmode_label(self) -> &'static str {
        match self {
            Self::Sta => "sta_mmode_addr_rejected",
            Self::Nacl => "nacl_mmode_addr_rejected",
            Self::Dbtr => "dbtr_mmode_addr_rejected",
            Self::Mpxy => "mpxy_mmode_addr_rejected",
            Self::PmuSnapshot => "pmu_snapshot_mmode_addr_rejected",
        }
    }
}

/// Single-instance token granting controlled access to [`SHMEM_POOL`].
pub(in crate::platform) struct ShmemPool {
    registered: Option<ShmemOwner>,
    dbtr_installed: Option<(usize, usize)>,
    poisoned: bool,
}

impl ShmemPool {
    /// # Safety
    ///
    /// Must be constructed exactly once during BSP [`Platform::boot`].
    pub(in crate::platform) unsafe fn take_once() -> Self {
        Self {
            registered: None,
            dbtr_installed: None,
            poisoned: false,
        }
    }

    pub(in crate::platform) fn base(&self) -> usize {
        SHMEM_POOL.get().cast::<u8>() as usize
    }

    pub(crate) const fn len(&self) -> usize {
        SHMEM_POOL_PAGES * PAGE_SIZE
    }

    pub(in crate::platform) const fn is_available(&self) -> bool {
        !self.poisoned && self.registered.is_none() && self.dbtr_installed.is_none()
    }

    pub(in crate::platform) const fn is_registered(&self) -> bool {
        self.registered.is_some()
    }

    pub(in crate::platform) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(in crate::platform) const fn has_leaked_dbtr_trigger(&self) -> bool {
        self.dbtr_installed.is_some()
    }

    pub(in crate::platform) fn ensure_idle(&self) -> Result<(), FailReason> {
        if self.is_available() {
            Ok(())
        } else {
            Err(FailReason::HardwareInconsistent)
        }
    }

    pub(in crate::platform) fn zero_all(&mut self) {
        self.zero_prefix(self.len());
    }

    pub(in crate::platform) fn zero_prefix(&mut self, bytes: usize) {
        let len = bytes.min(self.len());
        let ptr = self.base() as *mut u8;
        // SAFETY: Unique ownership of `ShmemPool` guarantees no active registered writer races here.
        unsafe { core::ptr::write_bytes(ptr, 0, len) };
    }

    fn set_registered(&mut self, owner: ShmemOwner) {
        self.registered = Some(owner);
    }

    fn clear_registered_and_zero(&mut self) {
        self.registered = None;
        self.zero_all();
    }

    fn unregister_and_release(&mut self, owner: ShmemOwner) -> Result<(), FailReason> {
        let ret = owner.set_raw(usize::MAX, usize::MAX, 0);
        if ret.error == 0 || sbi::error_code(ret) == SbiError::NoShmem.as_code() {
            self.registered = None;
            self.zero_all();
            Ok(())
        } else {
            // Keep `registered = Some(owner)` and poison pool without zeroing so firmware cannot race future uses.
            self.poisoned = true;
            Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)))
        }
    }

    pub(in crate::platform) fn write_first_usize(&mut self, value: usize) {
        let addr = self.base() as *mut usize;
        // SAFETY: Pool is 4 KiB-aligned and >= `size_of::<usize>()` bytes; owned exclusively.
        unsafe { core::ptr::write_volatile(addr, value) };
    }

    pub(in crate::platform) fn read_first_usize(&self) -> usize {
        self.read_usize_at(0)
    }

    pub(in crate::platform) fn read_usize_at(&self, word_index: usize) -> usize {
        let max_words = self.len() / size_of::<usize>();
        assert!(word_index < max_words, "shmem usize read out of bounds");
        let offset = word_index
            .checked_mul(size_of::<usize>())
            .expect("usize offset checked");
        // SAFETY: `word_index < len / size_of::<usize>()` implies `offset + size_of::<usize>() <= len`.
        unsafe { core::ptr::read_volatile((self.base() + offset) as *const usize) }
    }

    pub(in crate::platform) fn write_trigger_data_at(
        &mut self,
        entry_index: usize,
        data: TriggerData,
    ) {
        let max_entries = self.len() / size_of::<TriggerData>();
        assert!(
            entry_index < max_entries,
            "dbtr trigger write out of bounds"
        );
        let offset = entry_index
            .checked_mul(size_of::<TriggerData>())
            .expect("trigger offset checked");
        let addr = (self.base() + offset) as *mut TriggerData;
        // SAFETY: Pool is 4 KiB-aligned and `entry_index < max_entries`; owned exclusively.
        unsafe { core::ptr::write_volatile(addr, data) };
    }

    pub(in crate::platform) fn read_trigger_data_at(&self, entry_index: usize) -> TriggerData {
        let max_entries = self.len() / size_of::<TriggerData>();
        assert!(entry_index < max_entries, "dbtr trigger read out of bounds");
        let offset = entry_index
            .checked_mul(size_of::<TriggerData>())
            .expect("trigger offset checked");
        let addr = (self.base() + offset) as *const TriggerData;
        // SAFETY: Pool is 4 KiB-aligned and `entry_index < max_entries`.
        unsafe { core::ptr::read_volatile(addr) }
    }

    pub(crate) fn read_u32_at(&self, word_index: usize) -> u32 {
        let max_words = self.len() / size_of::<u32>();
        assert!(word_index < max_words, "shmem u32 read out of bounds");
        let offset = word_index
            .checked_mul(size_of::<u32>())
            .expect("word offset checked");
        // SAFETY: `word_index < len / 4` implies `offset + 4 <= len` inside 4 KiB-aligned `SHMEM_POOL`.
        unsafe { core::ptr::read_volatile((self.base() + offset) as *const u32) }
    }
}

/// Result of attempting to acquire an exclusive [`ShmemLease`].
pub(crate) enum ShmemAcquire<'a> {
    Leased(ShmemLease<'a>),
    Unsupported,
    TooLarge,
}

/// Result of attempting to acquire an exclusive [`DbtrSession`].
pub(crate) enum DbtrAcquire<'a> {
    Active(DbtrSession<'a>),
    TooLarge,
}

/// Exclusive BSP lease registering `SHMEM_POOL` with one SBI shared-memory extension.
///
/// Unregisters firmware shared memory BEFORE zeroing and releasing the pool on `finish`/`Drop`.
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
        debug_assert_ne!(owner, ShmemOwner::Dbtr);
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
    pub(crate) fn reregister(&self) -> SbiRet {
        self.owner.set_raw(self.platform.shmem.base(), 0, 0)
    }

    /// Invokes `sbi_mpxy_get_channel_ids` while owning `ShmemOwner::Mpxy`.
    pub(crate) fn mpxy_get_channel_ids(&self, start_index: usize) -> SbiRet {
        debug_assert_eq!(self.owner, ShmemOwner::Mpxy);
        // SAFETY: `self` guarantees exclusive registered MPXY shmem ownership.
        unsafe { sbi::mpxy::get_channel_ids(start_index) }
    }

    /// Invokes `sbi_mpxy_read_attrs` while owning `ShmemOwner::Mpxy`.
    pub(crate) fn mpxy_read_attrs(
        &self,
        channel_id: usize,
        base_attr_id: usize,
        attr_count: usize,
    ) -> SbiRet {
        debug_assert_eq!(self.owner, ShmemOwner::Mpxy);
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

impl Clock for ShmemLease<'_> {
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

impl HartTopology for ShmemLease<'_> {
    fn total_harts(&self) -> usize {
        self.platform.total_harts()
    }
}

/// Exclusive BSP session owning DBTR shared memory and any installed debug trigger.
pub(crate) struct DbtrSession<'a> {
    platform: &'a mut Platform,
    max_entries: usize,
    shmem_registered: bool,
    active: bool,
    installed: Option<(usize, usize)>,
}

impl<'a> DbtrSession<'a> {
    pub(in crate::platform) fn start(
        platform: &'a mut Platform,
    ) -> Result<DbtrAcquire<'a>, FailReason> {
        platform.shmem.ensure_idle()?;
        let num_ret = sbi::dbtr::num_triggers(0);
        if num_ret.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(num_ret)));
        }
        let trig_max = num_ret.value;
        let max_entries = platform.shmem.len() / size_of::<TriggerData>();
        if trig_max > max_entries {
            return Ok(DbtrAcquire::TooLarge);
        }

        platform.shmem.zero_all();
        platform.shmem.set_registered(ShmemOwner::Dbtr);
        let ret = ShmemOwner::Dbtr.set_raw(platform.shmem.base(), 0, 0);
        if ret.error != 0 {
            if sbi::error_code(ret) == SbiError::NotSupported.as_code() {
                platform.shmem.clear_registered_and_zero();
            } else {
                let _ = platform.shmem.unregister_and_release(ShmemOwner::Dbtr);
            }
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }
        Ok(DbtrAcquire::Active(Self {
            platform,
            max_entries,
            shmem_registered: true,
            active: true,
            installed: None,
        }))
    }

    /// Disables DBTR shared memory registration without poisoning an active session.
    pub(crate) fn disable_shmem(&mut self) -> SbiRet {
        let ret = ShmemOwner::Dbtr.set_raw(usize::MAX, usize::MAX, 0);
        if ret.error == 0 || sbi::error_code(ret) == SbiError::NoShmem.as_code() {
            self.shmem_registered = false;
            self.platform.shmem.clear_registered_and_zero();
        } else {
            self.platform.shmem.poisoned = true;
        }
        ret
    }

    /// Re-enables `SHMEM_POOL` as DBTR shared memory from a disabled state (no bulk zeroing in timed window).
    pub(crate) fn enable_shmem(&mut self) -> SbiRet {
        self.platform.shmem.set_registered(ShmemOwner::Dbtr);
        let ret = ShmemOwner::Dbtr.set_raw(self.platform.shmem.base(), 0, 0);
        if ret.error == 0 {
            self.shmem_registered = true;
        } else {
            self.shmem_registered = false;
            self.platform.shmem.registered = None;
        }
        ret
    }

    pub(crate) fn reregister_shmem(&self) -> SbiRet {
        ShmemOwner::Dbtr.set_raw(self.platform.shmem.base(), 0, 0)
    }

    pub(crate) fn read_triggers(&self, base: usize, count: usize) -> SbiRet {
        if count > self.max_entries {
            return SbiRet::invalid_param();
        }
        // SAFETY: Caller uses registered DBTR shmem bounded to `self.max_entries` or probes `NO_SHMEM`.
        unsafe { sbi::dbtr::read_triggers(base, count) }
    }

    pub(crate) fn read_trigger_data_at(&self, entry_index: usize) -> TriggerData {
        self.platform.shmem.read_trigger_data_at(entry_index)
    }

    /// Installs one hardware trigger (`data`) into slot 0 of DBTR shmem and tracks its index for teardown.
    pub(crate) fn install_single(&mut self, data: TriggerData) -> Result<usize, FailReason> {
        if self.installed.is_some() || self.platform.shmem.dbtr_installed.is_some() {
            return Err(FailReason::HardwareInconsistent);
        }
        self.platform.shmem.write_trigger_data_at(0, data);
        // SAFETY: `TriggerData` initialized in owned shmem; caller passes isolated `DBTR_SCRATCH` or `mbench_dbtr_exec_target`.
        let inst = unsafe { sbi::dbtr::install_triggers(1) };
        if inst.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(inst)));
        }
        let idx = self.platform.shmem.read_first_usize();
        self.installed = Some((idx, 1usize));
        self.platform.shmem.dbtr_installed = Some((idx, 1usize));
        Ok(idx)
    }

    /// Updates one installed trigger `idx` in place using `sbi_debug_update_triggers(1)`.
    pub(crate) fn update_single(&mut self, idx: usize, data: TriggerData) -> SbiRet {
        let msg = TriggerData {
            tstate: idx,
            tdata1: data.tdata1,
            tdata2: data.tdata2,
            tdata3: data.tdata3,
        };
        self.platform.shmem.write_trigger_data_at(0, msg);
        // SAFETY: `TriggerData` initialized in owned DBTR shmem; `tdata2` targets isolated scratch/stub.
        unsafe { sbi::dbtr::update_triggers(1) }
    }

    /// Calls `sbi_debug_update_triggers(count)` for bounded `count <= max_entries` range checks.
    pub(crate) fn update_raw(&mut self, count: usize, data: TriggerData) -> SbiRet {
        if count > self.max_entries {
            return SbiRet::invalid_param();
        }
        for i in 0..count {
            self.platform.shmem.write_trigger_data_at(i, data);
        }
        // SAFETY: `0..count` initialized in owned DBTR shmem.
        unsafe { sbi::dbtr::update_triggers(count) }
    }

    pub(crate) fn enable_installed(&self, idx: usize) -> SbiRet {
        sbi::dbtr::enable_triggers(idx, 1)
    }

    pub(crate) fn disable_installed(&self, idx: usize) -> SbiRet {
        sbi::dbtr::disable_triggers(idx, 1)
    }

    pub(crate) fn uninstall_installed(&mut self, idx: usize) -> SbiRet {
        let ret = sbi::dbtr::uninstall_triggers(idx, 1);
        if ret.error == 0 {
            self.installed = None;
            self.platform.shmem.dbtr_installed = None;
        }
        ret
    }

    /// Disables and uninstalls any active trigger, unregisters shmem, and zeroes the pool.
    pub(crate) fn finish(mut self) -> Result<(), FailReason> {
        let res = self.teardown_inner();
        self.active = false;
        res
    }

    fn teardown_inner(&mut self) -> Result<(), FailReason> {
        let mut first_err: Option<FailReason> = None;
        if let Some((base, mask)) = self.installed {
            let _ = sbi::dbtr::disable_triggers(base, mask);
            let uninst = sbi::dbtr::uninstall_triggers(base, mask);
            if uninst.error == 0 {
                self.installed = None;
                self.platform.shmem.dbtr_installed = None;
            } else {
                // Keep trigger ownership set and poison the pool until system teardown/reset.
                self.platform.shmem.poisoned = true;
                first_err = Some(FailReason::UnexpectedSbiError(sbi::error_code(uninst)));
            }
        }
        let unreg = self.platform.shmem.unregister_and_release(ShmemOwner::Dbtr);
        self.shmem_registered = false;
        if first_err.is_none()
            && let Err(err) = unreg
        {
            first_err = Some(err);
        }
        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

impl Drop for DbtrSession<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.teardown_inner();
            self.active = false;
        }
    }
}

impl Clock for DbtrSession<'_> {
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

impl HartTopology for DbtrSession<'_> {
    fn total_harts(&self) -> usize {
        self.platform.total_harts()
    }
}

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
    let addr = platform.shmem.base() + byte_offset;
    for (i, &entry) in entries.iter().enumerate() {
        let raw_bytes = entry.to_le_bytes();
        let dst_base = (addr + i * size_of::<EventInfoEntry>()) as *mut u8;
        for (b_idx, &byte) in raw_bytes.iter().enumerate() {
            // SAFETY: `total <= shmem.len()`; byte-wise volatile stores require 1-byte alignment
            // even when testing unaligned `byte_offset`.
            unsafe { core::ptr::write_volatile(dst_base.add(b_idx), byte) };
        }
    }
    // SAFETY: `addr` holds initialized `EventInfoEntry` bytes in writable S-mode RAM and PMU does not retain it.
    let ret = unsafe { sbi::pmu::event_get_info_raw(addr, 0, entries.len(), flags) };
    for (i, dst) in entries.iter_mut().enumerate() {
        let src_base = (addr + i * size_of::<EventInfoEntry>()) as *const u8;
        let mut raw_bytes = [0u8; size_of::<EventInfoEntry>()];
        for (b_idx, slot) in raw_bytes.iter_mut().enumerate() {
            // SAFETY: Same valid slice bounds, 1-byte aligned volatile reads.
            *slot = unsafe { core::ptr::read_volatile(src_base.add(b_idx)) };
        }
        *dst = EventInfoEntry::from_le_bytes(raw_bytes);
    }
    platform.shmem.zero_prefix(total);
    Ok(ret)
}

/// Runs non-short-circuiting shared-memory boundary & security checks for `target`.
///
/// Returns `Ok(true)` if skipped because firmware requires more shared memory than `SHMEM_POOL` provides.
pub(in crate::platform) fn probe_security(
    platform: &mut Platform,
    target: ShmemOwner,
    mmode_addr: Option<usize>,
    ctx: &mut CheckCtx,
) -> Result<bool, FailReason> {
    platform.shmem.ensure_idle()?;
    if target == ShmemOwner::Mpxy {
        let size_ret = sbi::mpxy::get_shmem_size();
        if !ctx.expect_sbi_err(sbi::error_code(size_ret), 0, "mpxy_get_shmem_size") {
            return Ok(false);
        }
        let needed = size_ret.value;
        if !ctx.expect(
            needed >= PAGE_SIZE && needed.is_multiple_of(PAGE_SIZE),
            "mpxy_valid_shmem_size",
        ) {
            return Ok(false);
        }
        if needed > platform.shmem.len() {
            return Ok(true);
        }
    }

    let valid_addr = platform.shmem.base();

    if target == ShmemOwner::Mpxy {
        platform.shmem.zero_all();
        let owret = target.set_raw(valid_addr, 0, sbi::mpxy::FLAG_OVERWRITE_RETURN);
        if owret.error == 0 {
            platform.shmem.set_registered(target);
            platform.shmem.unregister_and_release(target)?;
        }
        ctx.expect_sbi_err(sbi::error_code(owret), 0, "mpxy_overwrite_return_accepted");
    }

    let bad_flags = target.set_raw(valid_addr, 0, target.invalid_flags());
    if bad_flags.error == 0 {
        platform.shmem.set_registered(target);
        platform.shmem.unregister_and_release(target)?;
    }
    if target == ShmemOwner::Dbtr {
        ctx.expect_sbi_err_quirk(
            sbi::error_code(bad_flags),
            SbiError::InvalidParam.as_code(),
            0,
            "opensbi-v1.8.1:dbtr-ignores-shmem-flags",
            target.flags_label(),
        );
    } else {
        ctx.expect_sbi_err(
            sbi::error_code(bad_flags),
            SbiError::InvalidParam.as_code(),
            target.flags_label(),
        );
    }

    let unaligned = target.set_raw(valid_addr + 1, 0, 0);
    if unaligned.error == 0 {
        platform.shmem.set_registered(target);
        platform.shmem.unregister_and_release(target)?;
    }
    ctx.expect_sbi_err(
        sbi::error_code(unaligned),
        SbiError::InvalidParam.as_code(),
        target.unaligned_label(),
    );

    let bad_hi = target.set_raw(valid_addr, usize::MAX, 0);
    if bad_hi.error == 0 {
        platform.shmem.set_registered(target);
        platform.shmem.unregister_and_release(target)?;
    }
    ctx.expect_sbi_err_in(
        sbi::error_code(bad_hi),
        &[
            SbiError::InvalidAddress.as_code(),
            SbiError::InvalidParam.as_code(),
            SbiError::Failed.as_code(),
        ],
        target.phys_hi_label(),
    );

    if let Some(maddr) = mmode_addr {
        let mmode_ret = target.set_raw(maddr, 0, 0);
        if mmode_ret.error == 0 {
            platform.shmem.set_registered(target);
            platform.shmem.unregister_and_release(target)?;
            ctx.record_fail(
                target.mmode_label(),
                FailReason::SecurityViolation(target.mmode_label()),
            );
        } else {
            ctx.expect_sbi_err_in(
                sbi::error_code(mmode_ret),
                &[
                    SbiError::InvalidAddress.as_code(),
                    SbiError::Denied.as_code(),
                    SbiError::InvalidParam.as_code(),
                    SbiError::Failed.as_code(),
                ],
                target.mmode_label(),
            );
        }
    }

    platform.shmem.unregister_and_release(target)?;
    Ok(false)
}
