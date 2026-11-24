//! DBTR session lifecycle and debug-trigger operations over shared memory.

use core::arch::{asm, global_asm};

use mbench_core::record::FailReason;

use crate::{
    platform::{Platform, boot::SyncUnsafeCell, impl_platform_clock_topology, trap},
    sbi::{
        self, SbiError, SbiRet,
        dbtr::{TriggerAccess, TriggerData, TriggerKind, build_smode_match_tdata1},
    },
};

/// Result of attempting to acquire an exclusive [`DbtrSession`].
pub(crate) enum DbtrAcquire<'a> {
    Active(DbtrSession<'a>),
    TooLarge,
}

/// Exclusive BSP session owning DBTR shared memory and any installed debug trigger.
///
/// # Invariants
///
/// `active` is true only while this value owns the DBTR registration. The pool's
/// `dbtr_installed` field is the single source of truth for trigger ownership; this type keeps
/// no duplicate trigger state.
#[clippy::has_significant_drop]
#[must_use = "DbtrSession should be finished explicitly to report DBTR teardown errors"]
pub(crate) struct DbtrSession<'a> {
    platform: &'a mut Platform,
    max_entries: usize,
    active: bool,
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
        platform.shmem.set_registered(super::ShmemOwner::Dbtr);
        let ret = super::ShmemOwner::Dbtr.set_raw(platform.shmem.base(), 0, 0);
        if ret.error != 0 {
            if sbi::error_code(ret) == SbiError::NotSupported.as_code() {
                platform.shmem.clear_registered_and_zero();
            } else {
                let _ = platform
                    .shmem
                    .unregister_and_release(super::ShmemOwner::Dbtr);
            }
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }
        Ok(DbtrAcquire::Active(Self {
            platform,
            max_entries,
            active: true,
        }))
    }

    /// Disables DBTR shared-memory registration without poisoning an active session.
    pub(crate) fn disable_shmem(&mut self) -> SbiRet {
        if self.platform.shmem.has_leaked_dbtr_trigger() || self.platform.shmem.is_poisoned() {
            // INVARIANT: A live trigger still references the pool; never clear it here.
            self.platform.shmem.mark_poisoned();
            return SbiRet::invalid_param();
        }
        let ret = super::ShmemOwner::Dbtr.set_raw(usize::MAX, usize::MAX, 0);
        if ret.error == 0 || sbi::error_code(ret) == SbiError::NoShmem.as_code() {
            self.platform.shmem.clear_registered_and_zero();
        } else {
            self.platform.shmem.mark_poisoned();
        }
        ret
    }

    /// Ensures no leaked DBTR trigger or poisoned session invalidates shmem registration.
    pub(crate) fn ensure_shmem_clean(&mut self) -> Result<(), SbiRet> {
        if self.platform.shmem.has_leaked_dbtr_trigger() || self.platform.shmem.is_poisoned() {
            self.platform.shmem.mark_poisoned();
            return Err(SbiRet::invalid_param());
        }
        Ok(())
    }

    /// Re-enables `SHMEM_POOL` as DBTR shared memory without extra pre-checks inside timing windows.
    pub(crate) fn enable_shmem_measured(&mut self) -> SbiRet {
        self.platform.shmem.set_registered(super::ShmemOwner::Dbtr);
        let ret = super::ShmemOwner::Dbtr.set_raw(self.platform.shmem.base(), 0, 0);
        if ret.error != 0 {
            self.platform.shmem.clear_registered();
            self.platform.shmem.mark_poisoned();
        }
        ret
    }

    /// Re-enables `SHMEM_POOL` as DBTR shared memory from a disabled state.
    pub(crate) fn enable_shmem(&mut self) -> SbiRet {
        if let Err(err) = self.ensure_shmem_clean() {
            return err;
        }
        self.enable_shmem_measured()
    }

    pub(crate) fn reregister_shmem(&self) -> SbiRet {
        super::ShmemOwner::Dbtr.set_raw(self.platform.shmem.base(), 0, 0)
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
        if self.platform.shmem.has_leaked_dbtr_trigger() {
            return Err(FailReason::HardwareInconsistent);
        }
        self.platform.shmem.write_trigger_data_at(0, data);
        // SAFETY: `TriggerData` initialized in owned shmem; caller passes isolated `DBTR_SCRATCH` or `mbench_dbtr_exec_target`.
        let inst = unsafe { sbi::dbtr::install_triggers(1) };
        if inst.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(inst)));
        }
        let idx = self.platform.shmem.read_first_usize();
        self.platform.shmem.set_dbtr_trigger(idx, 1);
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
            self.platform.shmem.clear_dbtr_trigger();
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
        if let Some((base, mask)) = self.platform.shmem.dbtr_trigger() {
            let _ = sbi::dbtr::disable_triggers(base, mask);
            let uninst = sbi::dbtr::uninstall_triggers(base, mask);
            if uninst.error == 0 {
                self.platform.shmem.clear_dbtr_trigger();
            } else {
                // INVARIANT: Keep trigger ownership and poison the pool; never clear the backing
                // shared memory while firmware may still reference the installed trigger.
                self.platform.shmem.mark_poisoned();
                first_err = Some(FailReason::UnexpectedSbiError(sbi::error_code(uninst)));
            }
        }
        if !self.platform.shmem.has_leaked_dbtr_trigger() {
            let unreg = self
                .platform
                .shmem
                .unregister_and_release(super::ShmemOwner::Dbtr);
            if first_err.is_none()
                && let Err(err) = unreg
            {
                first_err = Some(err);
            }
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

impl_platform_clock_topology!(DbtrSession<'_>);

/// Selects the first supported S-mode match trigger for `access` and `target_addr`.
pub(crate) fn pick_match_trigger(
    access: TriggerAccess,
    target_addr: usize,
) -> Result<Option<TriggerData>, FailReason> {
    for kind in [TriggerKind::Mcontrol6, TriggerKind::Mcontrol] {
        let tdata1 = build_smode_match_tdata1(kind, access);
        let ret = sbi::dbtr::num_triggers(tdata1);
        if ret.error != 0 {
            return Err(FailReason::UnexpectedSbiError(sbi::error_code(ret)));
        }
        if ret.value > 0 {
            return Ok(Some(TriggerData {
                tstate: 0,
                tdata1,
                tdata2: target_addr,
                tdata3: 0,
            }));
        }
    }
    Ok(None)
}

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
    // CAST: the static lives in identity-mapped S-mode RAM; DBTR consumes the numeric address.
    DBTR_SCRATCH.get() as usize
}

/// Returns the entry address of the isolated 4-byte `nop; ret` target for execute triggers.
pub(crate) fn dbtr_exec_target_addr() -> usize {
    // CAST: RISC-V entry PCs are `usize`; the symbol is a valid executable S-mode address.
    mbench_dbtr_exec_target as *const () as usize
}

/// Executes a 4-byte load (`ld`) from `DBTR_SCRATCH` inside `try_catch_raw` to probe breakpoint traps.
pub(crate) fn probe_dbtr_load_scratch() -> Result<u64, trap::TrapInfo> {
    /// Loads `DBTR_SCRATCH` into caller-supplied `u64` storage during a trap-guarded probe.
    ///
    /// # Safety
    ///
    /// `ctx` must point to a valid aligned `u64` and run inside [`trap::try_catch_raw`].
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
    /// Executes the isolated `mbench_dbtr_exec_target` stub to test execute triggers.
    ///
    /// # Safety
    ///
    /// Must run inside [`trap::try_catch_raw`] with `mbench_dbtr_exec_target` valid for S-mode execution.
    unsafe extern "C" fn do_call(_ctx: *mut u8) {
        // SAFETY: `mbench_dbtr_exec_target` is an isolated pure `nop; ret` stub with zero `Drop` locals.
        unsafe { mbench_dbtr_exec_target() };
    }
    // SAFETY: `do_call` has zero `Drop` locals.
    unsafe { trap::try_catch_raw(core::ptr::null_mut(), do_call) }
}
