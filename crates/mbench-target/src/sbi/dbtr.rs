//! SBI Debug Triggers extension.

use mbench_core::record::SbiExtensionId;

use super::{SbiRet, raw_ecall};

pub(crate) const EID: usize = SbiExtensionId::Dbtr.eid();
const FID_NUM_TRIGGERS: usize = 0;
const FID_SET_SHMEM: usize = 1;
const FID_READ_TRIGGERS: usize = 2;
const FID_INSTALL_TRIGGERS: usize = 3;
const FID_UPDATE_TRIGGERS: usize = 4;
const FID_UNINSTALL_TRIGGERS: usize = 5;
const FID_ENABLE_TRIGGERS: usize = 6;
const FID_DISABLE_TRIGGERS: usize = 7;

const TDATA1_TYPE_SHIFT: usize = 60;
const TDATA1_LOAD_BIT: usize = 1 << 0;
const TDATA1_EXEC_BIT: usize = 1 << 2;
const TDATA1_S_BIT: usize = 1 << 4;

/// SBI DBTR software trigger state (`trig_state`) bit flags.
pub(crate) mod tstate {
    pub(crate) const MAPPED: usize = 1 << 0;
    pub(crate) const S: usize = 1 << 2;
}

/// RISC-V Sdtrig address/data match trigger type encodings.
#[repr(usize)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TriggerKind {
    Mcontrol = 2,
    Mcontrol6 = 6,
}

/// Match access class for S-mode hardware breakpoint triggers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TriggerAccess {
    Load,
    Exec,
}

/// Builds an S-mode-only (`S=1, U=0, M=0, DMODE=0`) Sdtrig match `tdata1` word (`action=0`).
pub(crate) const fn build_smode_match_tdata1(kind: TriggerKind, access: TriggerAccess) -> usize {
    let access_bit = match access {
        TriggerAccess::Load => TDATA1_LOAD_BIT,
        TriggerAccess::Exec => TDATA1_EXEC_BIT,
    };
    ((kind as usize) << TDATA1_TYPE_SHIFT) | TDATA1_S_BIT | access_bit
}

/// Trigger configuration entry layout in DBTR shared memory (`struct sbi_dbtr_data_msg`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TriggerData {
    pub(crate) tstate: usize,
    pub(crate) tdata1: usize,
    pub(crate) tdata2: usize,
    pub(crate) tdata3: usize,
}

const _: () = assert!(size_of::<TriggerData>() == 32);

#[inline(always)]
pub(crate) fn num_triggers(trig_tdata1: usize) -> SbiRet {
    // SAFETY: Read-only DBTR count query with integer parameter.
    unsafe { raw_ecall(EID, FID_NUM_TRIGGERS, [trig_tdata1, 0, 0, 0, 0, 0]) }
}

/// Configures or clears the DBTR shared memory region.
///
/// # Safety
///
/// `(phys_lo, phys_hi)` must obey the SBI shared-memory validity and registration lifetime contract.
#[inline(always)]
pub(crate) unsafe fn set_shmem(phys_lo: usize, phys_hi: usize, flags: usize) -> SbiRet {
    // SAFETY: Caller guarantees valid DBTR shmem lifetime or intentional rejection probe.
    unsafe { raw_ecall(EID, FID_SET_SHMEM, [phys_lo, phys_hi, flags, 0, 0, 0]) }
}

/// Reads trigger descriptors into the currently registered DBTR shmem.
///
/// # Safety
///
/// Caller must hold valid exclusive DBTR shared memory registered for this hart.
#[inline(always)]
pub(crate) unsafe fn read_triggers(trig_idx_base: usize, trig_count: usize) -> SbiRet {
    // SAFETY: Caller holds active DBTR shared-memory registration.
    unsafe {
        raw_ecall(
            EID,
            FID_READ_TRIGGERS,
            [trig_idx_base, trig_count, 0, 0, 0, 0],
        )
    }
}

/// Installs hardware debug triggers from registered DBTR shmem.
///
/// # Safety
///
/// Caller must hold valid exclusive DBTR shared memory populated with `TriggerData` entries
/// whose match addresses will not corrupt S-mode execution.
#[inline(always)]
pub(crate) unsafe fn install_triggers(trig_count: usize) -> SbiRet {
    // SAFETY: Caller holds active DBTR shared memory and safe trigger configuration.
    unsafe { raw_ecall(EID, FID_INSTALL_TRIGGERS, [trig_count, 0, 0, 0, 0, 0]) }
}

/// Updates already-installed hardware debug triggers from registered DBTR shmem.
///
/// # Safety
///
/// Caller must hold valid exclusive DBTR shared memory populated with `[trig_idx, tdata1, tdata2, tdata3]`
/// entries whose match addresses will not corrupt S-mode execution.
#[inline(always)]
pub(crate) unsafe fn update_triggers(trig_count: usize) -> SbiRet {
    // SAFETY: Caller holds active DBTR shared memory and safe trigger configuration.
    unsafe { raw_ecall(EID, FID_UPDATE_TRIGGERS, [trig_count, 0, 0, 0, 0, 0]) }
}

#[inline(always)]
pub(crate) fn uninstall_triggers(trig_idx_base: usize, trig_idx_mask: usize) -> SbiRet {
    // SAFETY: Releases hardware debug triggers indexed by integer bitmask.
    unsafe {
        raw_ecall(
            EID,
            FID_UNINSTALL_TRIGGERS,
            [trig_idx_base, trig_idx_mask, 0, 0, 0, 0],
        )
    }
}

#[inline(always)]
pub(crate) fn enable_triggers(trig_idx_base: usize, trig_idx_mask: usize) -> SbiRet {
    // SAFETY: Enables previously installed DBTR triggers via integer bitmask.
    unsafe {
        raw_ecall(
            EID,
            FID_ENABLE_TRIGGERS,
            [trig_idx_base, trig_idx_mask, 0, 0, 0, 0],
        )
    }
}

#[inline(always)]
pub(crate) fn disable_triggers(trig_idx_base: usize, trig_idx_mask: usize) -> SbiRet {
    // SAFETY: Disables DBTR triggers via integer bitmask.
    unsafe {
        raw_ecall(
            EID,
            FID_DISABLE_TRIGGERS,
            [trig_idx_base, trig_idx_mask, 0, 0, 0, 0],
        )
    }
}
