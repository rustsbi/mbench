//! SBI Hart State Management extension.

use super::SbiRet;

pub(crate) mod state {
    pub(crate) const STARTED: usize = sbi_spec::hsm::hart_state::STARTED;
    pub(crate) const STOPPED: usize = sbi_spec::hsm::hart_state::STOPPED;
    pub(crate) const SUSPENDED: usize = sbi_spec::hsm::hart_state::SUSPENDED;
}

pub(crate) mod suspend_type {
    pub(crate) const RETENTIVE: u32 = sbi_spec::hsm::suspend_type::RETENTIVE;
    pub(crate) const NON_RETENTIVE: u32 = sbi_spec::hsm::suspend_type::NON_RETENTIVE;
    /// SBI v3.0 reserved retentive suspend type (`0x0000_0001..=0x0FFF_FFFF`).
    pub(crate) const INVALID_RESERVED: u32 = 0x0000_0001;
}

/// Starts `hartid` in S-mode at `start_addr` with `a1 = opaque`.
///
/// # Safety
///
/// If `hartid` is stoppable/stopped, `start_addr` must point to valid S-mode entry code
/// using an isolated stack/per-hart scratch matching `opaque`.
#[inline(always)]
pub(crate) unsafe fn hart_start(hartid: usize, start_addr: usize, opaque: usize) -> SbiRet {
    sbi_rt::hart_start(hartid, start_addr, opaque)
}

/// Stops execution of the calling hart and returns ownership of it to M-mode.
///
/// # Safety
///
/// Caller must have disabled local interrupts and released all shared resources on this hart.
#[inline(always)]
pub(crate) unsafe fn hart_stop() -> SbiRet {
    sbi_rt::hart_stop()
}

#[inline(always)]
pub(crate) fn hart_get_status(hartid: usize) -> SbiRet {
    sbi_rt::hart_get_status(hartid)
}

/// Suspends the calling hart into `suspend_type`.
///
/// # Safety
///
/// For non-retentive suspend, `resume_addr` must point to valid S-mode entry code that
/// restores execution state from `opaque`.
#[inline(always)]
pub(crate) unsafe fn hart_suspend(suspend_type: u32, resume_addr: usize, opaque: usize) -> SbiRet {
    sbi_rt::hart_suspend(suspend_type, resume_addr, opaque)
}
