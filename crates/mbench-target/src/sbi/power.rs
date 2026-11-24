//! Small SBI performance, nested-virtualization, suspend, and reset wrappers.

pub(crate) mod cppc {
    //! SBI Collaborative Processor Performance Control extension.

    use crate::sbi::SbiRet;

    pub(crate) const REG_HIGHEST_PERF: u32 = 0x0000_0000;
    pub(crate) const REG_INVALID_RESERVED: u32 = 0x7FFF_FFFF;

    #[inline(always)]
    pub(crate) fn probe(reg_id: u32) -> SbiRet {
        sbi_rt::cppc_probe(reg_id)
    }

    #[inline(always)]
    pub(crate) fn read(reg_id: u32) -> SbiRet {
        sbi_rt::cppc_read(reg_id)
    }

    #[inline(always)]
    pub(crate) fn read_hi(reg_id: u32) -> SbiRet {
        sbi_rt::cppc_read_hi(reg_id)
    }
}

pub(crate) mod nacl {
    //! SBI Nested Acceleration extension.

    use sbi_rt::SharedPtr;

    use crate::sbi::SbiRet;

    pub(crate) const FEAT_SYNC_CSR: usize = sbi_spec::nacl::feature_id::SYNC_CSR;
    pub(crate) const FEAT_SYNC_HFENCE: usize = sbi_spec::nacl::feature_id::SYNC_HFENCE;
    pub(crate) const FEAT_SYNC_SRET: usize = sbi_spec::nacl::feature_id::SYNC_SRET;
    pub(crate) const FEAT_AUTOSWAP_CSR: usize = sbi_spec::nacl::feature_id::AUTOSWAP_CSR;

    #[inline(always)]
    pub(crate) fn probe_feature(feature_id: usize) -> SbiRet {
        sbi_rt::nacl_probe_feature(feature_id as u32)
    }

    /// Configures or clears the NACL shared memory region on the current hart.
    ///
    /// # Safety
    ///
    /// `(phys_lo, phys_hi)` must obey the SBI shared-memory validity and registration lifetime contract.
    #[inline(always)]
    pub(crate) unsafe fn set_shmem(phys_lo: usize, phys_hi: usize, flags: usize) -> SbiRet {
        sbi_rt::nacl_set_shmem(SharedPtr::new(phys_lo, phys_hi), flags)
    }
}

pub(crate) mod susp {
    //! SBI System Suspend extension.

    use mbench_core::record::SbiExtensionId;

    pub(crate) const EID: usize = SbiExtensionId::Susp.eid();
    pub(crate) const FID_SUSPEND: usize = sbi_spec::susp::SUSPEND;
    pub(crate) const SLEEP_TYPE_SUSPEND_TO_RAM: u32 = 0;
    pub(crate) const SLEEP_TYPE_INVALID_RESERVED: u32 = 1;
}

pub(crate) mod srst {
    //! SBI System Reset extension.

    use crate::sbi::SbiRet;

    #[repr(u32)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ResetType {
        Shutdown = sbi_spec::srst::RESET_TYPE_SHUTDOWN,
    }

    #[repr(u32)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ResetReason {
        NoReason = sbi_spec::srst::RESET_REASON_NO_REASON,
        SystemFailure = sbi_spec::srst::RESET_REASON_SYSTEM_FAILURE,
    }

    #[inline(always)]
    pub(crate) fn system_reset(reset_type: ResetType, reset_reason: ResetReason) -> SbiRet {
        sbi_rt::system_reset(reset_type as u32, reset_reason as u32)
    }

    /// Closed set of reserved `(reset_type, reset_reason)` negative probes for `sbi_system_reset`.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum InvalidResetProbe {
        ReservedType,
        ReservedReason,
    }

    /// Probes `sbi_system_reset` with a reserved `(reset_type, reset_reason)` encoding.
    #[inline(always)]
    pub(crate) fn probe_invalid_reset(probe: InvalidResetProbe) -> SbiRet {
        let (reset_type, reset_reason) = match probe {
            InvalidResetProbe::ReservedType => (3, 0),
            InvalidResetProbe::ReservedReason => (0, 2),
        };
        sbi_rt::system_reset(reset_type, reset_reason)
    }
}
