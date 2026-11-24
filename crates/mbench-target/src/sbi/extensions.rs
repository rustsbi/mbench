//! Small SBI timer, IPI, steal-time, and legacy extension wrappers.

pub(crate) mod time {
    //! SBI Timer extension.

    use mbench_core::record::SbiExtensionId;

    use crate::sbi::SbiRet;

    pub(crate) const EID: usize = SbiExtensionId::Time.eid();

    #[inline(always)]
    pub(crate) fn set_timer(stime_value: u64) -> SbiRet {
        sbi_rt::set_timer(stime_value)
    }
}

pub(crate) mod spi {
    //! SBI Inter-Processor Interrupt extension.

    use mbench_core::record::SbiExtensionId;
    use sbi_rt::HartMask;

    use crate::sbi::SbiRet;

    pub(crate) const EID: usize = SbiExtensionId::Spi.eid();

    #[inline(always)]
    pub(crate) fn send_ipi(hart_mask: usize, hart_mask_base: usize) -> SbiRet {
        sbi_rt::send_ipi(HartMask::from_mask_base(hart_mask, hart_mask_base))
    }
}

pub(crate) mod sta {
    //! SBI Steal-Time Accounting extension.

    use sbi_rt::SharedPtr;

    use crate::sbi::SbiRet;

    /// Configures or clears the STA shared memory region on the current hart.
    ///
    /// # Safety
    ///
    /// `(phys_lo, phys_hi)` must obey the SBI shared-memory validity and registration lifetime contract.
    #[inline(always)]
    pub(crate) unsafe fn set_shmem(phys_lo: usize, phys_hi: usize, flags: usize) -> SbiRet {
        sbi_rt::sta_set_shmem(SharedPtr::new(phys_lo, phys_hi), flags)
    }
}

pub(crate) mod legacy {
    //! SBI v0.1 legacy extension probing and console fallback.

    use crate::sbi::{base, into_result};

    const LEGACY_EIDS: [usize; 9] = [
        sbi_spec::legacy::LEGACY_SET_TIMER,
        sbi_spec::legacy::LEGACY_CONSOLE_PUTCHAR,
        sbi_spec::legacy::LEGACY_CONSOLE_GETCHAR,
        sbi_spec::legacy::LEGACY_CLEAR_IPI,
        sbi_spec::legacy::LEGACY_SEND_IPI,
        sbi_spec::legacy::LEGACY_REMOTE_FENCE_I,
        sbi_spec::legacy::LEGACY_REMOTE_SFENCE_VMA,
        sbi_spec::legacy::LEGACY_REMOTE_SFENCE_VMA_ASID,
        sbi_spec::legacy::LEGACY_SHUTDOWN,
    ];

    /// Probes legacy EIDs `0x00..=0x08` cleanly using `sbi_probe_extension`.
    pub(crate) fn probe_legacy_eids() -> [bool; 9] {
        let mut present = [false; 9];
        for (slot, eid) in present.iter_mut().zip(LEGACY_EIDS) {
            *slot = matches!(
                into_result(base::probe_extension(eid)),
                Ok(v) if v != sbi_spec::base::UNAVAILABLE_EXTENSION
            );
        }
        present
    }

    /// Minimal SBI v0.1 console putchar fallback used ONLY if DBCN and DTB UART are absent.
    #[inline(always)]
    pub(crate) fn legacy_console_putchar(byte: u8) {
        #[expect(
            deprecated,
            reason = "legacy SBI console putchar fallback required when DBCN and DTB UART are absent"
        )]
        let _ = sbi_rt::legacy::console_putchar(byte as usize);
    }
}
