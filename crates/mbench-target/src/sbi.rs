//! Strongly typed RISC-V SBI v3.0 bindings backed by `sbi-spec` and `sbi-rt`.

use core::arch::asm;

use mbench_core::record::SbiExtensionId;
pub(crate) use sbi_spec::{base::Version as SbiVersion, binary::SbiRet};

const _: () = {
    assert!(SbiExtensionId::Base.eid() == sbi_spec::base::EID_BASE);
    assert!(SbiExtensionId::Time.eid() == sbi_spec::time::EID_TIME);
    assert!(SbiExtensionId::Spi.eid() == sbi_spec::spi::EID_SPI);
    assert!(SbiExtensionId::Rfnc.eid() == sbi_spec::rfnc::EID_RFNC);
    assert!(SbiExtensionId::Hsm.eid() == sbi_spec::hsm::EID_HSM);
    assert!(SbiExtensionId::Srst.eid() == sbi_spec::srst::EID_SRST);
    assert!(SbiExtensionId::Pmu.eid() == sbi_spec::pmu::EID_PMU);
    assert!(SbiExtensionId::Dbcn.eid() == sbi_spec::dbcn::EID_DBCN);
    assert!(SbiExtensionId::Susp.eid() == sbi_spec::susp::EID_SUSP);
    assert!(SbiExtensionId::Cppc.eid() == sbi_spec::cppc::EID_CPPC);
    assert!(SbiExtensionId::Nacl.eid() == sbi_spec::nacl::EID_NACL);
    assert!(SbiExtensionId::Sta.eid() == sbi_spec::sta::EID_STA);
    assert!(SbiExtensionId::Sse.eid() == 0x0053_5345);
    assert!(SbiExtensionId::Fwft.eid() == 0x4657_4654);
    assert!(SbiExtensionId::Dbtr.eid() == 0x4442_5452);
    assert!(SbiExtensionId::Mpxy.eid() == 0x4D50_5859);
};

/// Typed SBI error codes defined by SBI v3.0 §3.1 (extends `sbi-spec` through `-14`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SbiError {
    Failed,
    NotSupported,
    InvalidParam,
    Denied,
    InvalidAddress,
    AlreadyAvailable,
    AlreadyStarted,
    AlreadyStopped,
    NoShmem,
    InvalidState,
    BadRange,
    Timeout,
    Io,
    DeniedLocked,
    Unknown(isize),
}

impl SbiError {
    /// Converts a raw SBI `a0` error register into [`SbiError`].
    pub(crate) const fn from_code(code: isize) -> Self {
        match code {
            -1 => Self::Failed,
            -2 => Self::NotSupported,
            -3 => Self::InvalidParam,
            -4 => Self::Denied,
            -5 => Self::InvalidAddress,
            -6 => Self::AlreadyAvailable,
            -7 => Self::AlreadyStarted,
            -8 => Self::AlreadyStopped,
            -9 => Self::NoShmem,
            -10 => Self::InvalidState,
            -11 => Self::BadRange,
            -12 => Self::Timeout,
            -13 => Self::Io,
            -14 => Self::DeniedLocked,
            other => Self::Unknown(other),
        }
    }

    /// Returns the raw negative SBI error code.
    pub(crate) const fn as_code(self) -> isize {
        match self {
            Self::Failed => -1,
            Self::NotSupported => -2,
            Self::InvalidParam => -3,
            Self::Denied => -4,
            Self::InvalidAddress => -5,
            Self::AlreadyAvailable => -6,
            Self::AlreadyStarted => -7,
            Self::AlreadyStopped => -8,
            Self::NoShmem => -9,
            Self::InvalidState => -10,
            Self::BadRange => -11,
            Self::Timeout => -12,
            Self::Io => -13,
            Self::DeniedLocked => -14,
            Self::Unknown(code) => code,
        }
    }
}

/// Returns the signed SBI error code stored in `ret.error`.
#[inline(always)]
pub(crate) const fn error_code(ret: SbiRet) -> isize {
    ret.error as isize
}

/// Converts a raw [`SbiRet`] into `Result<usize, SbiError>` covering all SBI v3.0 codes.
#[inline(always)]
pub(crate) const fn into_result(ret: SbiRet) -> Result<usize, SbiError> {
    if ret.error == 0 {
        Ok(ret.value)
    } else {
        Err(SbiError::from_code(ret.error as isize))
    }
}

/// Executes a raw SBI `ecall` with extension `eid`, function `fid`, and arguments `a0..a5`.
///
/// # Safety
///
/// Any physical address, hart entry PC, or state transition implied by `(eid, fid, args)` must
/// point to valid S-mode-owned memory/code and satisfy the RISC-V SBI v3.0 specification.
#[inline(always)]
pub(crate) unsafe fn raw_ecall(eid: usize, fid: usize, args: [usize; 6]) -> SbiRet {
    let error: usize;
    let value: usize;
    // SAFETY: Caller upholds all SBI pointer, lifetime, and state-machine preconditions for
    // `(eid, fid, args)`. Register mapping follows the RISC-V SBI calling convention.
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") args[0] => error,
            inlateout("a1") args[1] => value,
            in("a2") args[2],
            in("a3") args[3],
            in("a4") args[4],
            in("a5") args[5],
            in("a6") fid,
            in("a7") eid,
            options(nostack),
        );
    }
    SbiRet { error, value }
}

/// Executes an SBI `ecall` and verifies that `a2..a7` and callee-saved `s2..s5` are preserved.
///
/// # Safety
///
/// Same requirements as [`raw_ecall`]; additionally `s2..s5` are temporarily clobbered inside the
/// `asm!` block before restoration by the compiler.
pub(crate) unsafe fn ecall_check_abi(eid: usize, fid: usize, args: [usize; 6]) -> (SbiRet, bool) {
    const S2_MAGIC: usize = 0x1122_3344_5566_7788;
    const S3_MAGIC: usize = 0x99AA_BBCC_DDEE_FF01;
    const S4_MAGIC: usize = 0xCAFE_BABE_1357_2468;
    const S5_MAGIC: usize = 0xFEED_FACE_8642_7531;

    let error: usize;
    let value: usize;
    let out_a2: usize;
    let out_a3: usize;
    let out_a4: usize;
    let out_a5: usize;
    let out_a6: usize;
    let out_a7: usize;
    let out_s2: usize;
    let out_s3: usize;
    let out_s4: usize;
    let out_s5: usize;

    // SAFETY: All operands use disjoint explicit architectural registers (`t0..t3`, `s2..s5`,
    // `a0..a7`) and caller guarantees `(eid, fid, args)` obeys SBI memory/state preconditions.
    unsafe {
        asm!(
            "mv s2, t0",
            "mv s3, t1",
            "mv s4, t2",
            "mv s5, t3",
            "ecall",
            "mv t0, s2",
            "mv t1, s3",
            "mv t2, s4",
            "mv t3, s5",
            inlateout("t0") S2_MAGIC => out_s2,
            inlateout("t1") S3_MAGIC => out_s3,
            inlateout("t2") S4_MAGIC => out_s4,
            inlateout("t3") S5_MAGIC => out_s5,
            inlateout("a0") args[0] => error,
            inlateout("a1") args[1] => value,
            inlateout("a2") args[2] => out_a2,
            inlateout("a3") args[3] => out_a3,
            inlateout("a4") args[4] => out_a4,
            inlateout("a5") args[5] => out_a5,
            inlateout("a6") fid => out_a6,
            inlateout("a7") eid => out_a7,
            out("s2") _,
            out("s3") _,
            out("s4") _,
            out("s5") _,
            options(nostack),
        );
    }

    let abi_ok = out_s2 == S2_MAGIC
        && out_s3 == S3_MAGIC
        && out_s4 == S4_MAGIC
        && out_s5 == S5_MAGIC
        && out_a2 == args[2]
        && out_a3 == args[3]
        && out_a4 == args[4]
        && out_a5 == args[5]
        && out_a6 == fid
        && out_a7 == eid;
    (SbiRet { error, value }, abi_ok)
}

/// Probes an intentionally invalid EID (`0x7FFF_FFFF`) cleanly without memory side effects.
pub(crate) fn probe_invalid_eid() -> SbiRet {
    // SAFETY: Unassigned EID `0x7FFF_FFFF` takes no memory operands and must return NOT_SUPPORTED.
    unsafe { raw_ecall(0x7FFF_FFFF, 0, [0; 6]) }
}

/// Probes a known-unsupported function ID on standard extension `ext` and checks ABI preservation.
pub(crate) fn probe_invalid_fid_abi(ext: SbiExtensionId) -> (SbiRet, bool) {
    let fid = match ext {
        SbiExtensionId::Time | SbiExtensionId::Spi => 1,
        _ => 99,
    };
    // SAFETY: Non-existent FIDs within standard extensions perform no memory accesses.
    unsafe {
        ecall_check_abi(
            ext.eid(),
            fid,
            [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666],
        )
    }
}

/// Probes a known-unsupported function ID on standard extension `ext` without memory side effects.
pub(crate) fn probe_invalid_fid(ext: SbiExtensionId) -> SbiRet {
    probe_invalid_fid_abi(ext).0
}

/// Probed SBI base properties and available standard extension bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SbiCaps {
    pub(crate) spec_version: usize,
    pub(crate) impl_id: usize,
    pub(crate) impl_version: usize,
    pub(crate) mvendorid: usize,
    pub(crate) marchid: usize,
    pub(crate) mimpid: usize,
    pub(crate) base_probe_errors: u32,
    pub(crate) extensions: mbench_core::record::SbiCapMask,
}

impl SbiCaps {
    /// Queries Base extension info and probes all 16 SBI v3.0 standard extensions.
    pub(crate) fn probe() -> Self {
        let mut base_probe_errors = 0u32;
        let mut record_query = |ret: SbiRet| -> usize {
            match into_result(ret) {
                Ok(v) => v,
                Err(_) => {
                    base_probe_errors = base_probe_errors.saturating_add(1);
                    0
                }
            }
        };

        let spec_version = record_query(base::get_spec_version());
        let impl_id = record_query(base::get_impl_id());
        let impl_version = record_query(base::get_impl_version());
        let mvendorid = record_query(base::get_mvendorid());
        let marchid = record_query(base::get_marchid());
        let mimpid = record_query(base::get_mimpid());

        let mut extensions = mbench_core::record::SbiCapMask::BASE;
        for ext in SbiExtensionId::ALL {
            if ext == SbiExtensionId::Base {
                continue;
            }
            match into_result(base::probe_extension(ext.eid())) {
                Ok(val) if val != sbi_spec::base::UNAVAILABLE_EXTENSION => {
                    extensions.set_ext(ext);
                }
                Ok(_) => {}
                Err(_) => {
                    base_probe_errors = base_probe_errors.saturating_add(1);
                }
            }
        }

        Self {
            spec_version,
            impl_id,
            impl_version,
            mvendorid,
            marchid,
            mimpid,
            base_probe_errors,
            extensions,
        }
    }
}

/// Base Extension (`EID = 0x10`).
pub(crate) mod base {
    use mbench_core::record::SbiExtensionId;

    use super::{SbiRet, ecall_check_abi, raw_ecall};

    pub(crate) const EID: usize = SbiExtensionId::Base.eid();
    const FID_GET_SPEC_VERSION: usize = sbi_spec::base::GET_SBI_SPEC_VERSION;
    const FID_GET_IMPL_ID: usize = sbi_spec::base::GET_SBI_IMPL_ID;
    const FID_GET_IMPL_VERSION: usize = sbi_spec::base::GET_SBI_IMPL_VERSION;
    const FID_PROBE_EXTENSION: usize = sbi_spec::base::PROBE_EXTENSION;
    const FID_GET_MVENDORID: usize = sbi_spec::base::GET_MVENDORID;
    const FID_GET_MARCHID: usize = sbi_spec::base::GET_MARCHID;
    const FID_GET_MIMPID: usize = sbi_spec::base::GET_MIMPID;

    #[inline(always)]
    pub(crate) fn get_spec_version() -> SbiRet {
        // SAFETY: Side-effect-free Base CSR query taking zero memory arguments.
        unsafe { raw_ecall(EID, FID_GET_SPEC_VERSION, [0; 6]) }
    }

    #[inline(always)]
    pub(crate) fn get_impl_id() -> SbiRet {
        // SAFETY: Side-effect-free Base query taking zero memory arguments.
        unsafe { raw_ecall(EID, FID_GET_IMPL_ID, [0; 6]) }
    }

    #[inline(always)]
    pub(crate) fn get_impl_version() -> SbiRet {
        // SAFETY: Side-effect-free Base query taking zero memory arguments.
        unsafe { raw_ecall(EID, FID_GET_IMPL_VERSION, [0; 6]) }
    }

    #[inline(always)]
    pub(crate) fn probe_extension(extension_id: usize) -> SbiRet {
        // SAFETY: Pure query checking extension availability for integer `extension_id`.
        unsafe { raw_ecall(EID, FID_PROBE_EXTENSION, [extension_id, 0, 0, 0, 0, 0]) }
    }

    #[inline(always)]
    pub(crate) fn get_mvendorid() -> SbiRet {
        // SAFETY: Side-effect-free Base CSR query taking zero memory arguments.
        unsafe { raw_ecall(EID, FID_GET_MVENDORID, [0; 6]) }
    }

    #[inline(always)]
    pub(crate) fn get_marchid() -> SbiRet {
        // SAFETY: Side-effect-free Base CSR query taking zero memory arguments.
        unsafe { raw_ecall(EID, FID_GET_MARCHID, [0; 6]) }
    }

    #[inline(always)]
    pub(crate) fn get_mimpid() -> SbiRet {
        // SAFETY: Side-effect-free Base CSR query taking zero memory arguments.
        unsafe { raw_ecall(EID, FID_GET_MIMPID, [0; 6]) }
    }

    /// Calls `get_spec_version` with sentinel registers in `a0..a5` to check ABI preservation.
    pub(crate) fn check_abi_preservation() -> (SbiRet, bool) {
        // SAFETY: `FID_GET_SPEC_VERSION` ignores `a0..a5` and touches no supervisor memory.
        unsafe {
            ecall_check_abi(
                EID,
                FID_GET_SPEC_VERSION,
                [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666],
            )
        }
    }

    /// Probes unassigned EID `0x7FFF_FFFF` with sentinel `a0..a5` to check ABI preservation on error.
    pub(crate) fn check_abi_preservation_on_error() -> (SbiRet, bool) {
        // SAFETY: Unassigned EID `0x7FFF_FFFF` takes no memory operands and must preserve registers.
        unsafe {
            ecall_check_abi(
                0x7FFF_FFFF,
                0,
                [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666],
            )
        }
    }
}

/// Timer Extension (`EID = 0x54494D45`).
pub(crate) mod time {
    use mbench_core::record::SbiExtensionId;

    use super::SbiRet;

    pub(crate) const EID: usize = SbiExtensionId::Time.eid();

    #[inline(always)]
    pub(crate) fn set_timer(stime_value: u64) -> SbiRet {
        sbi_rt::set_timer(stime_value)
    }
}

/// IPI Extension (`EID = 0x735049`).
pub(crate) mod spi {
    use mbench_core::record::SbiExtensionId;
    use sbi_rt::HartMask;

    use super::SbiRet;

    pub(crate) const EID: usize = SbiExtensionId::Spi.eid();

    #[inline(always)]
    pub(crate) fn send_ipi(hart_mask: usize, hart_mask_base: usize) -> SbiRet {
        sbi_rt::send_ipi(HartMask::from_mask_base(hart_mask, hart_mask_base))
    }
}

/// Remote Fence Extension (`EID = 0x52464E43`).
pub(crate) mod rfnc {
    use sbi_rt::HartMask;

    use super::SbiRet;

    #[inline(always)]
    pub(crate) fn remote_fence_i(hart_mask: usize, hart_mask_base: usize) -> SbiRet {
        sbi_rt::remote_fence_i(HartMask::from_mask_base(hart_mask, hart_mask_base))
    }

    #[inline(always)]
    pub(crate) fn remote_sfence_vma(
        hart_mask: usize,
        hart_mask_base: usize,
        start_addr: usize,
        size: usize,
    ) -> SbiRet {
        sbi_rt::remote_sfence_vma(
            HartMask::from_mask_base(hart_mask, hart_mask_base),
            start_addr,
            size,
        )
    }

    #[inline(always)]
    pub(crate) fn remote_sfence_vma_asid(
        hart_mask: usize,
        hart_mask_base: usize,
        start_addr: usize,
        size: usize,
        asid: usize,
    ) -> SbiRet {
        sbi_rt::remote_sfence_vma_asid(
            HartMask::from_mask_base(hart_mask, hart_mask_base),
            start_addr,
            size,
            asid,
        )
    }

    #[inline(always)]
    pub(crate) fn remote_hfence_gvma_vmid(
        hart_mask: usize,
        hart_mask_base: usize,
        start_addr: usize,
        size: usize,
        vmid: usize,
    ) -> SbiRet {
        sbi_rt::remote_hfence_gvma_vmid(
            HartMask::from_mask_base(hart_mask, hart_mask_base),
            start_addr,
            size,
            vmid,
        )
    }

    #[inline(always)]
    pub(crate) fn remote_hfence_gvma(
        hart_mask: usize,
        hart_mask_base: usize,
        start_addr: usize,
        size: usize,
    ) -> SbiRet {
        sbi_rt::remote_hfence_gvma(
            HartMask::from_mask_base(hart_mask, hart_mask_base),
            start_addr,
            size,
        )
    }

    #[inline(always)]
    pub(crate) fn remote_hfence_vvma_asid(
        hart_mask: usize,
        hart_mask_base: usize,
        start_addr: usize,
        size: usize,
        asid: usize,
    ) -> SbiRet {
        sbi_rt::remote_hfence_vvma_asid(
            HartMask::from_mask_base(hart_mask, hart_mask_base),
            start_addr,
            size,
            asid,
        )
    }

    #[inline(always)]
    pub(crate) fn remote_hfence_vvma(
        hart_mask: usize,
        hart_mask_base: usize,
        start_addr: usize,
        size: usize,
    ) -> SbiRet {
        sbi_rt::remote_hfence_vvma(
            HartMask::from_mask_base(hart_mask, hart_mask_base),
            start_addr,
            size,
        )
    }
}

/// Hart State Management Extension (`EID = 0x48534D`).
pub(crate) mod hsm {
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
    pub(crate) unsafe fn hart_suspend(
        suspend_type: u32,
        resume_addr: usize,
        opaque: usize,
    ) -> SbiRet {
        sbi_rt::hart_suspend(suspend_type, resume_addr, opaque)
    }
}

/// System Reset Extension (`EID = 0x53525354`).
pub(crate) mod srst {
    use super::SbiRet;

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

/// Performance Monitoring Unit Extension (`EID = 0x504D55`).
pub(crate) mod pmu {
    use mbench_core::record::SbiExtensionId;

    use super::{SbiRet, raw_ecall};

    pub(crate) const EID: usize = SbiExtensionId::Pmu.eid();
    const FID_NUM_COUNTERS: usize = sbi_spec::pmu::NUM_COUNTERS;
    const FID_SNAPSHOT_SET_SHMEM: usize = sbi_spec::pmu::SNAPSHOT_SET_SHMEM;
    const FID_EVENT_GET_INFO: usize = 8;

    pub(crate) const HW_CPU_CYCLES: usize = sbi_spec::pmu::hardware_event::CPU_CYCLES;
    pub(crate) const HW_CACHE_REFERENCES: usize = sbi_spec::pmu::hardware_event::CACHE_REFERENCES;
    pub(crate) const HW_BRANCH_INSTRUCTIONS: usize =
        sbi_spec::pmu::hardware_event::BRANCH_INSTRUCTIONS;
    pub(crate) const HW_CACHE_BPU_READ_MISS: usize = (sbi_spec::pmu::event_type::HARDWARE_CACHE
        << 16)
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
        info & 0x0fff
    }

    /// Returns counter bit width encoded in `counter_info[17:12]` (`width - 1`).
    #[inline(always)]
    pub(crate) const fn info_width(info: usize) -> usize {
        ((info >> 12) & 0x3f) + 1
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
    pub(crate) unsafe fn snapshot_set_shmem(
        phys_lo: usize,
        phys_hi: usize,
        flags: usize,
    ) -> SbiRet {
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
}

/// Debug Console Extension (`EID = 0x4442434E`) with slice-bounded safe wrappers.
pub(crate) mod dbcn {
    use sbi_rt::Physical;

    use super::SbiRet;

    #[inline(always)]
    unsafe fn write_raw(num_bytes: usize, phys_lo: usize, phys_hi: usize) -> SbiRet {
        sbi_rt::console_write(Physical::<&[u8]>::new(num_bytes, phys_lo, phys_hi))
    }

    #[inline(always)]
    unsafe fn read_raw(num_bytes: usize, phys_lo: usize, phys_hi: usize) -> SbiRet {
        sbi_rt::console_read(Physical::<&mut [u8]>::new(num_bytes, phys_lo, phys_hi))
    }

    /// Writes `bytes` to the SBI debug console (safe in Bare and identity-mapped Sv39).
    #[inline(always)]
    pub(crate) fn write_slice(bytes: &[u8]) -> SbiRet {
        let dummy = 0u8;
        let phys_lo = if bytes.is_empty() {
            (&raw const dummy) as usize
        } else {
            bytes.as_ptr() as usize
        };
        // SAFETY: `bytes` (or stack `dummy` when `len == 0`) lies in valid readable identity-mapped RAM.
        unsafe { write_raw(bytes.len(), phys_lo, 0) }
    }

    /// Reads up to `buf.len()` bytes non-blockingly into `buf` from the SBI debug console.
    #[inline(always)]
    pub(crate) fn read_slice(buf: &mut [u8]) -> SbiRet {
        let mut dummy = 0u8;
        let phys_lo = if buf.is_empty() {
            (&raw mut dummy) as usize
        } else {
            buf.as_mut_ptr() as usize
        };
        // SAFETY: `buf` is uniquely borrowed writable memory in identity-mapped RAM.
        unsafe { read_raw(buf.len(), phys_lo, 0) }
    }

    /// Probes M-mode validation by requesting a read from out-of-range physical address `phys_hi = u32::MAX`.
    pub(crate) fn probe_invalid_phys_hi() -> SbiRet {
        // SAFETY: `phys_hi = 0xFFFF_FFFF` lies outside physical RAM and tests M-mode range checks without writes.
        unsafe { write_raw(4, 0, 0xFFFF_FFFF) }
    }

    #[inline(always)]
    pub(crate) fn write_byte(byte: u8) -> SbiRet {
        sbi_rt::console_write_byte(byte)
    }
}

/// System Suspend Extension (`EID = 0x53555350`).
pub(crate) mod susp {
    use mbench_core::record::SbiExtensionId;

    pub(crate) const EID: usize = SbiExtensionId::Susp.eid();
    pub(crate) const FID_SUSPEND: usize = sbi_spec::susp::SUSPEND;
    pub(crate) const SLEEP_TYPE_SUSPEND_TO_RAM: u32 = 0;
    pub(crate) const SLEEP_TYPE_INVALID_RESERVED: u32 = 1;

    /// Invokes `sbi_system_suspend(sleep_type, resume_addr, opaque)` with caller-supplied state.
    ///
    /// # Safety
    ///
    /// If `sleep_type` may enter suspend, `resume_addr` must point to a valid S-mode resume
    /// entry routine that restores execution state from `opaque` and supervisor CSRs.
    #[inline(always)]
    #[expect(
        dead_code,
        reason = "raw unsafe SUSP entrypoint preserved alongside assembly context-saving wrapper"
    )]
    pub(crate) unsafe fn system_suspend_raw(
        sleep_type: u32,
        resume_addr: usize,
        opaque: usize,
    ) -> super::SbiRet {
        sbi_rt::system_suspend(sleep_type, resume_addr, opaque)
    }
}

/// CPPC Extension (`EID = 0x43505043`).
pub(crate) mod cppc {
    use super::SbiRet;

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

/// Nested Acceleration Extension (`EID = 0x4E41434C`).
pub(crate) mod nacl {
    use sbi_rt::SharedPtr;

    use super::SbiRet;

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

/// Steal-Time Accounting Extension (`EID = 0x535441`).
pub(crate) mod sta {
    use sbi_rt::SharedPtr;

    use super::SbiRet;

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

/// Supervisor Software Events Extension (`EID = 0x535345`, SBI v3.0).
pub(crate) mod sse {
    use mbench_core::record::SbiExtensionId;

    use super::{SbiRet, raw_ecall};

    pub(crate) const EID: usize = SbiExtensionId::Sse.eid();
    const FID_READ_ATTRS: usize = 0;
    const FID_WRITE_ATTRS: usize = 1;
    const FID_REGISTER: usize = 2;
    const FID_UNREGISTER: usize = 3;
    const FID_ENABLE: usize = 4;
    const FID_DISABLE: usize = 5;
    pub(crate) const FID_COMPLETE: usize = 6;
    const FID_INJECT: usize = 7;
    const FID_HART_UNMASK: usize = 8;
    const FID_HART_MASK: usize = 9;

    pub(crate) const EVENT_LOCAL_SOFTWARE: usize = 0xFFFF_0000;
    pub(crate) const EVENT_INVALID: usize = 0xDEAD_BEEF;

    pub(crate) const ATTR_STATUS: usize = 0;
    pub(crate) const ATTR_PRIO: usize = 1;
    pub(crate) const ATTR_INVALID: usize = 10;

    pub(crate) const STATUS_STATE_MASK: usize = 0b11;
    pub(crate) const STATUS_STATE_UNUSED: usize = 0;
    pub(crate) const STATUS_STATE_REGISTERED: usize = 1;
    pub(crate) const STATUS_STATE_ENABLED: usize = 2;
    pub(crate) const STATUS_INJECTABLE: usize = 1 << 3;
    pub(crate) const STATUS_RESERVED_MASK: usize = !0b1111usize;

    /// Reads `attr_count` attributes for `event_id` into `(out_lo, out_hi)`.
    ///
    /// # Safety
    ///
    /// `(out_lo, out_hi)` must point to writable identity-mapped S-mode memory for `attr_count * size_of::<usize>()` bytes.
    #[inline(always)]
    pub(crate) unsafe fn read_attrs_raw(
        event_id: usize,
        base_attr_id: usize,
        attr_count: usize,
        out_lo: usize,
        out_hi: usize,
    ) -> SbiRet {
        // SAFETY: Caller guarantees writable output buffer for `attr_count` attributes.
        unsafe {
            raw_ecall(
                EID,
                FID_READ_ATTRS,
                [event_id, base_attr_id, attr_count, out_lo, out_hi, 0],
            )
        }
    }

    /// Writes `attr_count` attributes for `event_id` from `(in_lo, in_hi)`.
    ///
    /// # Safety
    ///
    /// `(in_lo, in_hi)` must point to readable identity-mapped S-mode memory for `attr_count * size_of::<usize>()` bytes.
    #[inline(always)]
    pub(crate) unsafe fn write_attrs_raw(
        event_id: usize,
        base_attr_id: usize,
        attr_count: usize,
        in_lo: usize,
        in_hi: usize,
    ) -> SbiRet {
        // SAFETY: Caller guarantees readable input buffer for `attr_count` attributes.
        unsafe {
            raw_ecall(
                EID,
                FID_WRITE_ATTRS,
                [event_id, base_attr_id, attr_count, in_lo, in_hi, 0],
            )
        }
    }

    /// Registers an S-mode SSE trampoline for `event_id`.
    ///
    /// # Safety
    ///
    /// `handler_pc` must be a valid SSE entry routine ending in `FID_COMPLETE`, and `handler_arg`
    /// must remain valid for the entire registered lifetime of `event_id`.
    #[inline(always)]
    pub(crate) unsafe fn register(
        event_id: usize,
        handler_pc: usize,
        handler_arg: usize,
    ) -> SbiRet {
        // SAFETY: Caller guarantees valid handler entrypoint and `handler_arg` lifetime.
        unsafe {
            raw_ecall(
                EID,
                FID_REGISTER,
                [event_id, handler_pc, handler_arg, 0, 0, 0],
            )
        }
    }

    #[inline(always)]
    pub(crate) fn unregister(event_id: usize) -> SbiRet {
        // SAFETY: Unregisters an SSE handler without passing memory pointers.
        unsafe { raw_ecall(EID, FID_UNREGISTER, [event_id, 0, 0, 0, 0, 0]) }
    }

    #[inline(always)]
    pub(crate) fn enable(event_id: usize) -> SbiRet {
        // SAFETY: Enables SSE event delivery without passing memory pointers.
        unsafe { raw_ecall(EID, FID_ENABLE, [event_id, 0, 0, 0, 0, 0]) }
    }

    #[inline(always)]
    pub(crate) fn disable(event_id: usize) -> SbiRet {
        // SAFETY: Disables SSE event delivery without passing memory pointers.
        unsafe { raw_ecall(EID, FID_DISABLE, [event_id, 0, 0, 0, 0, 0]) }
    }

    #[inline(always)]
    pub(crate) fn inject(event_id: usize, hart_id: usize) -> SbiRet {
        // SAFETY: Triggers delivery for an already-registered SSE event.
        unsafe { raw_ecall(EID, FID_INJECT, [event_id, hart_id, 0, 0, 0, 0]) }
    }

    #[inline(always)]
    pub(crate) fn hart_unmask() -> SbiRet {
        // SAFETY: Unmasks SSE events on current hart without memory operands.
        unsafe { raw_ecall(EID, FID_HART_UNMASK, [0; 6]) }
    }

    #[inline(always)]
    pub(crate) fn hart_mask() -> SbiRet {
        // SAFETY: Masks SSE events on current hart without memory operands.
        unsafe { raw_ecall(EID, FID_HART_MASK, [0; 6]) }
    }

    /// Invokes `sbi_sse_complete` directly from normal S-mode context to verify `INVALID_STATE`.
    #[inline(always)]
    pub(crate) fn complete_outside_handler() -> SbiRet {
        // SAFETY: Calling `FID_COMPLETE` with no RUNNING SSE event takes no memory pointers.
        unsafe { raw_ecall(EID, FID_COMPLETE, [0; 6]) }
    }
}

/// Firmware Features Extension (`EID = 0x46574654`, SBI v3.0).
pub(crate) mod fwft {
    use mbench_core::record::SbiExtensionId;

    use super::{SbiRet, raw_ecall};

    const EID: usize = SbiExtensionId::Fwft.eid();
    const FID_SET: usize = 0;
    const FID_GET: usize = 1;

    /// Typed SBI v3.0 Firmware Features identifiers.
    #[repr(usize)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum FwftFeatureId {
        MisalignedExcDeleg = 0,
        LandingPad = 1,
        ShadowStack = 2,
        DoubleTrap = 3,
        PteAdHwUpdating = 4,
        PointerMaskingPmlen = 5,
    }

    impl FwftFeatureId {
        pub(crate) const ALL: [Self; 6] = [
            Self::MisalignedExcDeleg,
            Self::LandingPad,
            Self::ShadowStack,
            Self::DoubleTrap,
            Self::PteAdHwUpdating,
            Self::PointerMaskingPmlen,
        ];

        pub(crate) const fn as_usize(self) -> usize {
            self as usize
        }
    }

    pub(crate) const FEAT_MISALIGNED_EXC_DELEG: usize =
        FwftFeatureId::MisalignedExcDeleg.as_usize();
    pub(crate) const FEAT_LOCAL_RESERVED: usize = 0x0000_0006;
    pub(crate) const FEAT_GLOBAL_RESERVED: usize = 0x8000_0000;
    pub(crate) const FLAG_INVALID_RESERVED: usize = 1 << 1;

    #[inline(always)]
    pub(crate) fn set(feature_id: usize, value: usize, flags: usize) -> SbiRet {
        // SAFETY: FWFT feature toggles operate strictly on integer register values.
        unsafe { raw_ecall(EID, FID_SET, [feature_id, value, flags, 0, 0, 0]) }
    }

    #[inline(always)]
    pub(crate) fn get(feature_id: usize) -> SbiRet {
        // SAFETY: FWFT feature query operates strictly on integer register values.
        unsafe { raw_ecall(EID, FID_GET, [feature_id, 0, 0, 0, 0, 0]) }
    }
}

/// Debug Triggers Extension (`EID = 0x44425452`, SBI v3.0).
pub(crate) mod dbtr {
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
    pub(crate) const fn build_smode_match_tdata1(
        kind: TriggerKind,
        access: TriggerAccess,
    ) -> usize {
        let access_bit = match access {
            TriggerAccess::Load => 1 << 0,
            TriggerAccess::Exec => 1 << 2,
        };
        let s_bit = 1usize << 4;
        ((kind as usize) << 60) | s_bit | access_bit
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
}

/// Message Proxy Extension (`EID = 0x4D505859`, SBI v3.0).
pub(crate) mod mpxy {
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
}

/// Non-destructive legacy SBI v0.1 extension presence probing via Base extension.
pub(crate) mod legacy {
    use super::{base, into_result};

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
}

/// Minimal SBI v0.1 console putchar fallback used ONLY if DBCN and DTB UART are absent.
#[inline(always)]
pub(crate) fn legacy_console_putchar(byte: u8) {
    #[expect(deprecated)]
    let _ = sbi_rt::legacy::console_putchar(byte as usize);
}
