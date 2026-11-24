//! Strongly typed RISC-V SBI v3.0 bindings backed by `sbi-spec` and `sbi-rt`.
//!
//! The root exposes the shared error/return types and the raw `ecall` boundary.
//! Per-extension child modules preserve the original `crate::sbi::*` paths.

use mbench_core::record::SbiExtensionId;
pub(crate) use sbi_spec::{base::Version as SbiVersion, binary::SbiRet};

pub(crate) mod base;
mod caps;
pub(crate) mod dbcn;
pub(crate) mod dbtr;
mod ecall;
mod extensions;
pub(crate) mod fwft;
pub(crate) mod hsm;
pub(crate) mod mpxy;
pub(crate) mod pmu;
mod power;
pub(crate) mod rfnc;
pub(crate) mod sse;

pub(crate) use caps::SbiCaps;
pub(crate) use ecall::{
    ecall_check_abi, probe_invalid_eid, probe_invalid_fid, probe_invalid_fid_abi, raw_ecall,
};
pub(crate) use extensions::{legacy, spi, sta, time};
pub(crate) use legacy::legacy_console_putchar;
pub(crate) use power::{cppc, nacl, srst, susp};

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
