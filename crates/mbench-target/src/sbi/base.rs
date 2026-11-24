//! SBI Base extension queries and ABI-preservation probes.

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
const INVALID_EID: usize = 0x7FFF_FFFF;
const ABI_SENTINEL: [usize; 6] = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666];

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
    unsafe { ecall_check_abi(EID, FID_GET_SPEC_VERSION, ABI_SENTINEL) }
}

/// Probes unassigned EID `0x7FFF_FFFF` with sentinel `a0..a5` to check ABI preservation on error.
pub(crate) fn check_abi_preservation_on_error() -> (SbiRet, bool) {
    // SAFETY: Unassigned EID `0x7FFF_FFFF` takes no memory operands and must preserve registers.
    unsafe { ecall_check_abi(INVALID_EID, 0, ABI_SENTINEL) }
}
