//! SBI Firmware Features extension.

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

pub(crate) const FEAT_MISALIGNED_EXC_DELEG: usize = FwftFeatureId::MisalignedExcDeleg.as_usize();
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
