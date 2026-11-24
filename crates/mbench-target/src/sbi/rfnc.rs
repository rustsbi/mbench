//! SBI Remote Fence extension.

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
