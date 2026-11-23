//! Typed Sv39 identity page table with bitflags PTEs and a 4 KiB leaf target page for `RFNC`.

use bitflags::bitflags;
use riscv::register::satp::{self, Mode, Satp};

use crate::platform::boot::SyncUnsafeCell;

const PT_ENTRIES: usize = 512;
const PAGE_SIZE: usize = 4096;
const SV39_ASID: usize = 1;

bitflags! {
    /// RISC-V Sv39 page table entry permission and status flags (OSTD layout).
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PteFlags: usize {
        const VALID      = 1 << 0;
        const READABLE   = 1 << 1;
        const WRITABLE   = 1 << 2;
        const EXECUTABLE = 1 << 3;
        const ACCESSED   = 1 << 6;
        const DIRTY      = 1 << 7;
        const LEAF       = Self::VALID.bits()
            | Self::READABLE.bits()
            | Self::WRITABLE.bits()
            | Self::EXECUTABLE.bits()
            | Self::ACCESSED.bits()
            | Self::DIRTY.bits();
    }
}

#[repr(C, align(4096))]
struct PageTable([usize; PT_ENTRIES]);

#[repr(C, align(4096))]
struct TargetPage([u8; PAGE_SIZE]);

const _: () = assert!(PT_ENTRIES == 512);
const _: () = assert!(PAGE_SIZE == (1 << 12));
const _: () = assert!(size_of::<PageTable>() == PAGE_SIZE);

static L2_PT: SyncUnsafeCell<PageTable> = SyncUnsafeCell::new(PageTable([0; PT_ENTRIES]));
static L1_PT: SyncUnsafeCell<PageTable> = SyncUnsafeCell::new(PageTable([0; PT_ENTRIES]));
static L0_PT: SyncUnsafeCell<PageTable> = SyncUnsafeCell::new(PageTable([0; PT_ENTRIES]));
static RFENCE_TARGET_PAGE: SyncUnsafeCell<TargetPage> =
    SyncUnsafeCell::new(TargetPage([0x5A; PAGE_SIZE]));
static RFENCE_ALT_PAGE: SyncUnsafeCell<TargetPage> =
    SyncUnsafeCell::new(TargetPage([0xA5; PAGE_SIZE]));

const fn encode_pte(ppn: usize, flags: PteFlags) -> usize {
    (ppn << 10) | flags.bits()
}

/// Validated static Sv39 configuration constructed at boot and applied across harts via [`SatpTarget`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sv39Config {
    satp: Satp,
    target_page: usize,
}

impl Sv39Config {
    pub(crate) fn asid(self) -> usize {
        self.satp.asid()
    }

    pub(crate) const fn target_page_addr(self) -> usize {
        self.target_page
    }
}

/// Controlled address-translation mode selectable on a hart (`Bare` or static identity `Sv39`).
#[derive(Clone, Copy, Debug)]
pub(in crate::platform) enum SatpTarget {
    Bare,
    Sv39(Sv39Config),
}

/// Initializes the static 3-level Sv39 identity map covering `0..512 GiB`.
///
/// # Safety
///
/// Must be called once by the BSP before any secondary harts activate Sv39.
pub(crate) unsafe fn init_sv39_identity_table() -> Sv39Config {
    let target_page = RFENCE_TARGET_PAGE.get().cast::<u8>() as usize;
    let l2_idx = (target_page >> 30) & 0x1ff;
    let l1_idx = (target_page >> 21) & 0x1ff;

    // SAFETY: Called once by BSP with exclusive access to static page tables.
    unsafe {
        let l2 = &mut *L2_PT.get();
        let l1 = &mut *L1_PT.get();
        let l0 = &mut *L0_PT.get();

        // Map 0..512 GiB as 1 GiB gigapages so code, stacks, DTB, and MMIO remain accessible.
        for (i, entry) in l2.0.iter_mut().enumerate() {
            *entry = encode_pte(i << 18, PteFlags::LEAF);
        }

        // Split the 1 GiB region containing `RFENCE_TARGET_PAGE` down to 2 MiB megapages.
        for (j, entry) in l1.0.iter_mut().enumerate() {
            *entry = encode_pte((l2_idx << 18) | (j << 9), PteFlags::LEAF);
        }
        l2.0[l2_idx] = encode_pte((l1 as *const PageTable as usize) >> 12, PteFlags::VALID);

        // Split the 2 MiB region containing `RFENCE_TARGET_PAGE` down to genuine 4 KiB leaves.
        for (k, entry) in l0.0.iter_mut().enumerate() {
            *entry = encode_pte((l2_idx << 18) | (l1_idx << 9) | k, PteFlags::LEAF);
        }
        l1.0[l1_idx] = encode_pte((l0 as *const PageTable as usize) >> 12, PteFlags::VALID);
    }

    let root_ppn = (L2_PT.get().cast::<u8>() as usize) >> 12;
    let mut satp = Satp::from_bits(0);
    satp.set_mode(Mode::Sv39);
    satp.set_asid(SV39_ASID);
    satp.set_ppn(root_ppn);
    Sv39Config { satp, target_page }
}

/// Returns the static 4 KiB-leaf target page address.
pub(crate) fn target_page_addr() -> usize {
    RFENCE_TARGET_PAGE.get().cast::<u8>() as usize
}

pub(in crate::platform) const TARGET_PAGE_SENTINEL: u64 = u64::from_le_bytes([0x5A; 8]);
pub(in crate::platform) const ALT_PAGE_SENTINEL: u64 = u64::from_le_bytes([0xA5; 8]);

/// Remaps `RFENCE_TARGET_PAGE`'s virtual address in `L0_PT` to `RFENCE_ALT_PAGE` without flushing TLBs.
///
/// # Safety
///
/// Must only be called while `Sv39Guard` is active and BSP coordinates explicit TLB flushes.
pub(in crate::platform) unsafe fn remap_target_page_to_alt(cfg: &Sv39Config) {
    let target_va = cfg.target_page;
    let l0_idx = (target_va >> 12) & 0x1ff;
    let alt_ppn = (RFENCE_ALT_PAGE.get().cast::<u8>() as usize) >> 12;
    // SAFETY: `L0_PT` is exclusively updated by BSP under `Sv39Guard`; `alt_ppn` is static `RFENCE_ALT_PAGE`.
    unsafe {
        core::ptr::write_volatile(
            &raw mut (*L0_PT.get()).0[l0_idx],
            encode_pte(alt_ppn, PteFlags::LEAF),
        );
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// Restores `RFENCE_TARGET_PAGE`'s virtual address in `L0_PT` back to identity without flushing TLBs.
///
/// # Safety
///
/// Must only be called while `Sv39Guard` is active (or during teardown) before releasing `Sv39Guard`.
pub(in crate::platform) unsafe fn restore_target_page_identity(cfg: &Sv39Config) {
    let target_va = cfg.target_page;
    let l0_idx = (target_va >> 12) & 0x1ff;
    let identity_ppn = target_va >> 12;
    // SAFETY: `L0_PT` is exclusively updated by BSP; restores identity mapping of `RFENCE_TARGET_PAGE`.
    unsafe {
        core::ptr::write_volatile(
            &raw mut (*L0_PT.get()).0[l0_idx],
            encode_pte(identity_ppn, PteFlags::LEAF),
        );
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// Switches the current hart's `satp` to `target`, flushes TLBs, and returns the effective `satp`.
pub(in crate::platform) fn apply(target: SatpTarget) -> Satp {
    let desired = match target {
        SatpTarget::Bare => Satp::from_bits(0),
        SatpTarget::Sv39(cfg) => cfg.satp,
    };
    riscv::asm::sfence_vma_all();
    // SAFETY: `desired` is either Bare (`0`) or the initialized Sv39 identity root covering all RAM/MMIO.
    unsafe { satp::write(desired) };
    riscv::asm::sfence_vma_all();
    if let SatpTarget::Sv39(cfg) = target {
        // SAFETY: `cfg.target_page` is `RFENCE_TARGET_PAGE`, 4 KiB-aligned and identity-mapped.
        unsafe {
            let _ = core::ptr::read_volatile(cfg.target_page as *const u64);
        }
    }
    satp::read()
}

/// Returns `true` if Sv39 translation is currently active on the calling hart.
pub(crate) fn is_sv39_active() -> bool {
    satp::read().try_mode() == Ok(Mode::Sv39)
}
