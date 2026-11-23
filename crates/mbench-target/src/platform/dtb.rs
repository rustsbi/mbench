//! Flattened Device Tree (FDT) discovery for hart topology, timer, ISA, reserved RAM, and UART.

use fdt::Fdt;
use mbench_core::isa::{self, IsaExtensions};

use crate::platform::boot::MAX_HARTS;

const DEFAULT_TIMEBASE_HZ: u64 = 10_000_000;
const QEMU_VIRT_MMODE_BASE: usize = 0x8000_0000;

/// Validated NS16550/NS16550A UART MMIO configuration parsed from FDT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Uart16550Config {
    base: usize,
    reg_shift: u8,
    reg_io_width: u8,
}

impl Uart16550Config {
    fn from_fdt_node(node: &fdt::node::FdtNode<'_, '_>) -> Option<Self> {
        let reg = node.reg()?.next()?;
        let reg_offset = node
            .property("reg-offset")
            .and_then(fdt::node::NodeProperty::as_usize)
            .unwrap_or(0);
        let base = (reg.starting_address as usize).checked_add(reg_offset)?;
        if base == 0 {
            return None;
        }

        let shift_val = node
            .property("reg-shift")
            .and_then(fdt::node::NodeProperty::as_usize)
            .unwrap_or(0);
        let reg_shift = u8::try_from(shift_val).ok().filter(|&s| s <= 3)?;

        let width_val = node
            .property("reg-io-width")
            .and_then(fdt::node::NodeProperty::as_usize)
            .unwrap_or(1);
        let reg_io_width = match width_val {
            1 => 1u8,
            4 => 4u8,
            _ => return None,
        };

        let width = usize::from(reg_io_width);
        let stride = 1usize << reg_shift;
        if stride < width || !base.is_multiple_of(width) {
            return None;
        }
        let min_span = (5usize << reg_shift).checked_add(width)?;
        let offset_span = reg_offset.checked_add(min_span)?;
        if let Some(size) = reg.size
            && offset_span > size
        {
            return None;
        }
        base.checked_add(min_span)?;

        Some(Self {
            base,
            reg_shift,
            reg_io_width,
        })
    }

    pub(in crate::platform) const fn base(self) -> usize {
        self.base
    }

    pub(in crate::platform) const fn lsr_addr(self) -> usize {
        self.base + (5usize << self.reg_shift)
    }

    pub(in crate::platform) const fn reg_io_width(self) -> u8 {
        self.reg_io_width
    }
}

/// Platform hardware properties parsed once from the boot FDT.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HardwareInfo {
    pub(crate) boot_hart_id: usize,
    pub(crate) hart_count: usize,
    pub(crate) hart_ids: [usize; MAX_HARTS],
    pub(crate) timebase_hz: u64,
    pub(crate) reserved_mem_bytes: u64,
    pub(crate) mmode_reserved_addr: Option<usize>,
    pub(crate) isa: IsaExtensions,
    pub(crate) has_sstc: bool,
    pub(crate) has_h_ext: bool,
    pub(crate) uart16550: Option<Uart16550Config>,
    pub(crate) bootargs: &'static str,
}

impl HardwareInfo {
    /// Parses the FDT at `dtb_paddr`, putting `boot_hart_id` in slot 0 of `hart_ids`.
    ///
    /// # Safety
    ///
    /// `dtb_paddr` must point to a valid, immutable FDT blob passed by M-mode firmware
    /// that remains intact for the lifetime of the benchmark run (or `0` when unavailable).
    pub(crate) unsafe fn from_dtb(boot_hart_id: usize, dtb_paddr: usize) -> Self {
        let mut info = Self {
            boot_hart_id,
            hart_count: 1,
            hart_ids: [0; MAX_HARTS],
            timebase_hz: DEFAULT_TIMEBASE_HZ,
            reserved_mem_bytes: 0,
            mmode_reserved_addr: None,
            isa: IsaExtensions::empty(),
            has_sstc: false,
            has_h_ext: false,
            uart16550: None,
            bootargs: "",
        };
        info.hart_ids[0] = boot_hart_id;

        if dtb_paddr == 0 {
            return info;
        }

        // SAFETY: Caller guarantees `dtb_paddr` points to a valid FDT for `'static`.
        let Ok(fdt) = (unsafe { Fdt::from_ptr(dtb_paddr as *const u8) }) else {
            return info;
        };

        if let Some(chosen) = fdt.find_node("/chosen")
            && let Some(prop) = chosen.property("bootargs")
            && let Some(raw) = prop.as_str()
        {
            info.bootargs = raw;
        }

        if let Some(cpus_node) = fdt.find_node("/cpus")
            && let Some(tb) = cpus_node
                .property("timebase-frequency")
                .and_then(fdt::node::NodeProperty::as_usize)
            && tb > 0
        {
            info.timebase_hz = tb as u64;
        }

        parse_harts(&fdt, boot_hart_id, &mut info);
        let (reserved_bytes, mmode_addr) = parse_reserved_memory(&fdt);
        info.reserved_mem_bytes = reserved_bytes;
        info.mmode_reserved_addr = mmode_addr;
        info.uart16550 = parse_uart16550(&fdt);
        info
    }
}

fn is_active_cpu(cpu: &fdt::standard_nodes::Cpu<'_, '_>) -> bool {
    let is_cpu = cpu
        .property("device_type")
        .and_then(fdt::node::NodeProperty::as_str)
        .is_none_or(|s| s == "cpu");
    let status_ok = cpu
        .property("status")
        .and_then(fdt::node::NodeProperty::as_str)
        .is_none_or(|s| s == "ok" || s == "okay");
    is_cpu && status_ok
}

fn parse_harts(fdt: &Fdt<'_>, boot_hart_id: usize, info: &mut HardwareInfo) {
    let any_has_mmu = fdt
        .cpus()
        .filter(is_active_cpu)
        .any(|cpu| cpu.property("mmu-type").is_some());

    let mut common_isa = IsaExtensions::all();
    let mut saw_cpu = false;
    let mut count = 1usize;
    info.hart_ids[0] = boot_hart_id;

    for cpu in fdt.cpus().filter(is_active_cpu) {
        if any_has_mmu && cpu.property("mmu-type").is_none() {
            continue;
        }
        let Some(hart_id) = cpu
            .property("reg")
            .and_then(fdt::node::NodeProperty::as_usize)
        else {
            continue;
        };

        saw_cpu = true;
        common_isa &= detect_cpu_isa(&cpu);

        if hart_id != boot_hart_id && count < MAX_HARTS {
            info.hart_ids[count] = hart_id;
            count += 1;
        }
    }

    info.hart_count = count;
    info.isa = if saw_cpu {
        common_isa
    } else {
        IsaExtensions::empty()
    };
    info.has_sstc = info.isa.has_sstc();
    info.has_h_ext = info.isa.has_h_ext();
}

fn detect_cpu_isa(cpu: &fdt::standard_nodes::Cpu<'_, '_>) -> IsaExtensions {
    let mut exts = IsaExtensions::empty();
    if let Some(ext_prop) = cpu.property("riscv,isa-extensions") {
        exts |= isa::parse_isa_extensions_list(ext_prop.value);
    }
    if let Some(isa_str) = cpu
        .property("riscv,isa")
        .and_then(fdt::node::NodeProperty::as_str)
    {
        exts |= isa::parse_isa_string(isa_str);
    }
    exts
}

fn parse_reserved_memory(fdt: &Fdt<'_>) -> (u64, Option<usize>) {
    let mut total = 0u64;
    let mut explicit_mmode: Option<usize> = None;

    for res in fdt.memory_reservations() {
        total = total.saturating_add(res.size() as u64);
    }

    if let Some(node) = fdt.find_node("/reserved-memory") {
        for child in node.children() {
            let has_no_map = child.property("no-map").is_some();
            let is_mmode_node = child.name.starts_with("mmode_resv");
            if let Some(regs) = child.reg() {
                for reg in regs {
                    let addr = reg.starting_address as usize;
                    if has_no_map
                        && is_mmode_node
                        && explicit_mmode.is_none()
                        && addr != 0
                        && reg.size.is_some_and(|s| s > 0)
                    {
                        explicit_mmode = Some(addr);
                    }
                    if let Some(size) = reg.size {
                        total = total.saturating_add(size as u64);
                    }
                }
            }
        }
    }

    if explicit_mmode.is_none() && is_qemu_virt_board(fdt) {
        explicit_mmode = Some(QEMU_VIRT_MMODE_BASE);
    }

    (total, explicit_mmode)
}

fn is_qemu_virt_board(fdt: &Fdt<'_>) -> bool {
    let Some(root) = fdt.find_node("/") else {
        return false;
    };
    root.compatible()
        .is_some_and(|compat| compat.all().any(|name| name == "riscv-virtio"))
}

fn parse_uart16550(fdt: &Fdt<'_>) -> Option<Uart16550Config> {
    if let Some(stdout) = fdt.chosen().stdout()
        && is_ns16550(&stdout)
        && let Some(cfg) = Uart16550Config::from_fdt_node(&stdout)
    {
        return Some(cfg);
    }

    for node in fdt.all_nodes() {
        if is_ns16550(&node)
            && let Some(cfg) = Uart16550Config::from_fdt_node(&node)
        {
            return Some(cfg);
        }
    }
    None
}

fn is_ns16550(node: &fdt::node::FdtNode<'_, '_>) -> bool {
    node.compatible().is_some_and(|compat| {
        compat
            .all()
            .any(|name| name == "ns16550a" || name == "ns16550")
    })
}
