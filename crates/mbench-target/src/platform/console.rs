//! Console backend selection (`SBI DBCN -> DTB NS16550A -> SBI Legacy`) outside timed batches.

use core::{fmt, marker::PhantomData, panic::PanicInfo};

use mbench_core::{protocol, record::SbiExtensionId};

use crate::{
    platform::dtb::Uart16550Config,
    sbi::{self, SbiCaps},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsoleKind {
    Dbcn,
    Uart16550(Uart16550Config),
    LegacySbi,
}

/// Active S-mode console output mechanism selected from verified capabilities.
///
/// The UART variant performs volatile MMIO without synchronization and is therefore intentionally
/// `!Sync`; console writes must come from the single owning BSP context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConsoleBackend(ConsoleKind, PhantomData<*mut ()>);

impl ConsoleBackend {
    /// Selects the highest-priority working console backend from probed SBI and FDT state.
    pub(crate) fn select(caps: &SbiCaps, uart16550: Option<Uart16550Config>) -> Self {
        if caps.extensions.contains_ext(SbiExtensionId::Dbcn) {
            // Probe a zero-byte write against valid RAM to verify DBCN responsiveness.
            let probe = sbi::dbcn::write_slice(&[]);
            if probe.error == 0 {
                return Self(ConsoleKind::Dbcn, PhantomData);
            }
        }
        if let Some(cfg) = uart16550 {
            return Self(ConsoleKind::Uart16550(cfg), PhantomData);
        }
        Self(ConsoleKind::LegacySbi, PhantomData)
    }

    /// Returns the short backend label recorded in `@@MBENCH:META`.
    pub(crate) const fn name(self) -> &'static str {
        match self.0 {
            ConsoleKind::Dbcn => "dbcn",
            ConsoleKind::Uart16550(_) => "uart16550",
            ConsoleKind::LegacySbi => "legacy_sbi",
        }
    }
}

impl fmt::Write for ConsoleBackend {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        match self.0 {
            ConsoleKind::Dbcn => {
                let mut bytes = s.as_bytes();
                while !bytes.is_empty() {
                    let ret = sbi::dbcn::write_slice(bytes);
                    if ret.error == 0 && ret.value > 0 {
                        let written = ret.value.min(bytes.len());
                        bytes = &bytes[written..];
                    } else {
                        for &b in bytes {
                            let _ = sbi::dbcn::write_byte(b);
                        }
                        break;
                    }
                }
            }
            ConsoleKind::Uart16550(cfg) => {
                for &b in s.as_bytes() {
                    if b == b'\n' {
                        uart16550_putc(cfg, b'\r');
                    }
                    uart16550_putc(cfg, b);
                }
            }
            ConsoleKind::LegacySbi => {
                for &b in s.as_bytes() {
                    sbi::legacy_console_putchar(b);
                }
            }
        }
        Ok(())
    }
}

struct EmergencyConsole;

impl fmt::Write for EmergencyConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if sbi::dbcn::write_byte(b).error != 0 {
                sbi::legacy_console_putchar(b);
            }
        }
        Ok(())
    }
}

/// Emits a JSON-escaped `@@MBENCH:PANIC` frame on Rust panic and shuts down the target.
pub(crate) fn emergency_panic(info: &PanicInfo<'_>) -> ! {
    let mut con = EmergencyConsole;
    let _ = protocol::write_panic_line(info, &mut con);
    halt_with_failure_reset()
}

/// Emits an `@@MBENCH:PANIC` frame on an unhandled S-mode trap and shuts down the target.
pub(crate) fn emergency_unhandled_trap(scause: usize, stval: usize, sepc: usize) -> ! {
    let mut con = EmergencyConsole;
    let _ = protocol::write_unhandled_trap_panic(scause, stval, sepc, &mut con);
    halt_with_failure_reset()
}

fn halt_with_failure_reset() -> ! {
    let _ = sbi::srst::system_reset(
        sbi::srst::ResetType::Shutdown,
        sbi::srst::ResetReason::SystemFailure,
    );
    loop {
        riscv::asm::wfi();
    }
}

fn uart16550_putc(cfg: Uart16550Config, byte: u8) {
    const LSR_TX_IDLE: u8 = 1 << 5;
    let lsr_addr = cfg.lsr_addr();
    let tx_addr = cfg.base();

    if cfg.reg_io_width() == 4 {
        // SAFETY: `cfg` was validated from the FDT NS16550A node with 4-byte MMIO width & alignment.
        unsafe {
            // CAST: FDT MMIO addresses have no Rust allocation provenance; volatile-only access.
            let lsr = core::ptr::without_provenance::<u32>(lsr_addr);
            while core::ptr::read_volatile(lsr) & u32::from(LSR_TX_IDLE) == 0 {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile(
                core::ptr::without_provenance_mut::<u32>(tx_addr),
                u32::from(byte),
            );
        }
    } else {
        // SAFETY: `cfg` was validated from the FDT NS16550A node with 1-byte MMIO width.
        unsafe {
            // CAST: FDT MMIO addresses have no Rust allocation provenance; volatile-only access.
            let lsr = core::ptr::without_provenance::<u8>(lsr_addr);
            while core::ptr::read_volatile(lsr) & LSR_TX_IDLE == 0 {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile(core::ptr::without_provenance_mut::<u8>(tx_addr), byte);
        }
    }
}
