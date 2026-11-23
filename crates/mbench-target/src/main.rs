//! Bare-metal RISC-V S-mode `mbench` target image.

#![no_std]
#![no_main]

mod platform;
mod sbi;
mod suites;

use core::panic::PanicInfo;

use platform::Platform;

/// Crate entry invoked from [`platform::boot`] with the initialized single-instance [`Platform`].
pub(crate) fn mbench_main(mut platform: Platform) -> ! {
    suites::run_all(&mut platform)
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    platform::console::emergency_panic(info)
}
