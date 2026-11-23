//! 64 KiB L1 instruction-cache thrashing gadget isolated in `.text.icache_thrash`.

use core::arch::global_asm;

global_asm!(
    r#"
.section .text.icache_thrash, "ax", @progbits

.balign 4096
.global mbench_icache_thrash
.type mbench_icache_thrash, @function
mbench_icache_thrash:
.rept 1023
    .option push
    .option norvc
    j 1f
    .option pop
    .balign 64
1:
.endr
    ret
.size mbench_icache_thrash, . - mbench_icache_thrash
"#
);

unsafe extern "C" {
    fn mbench_icache_thrash();
}

/// Sweeps 64 KiB of L1 instruction cache lines across 1,024 64-byte stride jumps.
#[inline(always)]
pub(crate) fn thrash() {
    // SAFETY: Side-effect-free jump chain in `.text.icache_thrash`.
    unsafe { mbench_icache_thrash() };
}
