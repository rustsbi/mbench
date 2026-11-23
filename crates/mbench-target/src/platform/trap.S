.text

.balign 4
.global mbench_trap_entry
mbench_trap_entry:
    sd   t0, 0(tp)
    sd   t1, 8(tp)
    sd   t2, 16(tp)
    sd   t3, 24(tp)
    sd   a0, 32(tp)
    sd   a1, 40(tp)
    sd   a2, 48(tp)
    sd   a3, 56(tp)
    sd   a4, 64(tp)
    sd   a5, 72(tp)
    sd   a6, 80(tp)
    sd   a7, 88(tp)

    ld   t0, {OFF_HOOK_MODE}(tp)
    beqz t0, 10f

    csrr t1, scause

    # Hook 1: EbreakCount (scause == 3)
    li   t2, {MODE_EBREAK}
    bne  t0, t2, 2f
    li   t2, 3
    bne  t1, t2, 10f
    j    8f

2:  # Hook 6: IllegalCount (scause == 2)
    li   t2, {MODE_ILLEGAL}
    bne  t0, t2, 3f
    li   t2, 2
    bne  t1, t2, 10f

8:  # Common synchronous trap step (advance sepc past 2B/4B instruction and increment hook_flag)
    csrr t2, sepc
    lhu  t3, 0(t2)
    andi t3, t3, 3
    li   t0, 3
    beq  t3, t0, 9f
    addi t2, t2, 2
    j    91f
9:
    addi t2, t2, 4
91:
    csrw sepc, t2
    li   t2, 1
    addi t3, tp, {OFF_HOOK_FLAG}
    .option push
    .option arch, +a
    amoadd.d.rl zero, t2, (t3)
    .option pop
    j    mbench_trap_restore

3:  # Hook 2/3: TimerCaptureSbi or TimerCaptureSstc (scause == (1 << 63) | 5)
    li   t2, 1
    slli t2, t2, 63
    ori  t2, t2, 5
    bne  t1, t2, 4f

    li   t3, {MODE_TIMER_SBI}
    beq  t0, t3, 31f
    li   t3, {MODE_TIMER_SSTC}
    bne  t0, t3, 10f

31:
    fence iorw, iorw
    ld   t1, {OFF_COUNTER_MASK}(tp)
    andi t2, t1, 1
    beqz t2, 32f
    rdcycle t2
    sd   t2, {OFF_HOOK_CYCLES}(tp)
32:
    andi t2, t1, 2
    beqz t2, 33f
    rdinstret t2
    sd   t2, {OFF_HOOK_INSTRET}(tp)
33:
    andi t2, t1, 4
    beqz t2, 34f
    rdtime t2
    sd   t2, {OFF_HOOK_TICKS}(tp)
34:
    li   t3, {MODE_TIMER_SSTC}
    beq  t0, t3, 35f
    # Clear STIP via sbi_set_timer(u64::MAX)
    li   a0, -1
    li   a1, 0
    li   a2, 0
    li   a3, 0
    li   a4, 0
    li   a5, 0
    li   a6, 0
    li   a7, {EID_TIME}
    ecall
    j    36f
35:
    # Clear STIP via Sstc stimecmp (CSR 0x14D) = u64::MAX
    li   t2, -1
    csrw 0x14D, t2
36:
    li   t2, 1
    addi t3, tp, {OFF_HOOK_FLAG}
    .option push
    .option arch, +a
    amoswap.d.rl zero, t2, (t3)
    .option pop
    j    mbench_trap_restore

4:  # Hook 4/5: IpiCapture or IpiBounce (scause == (1 << 63) | 1)
    li   t2, 1
    slli t2, t2, 63
    ori  t2, t2, 1
    bne  t1, t2, 10f

    li   t3, {MODE_IPI_CAPTURE}
    bne  t0, t3, 5f
    fence iorw, iorw
    ld   t1, {OFF_COUNTER_MASK}(tp)
    andi t2, t1, 1
    beqz t2, 41f
    rdcycle t2
    sd   t2, {OFF_HOOK_CYCLES}(tp)
41:
    andi t2, t1, 2
    beqz t2, 42f
    rdinstret t2
    sd   t2, {OFF_HOOK_INSTRET}(tp)
42:
    andi t2, t1, 4
    beqz t2, 43f
    rdtime t2
    sd   t2, {OFF_HOOK_TICKS}(tp)
43:
    csrci sip, 2
    li   t2, 1
    addi t3, tp, {OFF_HOOK_FLAG}
    .option push
    .option arch, +a
    amoadd.d.rl zero, t2, (t3)
    .option pop
    j    mbench_trap_restore

5:
    li   t3, {MODE_IPI_BOUNCE}
    bne  t0, t3, 10f
    csrci sip, 2
    ld   t1, {OFF_BOUNCE_TARGET}(tp)
    andi t2, t1, 63
    li   a0, 1
    sll  a0, a0, t2
    li   t3, -64
    and  a1, t1, t3
    li   a2, 0
    li   a3, 0
    li   a4, 0
    li   a5, 0
    li   a6, 0
    li   a7, {EID_SPI}
    ecall
    li   t2, 1
    addi t3, tp, {OFF_HOOK_FLAG}
    .option push
    .option arch, +a
    amoadd.d.rl zero, t2, (t3)
    .option pop
    j    mbench_trap_restore

10: # try_catch recovery check
    ld   t0, {OFF_TRY_CATCH_PC}(tp)
    beqz t0, 20f
    csrr t1, scause
    sd   t1, {OFF_TRAP_SCAUSE}(tp)
    csrr t1, stval
    sd   t1, {OFF_TRAP_STVAL}(tp)
    csrr t1, sepc
    sd   t1, {OFF_TRAP_SEPC}(tp)
    csrw sepc, t0
    sd   zero, {OFF_TRY_CATCH_PC}(tp)
    j    mbench_trap_restore

20: # Unhandled trap -> panic shutdown
    csrr a0, scause
    csrr a1, stval
    csrr a2, sepc
    j    mbench_unhandled_trap

mbench_trap_restore:
    ld   t0, 0(tp)
    ld   t1, 8(tp)
    ld   t2, 16(tp)
    ld   t3, 24(tp)
    ld   a0, 32(tp)
    ld   a1, 40(tp)
    ld   a2, 48(tp)
    ld   a3, 56(tp)
    ld   a4, 64(tp)
    ld   a5, 72(tp)
    ld   a6, 80(tp)
    ld   a7, 88(tp)
    sret

.balign 4
.global mbench_try_catch_call
.type mbench_try_catch_call, @function
mbench_try_catch_call:
    addi sp, sp, -112
    sd   ra, 0(sp)
    sd   s0, 8(sp)
    sd   s1, 16(sp)
    sd   s2, 24(sp)
    sd   s3, 32(sp)
    sd   s4, 40(sp)
    sd   s5, 48(sp)
    sd   s6, 56(sp)
    sd   s7, 64(sp)
    sd   s8, 72(sp)
    sd   s9, 80(sp)
    sd   s10, 88(sp)
    sd   s11, 96(sp)
    sd   sp, {OFF_SAVED_SP}(tp)
    la   t0, mbench_try_catch_recover
    sd   t0, {OFF_TRY_CATCH_PC}(tp)
    jalr a1
    sd   zero, {OFF_TRY_CATCH_PC}(tp)
    li   a0, 0
    j    1f
mbench_try_catch_recover:
    ld   sp, {OFF_SAVED_SP}(tp)
    sd   zero, {OFF_TRY_CATCH_PC}(tp)
    li   a0, 1
1:
    ld   ra, 0(sp)
    ld   s0, 8(sp)
    ld   s1, 16(sp)
    ld   s2, 24(sp)
    ld   s3, 32(sp)
    ld   s4, 40(sp)
    ld   s5, 48(sp)
    ld   s6, 56(sp)
    ld   s7, 64(sp)
    ld   s8, 72(sp)
    ld   s9, 80(sp)
    ld   s10, 88(sp)
    ld   s11, 96(sp)
    addi sp, sp, 112
    ret
.size mbench_try_catch_call, . - mbench_try_catch_call
