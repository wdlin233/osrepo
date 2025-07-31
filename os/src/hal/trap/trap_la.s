FP_START = 32
.altmacro
.macro SAVE_GP n
    st.d $r\n, $sp, \n*8
.endm
.macro LOAD_GP n
    ld.d $r\n, $sp, \n*8
.endm
.macro SAVE_FP n, m
    fst.d $f\n, $sp, \m*8
.endm
.macro LOAD_FP n, m
    fld.d $f\n, $sp, \m*8
.endm

    .section .text.trampoline
    .globl __alltraps
    .globl __restore
    .balign 4096
.equ CSR_SAVE, 0x30    
.equ CSR_ERA, 0x6
.equ CSR_PRMD, 0x1
.equ CSR_PGDL, 0x19
.equ CSR_PGD, 0x1b
# user -> kernel
__alltraps:
    # turn off the interrept is necessary
    csrwr   $sp, CSR_SAVE
    # now sp->*TrapContext in user space, CSR_SAVE->user stack
    # save other general purpose registers
    # $r2 is $tp
    SAVE_GP 1
    SAVE_GP 2
    # skip $sp($r3), we will save it later
    # save $r4~$r31
    .set n, 4
    .rept 28
        SAVE_GP %n
        .set n, n+1
    .endr
    # save floating point registers
    .set n, 0
    .set m, FP_START
    .rept 32
        SAVE_FP %n, %m
        .set n, n+1
        .set m, m+1
    .endr
    # save fcsr
    movfcsr2gr $t0, $fcsr0
    st.w $t0, $sp, 64*8
    # save FCC
    movcf2gr $t0, $fcc7
    slli.w $t0, $t0, 1
    movcf2gr $t0, $fcc6
    slli.w $t0, $t0, 1
    movcf2gr $t0, $fcc5
    slli.w $t0, $t0, 1
    movcf2gr $t0, $fcc4
    slli.w $t0, $t0, 1
    movcf2gr $t0, $fcc3
    slli.w $t0, $t0, 1
    movcf2gr $t0, $fcc2
    slli.w $t0, $t0, 1
    movcf2gr $t0, $fcc1
    slli.w $t0, $t0, 1
    movcf2gr $t0, $fcc0
    st.b $t0, $sp, 64*8+4

    # save origin_a0
    st.d $a0, $sp, 70*8
    # save prmd, era etc.
    csrrd   $t0, CSR_PRMD       # prmd
    csrrd   $t1, CSR_ERA        # return address
    st.d    $t0, $sp, 65*8
    st.d    $t1, $sp, 66*8      # pc register

    csrrd   $t2, CSR_SAVE       # read user stack pointer
    st.d    $t2, $sp, 3*8

    # load kernel_satp into $t0
    # ld.d    $t0, $sp, 67*8
    # load trap_handler into $t1
    ld.d    $t1, $sp, 69*8
    # move to kernel_sp
    ld.d    $sp, $sp, 68*8
    # switch to kernel space
    # csrwr   $t0, CSR_PGDL       # set kernel page table
    invtlb 0x3, $zero, $zero
    # jump to trap_handler
    jr $t1

# kernel -> user
__restore:
    # a0: *TrapContext in user space(Constant), 
    # a1: user space token
    # switch to user space
    slli.d $a1, $a1, 12
    csrwr  $a1, CSR_PGDL
    invtlb 0x3, $zero, $zero
    move    $sp, $a0
    csrwr  $a0, CSR_SAVE

    # now sp points to TrapContext in user space, start restoring based on it
    # restore fcsr
    ld.d $t0, $sp, 64*8
    movgr2fcsr $fcsr0, $t0
    # restore FCC
    ld.b $t0, $sp, 64*8+4
    movgr2cf $fcc0, $t0
    srli.w $t0, $t0, 1
    movgr2cf $fcc1, $t0
    srli.w $t0, $t0, 1
    movgr2cf $fcc2, $t0
    srli.w $t0, $t0, 1
    movgr2cf $fcc3, $t0
    srli.w $t0, $t0, 1
    movgr2cf $fcc4, $t0
    srli.w $t0, $t0, 1
    movgr2cf $fcc5, $t0
    srli.w $t0, $t0, 1
    movgr2cf $fcc6, $t0
    srli.w $t0, $t0, 1
    movgr2cf $fcc7, $t0

    # restore prmd, era etc.
    ld.d    $t0, $sp, 65*8     # prmd
    ld.d    $t1, $sp, 66*8     # era
    csrwr $t0, CSR_PRMD
    csrwr $t1, CSR_ERA

    # restore general purpose registers except r0/$sp
    LOAD_GP 1
    LOAD_GP 2
    # skip $sp($r3), we will restore it later
    # restore $r4~$r31
    .set n, 4
    .rept 28
        LOAD_GP %n
        .set n, n+1
    .endr
    # restore floating point registers
    .set n, 0
    .set m, FP_START
    .rept 32
        LOAD_FP %n, %m
        .set n, n+1
        .set m, m+1
    .endr
    # back to user stack pointer
    LOAD_GP 3
    ertn

    .section .text
    .globl __trap_from_kernel
    .balign 4096
__trap_from_kernel:
    # Keep the original $sp in SAVE
    csrwr $sp, CSR_SAVE    
    csrrd $sp, CSR_SAVE
    # Now move the $sp lower to push the registers
    addi.d $sp, $sp, -256
    # Align the $sp
    srli.d  $sp, $sp, 3
    slli.d  $sp, $sp, 3
    # now sp->*GeneralRegisters in kern space, CSR_SAVE->(the previous $sp)

    SAVE_GP 1 # Save $ra
    SAVE_GP 2 # Save $tp

    # skip r3(sp)
    .set n, 4
    .rept 28
        SAVE_GP %n
        .set n, n+1
    .endr
    
    csrrd $t0, CSR_ERA
    st.d $t0, $sp, 66*8

    move $a0, $sp
    csrrd $sp, CSR_SAVE
    st.d $sp, $a0, 3*8
    move $sp, $a0

    bl trap_from_kernel

    ld.d  $ra, $sp, 66*8
    csrwr $ra, CSR_ERA
    LOAD_GP 1
    LOAD_GP 2

    # skip r3(sp)
    .set n, 4
    .rept 28
        LOAD_GP %n
        .set n, n+1
    .endr
    .set n, 0
    
    csrrd $sp, CSR_SAVE
    ertn

# tlb refill
    .section .text
    .globl __tlb_refill
    .balign 4096
__tlb_refill:
    csrwr $t0, 0x8B
    csrrd $t0, 0x1B
    lddir $t0, $t0, 3 #访问页目录表PGD
    lddir $t0, $t0, 1 #访问页目录表PMD
    ldpte $t0, 0
    #取回偶数号页表项
    ldpte $t0, 1
    #取回奇数号页表项
    tlbfill
    csrrd $t0, 0x8B
    #jr $ra
    ertn