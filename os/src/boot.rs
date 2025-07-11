use super::main;
use core::arch::global_asm;

#[link_section = ".bss.stack"]
static mut BOOT_STACK: [u8; 4096 * 16] = [0; 4096 * 16];
const BOOT_STACK_SIZE: usize = 4096 * 16;

// 条件编译：RISC-V 启动代码
//#[cfg(target_arch = "riscv64")]
global_asm!(
    r#"
    .section .text.entry
    .globl _start
_start:
    mv tp,a0
    slli t0, a0, 8  # t0 = hart_id << 16(4096 * 8)
    la sp, boot_stack_top
    sub sp, sp, t0  # sp = stack top - hart_id * stack_size

    la t0, boot_pagetable
    li t1, 8 << 60
    srli t0, t0, 12
    or t0, t0, t1
    csrw satp, t0
    sfence.vma

    call trampoline 

    .section .bss.stack
    .globl boot_stack_lower_bound
boot_stack_lower_bound:
    .space {boot_stack_size}
    
    .globl boot_stack_top
boot_stack_top:

.section .data
    .align 12
boot_pagetable:
    # we need 2 pte here
    # 0x0000_0000_8000_0000 -> 0x0000_0000_8000_0000
    # 0xffff_fc00_8000_0000 -> 0x0000_0000_8000_0000
    .quad 0
    .quad 0
    .quad (0x80000 << 10) | 0xcf # VRWXAD
    .zero 8 * 255
    .quad (0x80000 << 10) | 0xcf # VRWXAD
    .zero 8 * 253

    .section .text.trampoline
    .align 12
    .global sigreturn_trampoline
sigreturn_trampoline:
    li	a7,139
    ecall
    "#,
    boot_stack_size = const BOOT_STACK_SIZE,
    //rust_main = sym super::main,
    //boot_stack_top = sym BOOT_STACK.as_ptr(),
);

/// The earliest entry point for the primary CPU.
///
/// We can't use bl to jump to higher address, so we use jirl to jump to higher
/// address.
#[cfg(target_arch = "loongarch64")]
#[no_mangle]
#[link_section = ".text.entry"]
unsafe extern "C" fn _start() -> ! {
    core::arch::asm!(
        "
        // INIT_DMW
        ori         $t0, $zero, 0x1     # CSR_DMW1_PLV0
        lu52i.d     $t0, $t0, -2048     # UC, PLV0, 0x8000 xxxx xxxx xxxx
        csrwr       $t0, 0x180          # LOONGARCH_CSR_DMWIN0
        ori         $t0, $zero, 0x11    # CSR_DMW1_MAT | CSR_DMW1_PLV0
        lu52i.d     $t0, $t0, -1792     # CA, PLV0, 0x9000 xxxx xxxx xxxx
        csrwr       $t0, 0x181          # LOONGARCH_CSR_DMWIN1
        // addi.d    $t0, $zero,0x11
        // csrwr     $t0, 0x181               # LOONGARCH_CSR_DMWIN1

        // 启用分页 Enable PG
        li.w        $t0, 0xb0       # PLV=0, IE=0, PG=1
        csrwr       $t0, 0x0        # LOONGARCH_CSR_CRMD
        li.w        $t0, 0x00       # PLV=0, PIE=0, PWE=0
        csrwr       $t0, 0x1        # LOONGARCH_CSR_PRMD
        li.w        $t0, 0x00       # FPE=0, SXE=0, ASXE=0, BTE=0
        csrwr       $t0, 0x2        # LOONGARCH_CSR_EUEN

        la.global   $sp, {boot_stack}
        li.d        $t0, {boot_stack_size}
        add.d       $sp, $sp, $t0   // 设置启动栈 setup boot stack
        csrrd       $a0, 0x20       // 读取 cpuid 
        la.global   $t0, {main}
        jirl        $zero, $t0, 0   // 跳转到 main
        ",
        boot_stack = sym BOOT_STACK,
        boot_stack_size = const BOOT_STACK_SIZE,
        main = sym super::main,
        options(noreturn),
    )
}