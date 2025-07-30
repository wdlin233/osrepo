use super::main;
use core::arch::global_asm;

#[link_section = ".bss.stack"]
static mut BOOT_STACK: [u8; 4096 * 16] = [0; 4096 * 16];
const BOOT_STACK_SIZE: usize = 4096 * 16;

// 条件编译：RISC-V 启动代码
#[cfg(target_arch = "riscv64")]
global_asm!(
    r#"
    .section .text.entry
    .globl _start
_start:
    // csrr a0, 0x20 // 读取 cpuid
    la sp, boot_stack_top  
    call {rust_main} 

    .section .bss.stack
    .globl boot_stack_lower_bound
boot_stack_lower_bound:
    .space {boot_stack_size}
    .globl boot_stack_top
boot_stack_top:
    "#,
    boot_stack_size = const BOOT_STACK_SIZE,
    rust_main = sym super::main,
    //boot_stack_top = sym BOOT_STACK.as_ptr(),
);

/// The earliest entry point for the primary CPU.
///
/// We can't use bl to jump to higher address, so we use jirl to jump to higher
/// address.
#[cfg(target_arch = "loongarch64")]
global_asm!(
    r#"
    .section .text.entry
    .globl _start
_start:
    pcaddi      $t0,    0x0
    srli.d      $t0,    $t0,    0x30
    slli.d      $t0,    $t0,    0x30
    addi.d      $t0,    $t0,    0x11
    csrwr       $t0,    0x181   # Make sure the window remains the same after the switch.
    sub.d       $t0,    $t0,    $t0
    addi.d      $t0,    $t0,    0x11
    csrwr       $t0,    0x180
    pcaddi      $t0,    0x0
    slli.d      $t0,    $t0,    0x10
    srli.d      $t0,    $t0,    0x10
    jirl        $t0,    $t0,    0x10    # 跳0段的下一条指令
    # The barrier
    sub.d       $t0,    $t0,    $t0
    csrwr       $t0,    0x181
    sub.d       $t0,    $t0,    $t0
    la.global $sp, boot_stack_top
    bl          {rust_main}

    .section .bss.stack
    .globl boot_stack
boot_stack:
    .space {boot_stack_size}
    .globl boot_stack_top
boot_stack_top:
    "#,
    boot_stack_size = const BOOT_STACK_SIZE,
    rust_main = sym super::main
);
