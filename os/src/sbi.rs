//! SBI call wrappers

#![allow(unused)]

use core::arch::asm;
/// set timer sbi call id
const SBI_SET_TIMER: usize = 0x54494D45;
/// console putchar sbi call id
const SBI_CONSOLE_PUTCHAR: usize = 1;
/// console getchar sbi call id
const SBI_CONSOLE_GETCHAR: usize = 2;
/// shutdown sbi call id
const SBI_SHUTDOWN: usize = 0x53525354;

/// general sbi call
#[inline(always)]
#[cfg(target_arch = "riscv64")]
fn sbi_call(which: usize, arg0: usize, arg1: usize, arg2: usize) -> usize {
    let mut ret;
    unsafe {
        asm!(
            "ecall",     // sbi call
            inlateout("x10") arg0 => ret, // sbi call arg0 and return value
            in("x11") arg1, // sbi call arg1
            in("x12") arg2, // sbi call arg2
            in("x16") 0, // for sbi call id args need 2 reg (x16, x17)
            in("x17") which,// sbi call id
        );
    }
    ret
}

/// use sbi call to set timer
#[cfg(target_arch = "riscv64")]
pub fn set_timer(timer: usize) {
    sbi_call(SBI_SET_TIMER, timer, 0, 0);
}

/// use sbi call to putchar in console (qemu uart handler)
#[cfg(target_arch = "riscv64")]
pub fn console_putchar(c: usize) {
    sbi_call(SBI_CONSOLE_PUTCHAR, c, 0, 0);
}

/// use sbi call to getchar from console (qemu uart handler)
#[cfg(target_arch = "riscv64")]
pub fn console_getchar() -> usize {
    sbi_call(SBI_CONSOLE_GETCHAR, 0, 0, 0)
}

/// use sbi call to shutdown the kernel
#[cfg(target_arch = "riscv64")]
pub fn shutdown() -> ! {
    sbi_call(SBI_SHUTDOWN, 0, 0, 0);
    panic!("It should shutdown!");
}

#[cfg(target_arch = "loongarch64")]
#[no_mangle]
pub(crate) extern "C" fn shutdown() -> ! {
    loop {
        unsafe {
            asm!("idle 0");
        }
    }
}

#[cfg(target_arch = "loongarch64")]
pub fn console_putchar(_c: usize) {
    // You can implement UART output for loongarch64 here if needed
    unimplemented!()
}

#[cfg(target_arch = "loongarch64")]
pub fn console_getchar() -> usize {
    // You can implement UART input for loongarch64 here if needed
    0
}

#[cfg(target_arch = "loongarch64")]
pub fn set_timer(_timer: usize) {
    // Timer not implemented for loongarch64
    unimplemented!()
}