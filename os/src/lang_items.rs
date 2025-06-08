//! The panic handler and backtrace

use crate::hal::utils::shutdown;
use core::arch::asm;
use core::panic::PanicInfo;
    use crate::println;

#[panic_handler]
/// panic handler
fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        println!(
            "[kernel] Panicked at {}:{} {}",
            location.file(),
            location.line(),
            info.message()
        );
    } else {
        println!("[kernel] Panicked: {}", info.message());
    }
    // unsafe {
    //     backtrace();
    // }
    shutdown()
}
/// backtrace function
#[allow(unused)]
#[cfg(target_arch = "riscv64")]
unsafe fn backtrace() {
    use crate::task::current_kstack_top;
    let mut fp: usize;
    let stop = current_kstack_top();
    asm!("mv {}, s0", out(reg) fp);
    println!("---START BACKTRACE---");
    for i in 0..10 {
        if fp == stop {
            break;
        }
        println!("#{}:ra={:#x}", i, *((fp - 8) as *const usize));
        fp = *((fp - 16) as *const usize);
    }
    println!("---END   BACKTRACE---");
}
