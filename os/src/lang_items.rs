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
    shutdown()
}
