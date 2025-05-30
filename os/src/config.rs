//! Constants in the kernel

#[allow(unused)]

pub const FLAG: &str = "
███████╗██╗   ██╗██████╗ ███████╗████████╗██╗██╗   ██╗███╗   ███╗
██╔════╝██║   ██║██╔══██╗██╔════╝╚══██╔══╝██║██║   ██║████╗ ████║
███████╗██║   ██║██████╔╝███████╗   ██║   ██║██║   ██║██╔████╔██║
╚════██║██║   ██║██╔══██╗╚════██║   ██║   ██║██║   ██║██║╚██╔╝██║
███████║╚██████╔╝██████╔╝███████║   ██║   ██║╚██████╔╝██║ ╚═╝ ██║
╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝     ╚═╝

"; // ANSI Shadow

/// The number of ticks per second
pub const TICKS_PER_SEC: usize = 100;
/// The number of milliseconds per second
pub const MSEC_PER_SEC: usize = 1000;
/// user app's stack size
pub const USER_STACK_SIZE: usize = 4096 * 2;
/// kernel stack size
pub const KERNEL_STACK_SIZE: usize = 4096 * 2;
/// kernel heap size
pub const KERNEL_HEAP_SIZE: usize = 0x200_0000;
/// the virtual addr of trapoline
pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
/// the virtual addr of trap context
pub const TRAP_CONTEXT_BASE: usize = TRAMPOLINE - PAGE_SIZE;
/// qemu board info
pub use crate::board::{CLOCK_FREQ, MMIO};

pub const VIRT_BIAS: usize = 0x9000000000000000;
pub const UART: usize = 0x1FE001E0 + VIRT_BIAS;

#[cfg(target_arch = "riscv64")]
/// physical memory end address
pub const MEMORY_END: usize = 0x88000000;
#[cfg(target_arch = "riscv64")]
/// page size : 4KB
pub const PAGE_SIZE: usize = 0x1000;
#[cfg(target_arch = "riscv64")]
/// page size bits: 12
pub const PAGE_SIZE_BITS: usize = 0xc;

#[cfg(target_arch = "loongarch64")]
pub const MEMORY_END: usize = 0x000000000_1000_0000 + VIRT_BIAS;
#[cfg(target_arch = "loongarch64")]
pub const PAGE_SIZE: usize = 0x4000; //16kB
#[cfg(target_arch = "loongarch64")]
pub const PAGE_SIZE_BITS: usize = 14; // 0xe
#[cfg(target_arch = "loongarch64")]
pub const PALEN: usize = 48;