//! Constants in the kernel

#[allow(unused)]

pub const FLAG: &str = r#"

   _____       __         __  _               
  / ___/__  __/ /_  _____/ /_(_)_  ______ ___ 
  \__ \/ / / / __ \/ ___/ __/ / / / / __ `__ \
 ___/ / /_/ / /_/ (__  ) /_/ / /_/ / / / / / /
/____/\__,_/_.___/____/\__/_/\__,_/_/ /_/ /_/                     

"#; // ANSI Shadow

/// The number of ticks per second
pub const TICKS_PER_SEC: usize = 100;
/// The number of milliseconds per second
pub const MSEC_PER_SEC: usize = 1000;
/// kernel stack size
pub const KERNEL_STACK_SIZE: usize = 4096 * 8;
/// kernel stack top address
pub const KSTACK_TOP: usize = 0x40_0000_0000 - PAGE_SIZE + 1;

pub const THREAD_MAX_NUM: usize = 3000;

pub const USER_SPACE_SIZE: usize = 0x30_0000_0000;

pub const USER_TRAP_CONTEXT_TOP: usize = USER_SPACE_SIZE;

pub const USER_STACK_TOP: usize = USER_TRAP_CONTEXT_TOP - PAGE_SIZE * THREAD_MAX_NUM;

pub const MMAP_TOP: usize = USER_TRAP_CONTEXT_TOP
    - PAGE_SIZE * THREAD_MAX_NUM
    - USER_STACK_SIZE * THREAD_MAX_NUM
    - PAGE_SIZE;
//heap bottom
pub const USER_HEAP_BOTTOM: usize = USER_STACK_TOP + PAGE_SIZE;
///heap size
pub const USER_HEAP_SIZE: usize = 0x10_0000;

/// qemu board info
pub use crate::board::{CLOCK_FREQ, MMIO};

pub const VIRT_BIAS: usize = 0x9000_0000_0000_0000; // virtual address bias for loongarch64
pub const UART: usize = 0x1FE001E0 + VIRT_BIAS;

//#[cfg(target_arch = "riscv64")]
/// physical memory end address, -m 1G
pub const MEMORY_END: usize = 0xC000_0000 + KERNEL_ADDR_OFFSET;
//#[cfg(target_arch = "riscv64")]
/// page size : 4KB
pub const PAGE_SIZE: usize = 0x1000;
//#[cfg(target_arch = "riscv64")]
/// page size bits: 12
pub const PAGE_SIZE_BITS: usize = 0xc;
//#[cfg(target_arch = "riscv64")]
/// user app's stack size
pub const USER_STACK_SIZE: usize = 4 * 1024 * 8;
//#[cfg(target_arch = "riscv64")]
/// kernel heap size
pub const KERNEL_HEAP_SIZE: usize = 0x200_0000;

#[cfg(target_arch = "loongarch64")]
pub const MEMORY_END: usize = 0x000000000_1000_0000 + VIRT_BIAS;
#[cfg(target_arch = "loongarch64")]
pub const PAGE_SIZE: usize = 0x4000; //16kB
#[cfg(target_arch = "loongarch64")]
pub const PAGE_SIZE_BITS: usize = 14; // 0xe
#[cfg(target_arch = "loongarch64")]
pub const PALEN: usize = 48;
#[cfg(target_arch = "loongarch64")]
pub const USER_STACK_SIZE: usize = PAGE_SIZE;
#[cfg(target_arch = "loongarch64")]
pub const KERNEL_HEAP_SIZE: usize = 0x1E0_0000; //内核的可分配堆大小3MB

pub const PRE_ALLOC_PAGES: usize = 8;
pub const DL_INTERP_OFFSET: usize = 0x15_0000_0000;

pub const KERNEL_ADDR_OFFSET: usize = 0xffff_ffc0_0000_0000;
pub const KERNEL_PGNUM_OFFSET: usize = KERNEL_ADDR_OFFSET >> PAGE_SIZE_BITS;
