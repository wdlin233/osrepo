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
/// the virtual addr of trapoline
pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;

pub const THREAD_MAX_NUM: usize = 3000;
// 0x40_0000_0000 即 256GiB，低位地址空间的最高地址，但是不影响
pub const USER_SPACE_SIZE: usize = 0x5000_0000;

/*
------------------------------
    ...
    ...
    ...
    -----------------
    user1's heap size
-------------------------------heap_bottom
    guard page
--------------------------------user_trap_context_top
    guard page
    --------------------
    user1's trap context
    --------------------
    guard page
    --------------------
    user2's trap context
    ...
    ...
    ...
-----------------------------user_stack_top
    guard page
    ---------------
    user1's stack
    ---------------
    guard page
    ---------------
    user2's stack
    ...
    ...
    ...
------------------------------





*/

pub const USER_TRAP_CONTEXT_TOP: usize = USER_SPACE_SIZE;

pub const USER_STACK_TOP: usize = USER_TRAP_CONTEXT_TOP - PAGE_SIZE * THREAD_MAX_NUM;

pub const MMAP_TOP: usize = USER_TRAP_CONTEXT_TOP
    - PAGE_SIZE * THREAD_MAX_NUM
    - USER_STACK_SIZE * THREAD_MAX_NUM
    - PAGE_SIZE;
//heap bottom
pub const USER_HEAP_BOTTOM: usize = USER_TRAP_CONTEXT_TOP + PAGE_SIZE;
///heap size
pub const USER_HEAP_SIZE: usize = 0x10_0000;

/// qemu board info
pub use crate::board::{CLOCK_FREQ, MMIO};

pub const VIRT_BIAS: usize = 0x9000_0000_0000_0000; // virtual address bias for loongarch64
pub const UART: usize = 0x1FE001E0 + VIRT_BIAS;

#[cfg(target_arch = "riscv64")]
/// physical memory end address
pub const MEMORY_END: usize = 0x8800_0000;
#[cfg(target_arch = "riscv64")]
/// page size : 4KB
pub const PAGE_SIZE: usize = 0x1000;
#[cfg(target_arch = "riscv64")]
/// page size bits: 12
pub const PAGE_SIZE_BITS: usize = 0xc;
#[cfg(target_arch = "riscv64")]
/// user app's stack size
pub const USER_STACK_SIZE: usize = 4096 * 8;
#[cfg(target_arch = "riscv64")]
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

/// yield wakeup task
pub const YIELD_CHECK: usize = 90;
#[allow(unused)]
/// Use a fs block size of 512 bytes
pub const BLOCK_SIZE: usize = 4096;
/// The io block size of the disk layer
pub const IO_BLOCK_SIZE: usize = 512;
