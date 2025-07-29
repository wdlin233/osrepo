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
pub const TRAMPOLINE: usize = 0x0000_0000_ffff_ffff - PAGE_SIZE + 1;

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
pub const USER_HEAP_BOTTOM: usize = 0x100_0000;
///heap size
pub const USER_HEAP_SIZE: usize = 0x10_0000;

/// qemu board info
pub use crate::board::{CLOCK_FREQ, MMIO};
pub const UART: usize = 0x9000_0000_1FE0_01E0;

#[cfg(target_arch = "riscv64")]
/// physical memory end address
pub const MEMORY_END: usize = 0x8800_0000;
#[cfg(target_arch = "loongarch64")]
pub const MEMORY_END: usize = 0x9000_0000_8800_0000;

/// page size : 4KB
pub const PAGE_SIZE: usize = 0x1000;
/// page size bits: 12
pub const PAGE_SIZE_BITS: usize = 0xc;
/// user app's stack size
pub const USER_STACK_SIZE: usize = 4096 * 8;
/// kernel heap size
pub const KERNEL_HEAP_SIZE: usize = 0x200_0000;

#[cfg(target_arch = "loongarch64")]
pub const PALEN: usize = 48;
