//! The main module and entrypoint
//!
//! Various facilities of the kernels are implemented as submodules. The most
//! important ones are:
//!
//! - [`trap`]: Handles all cases of switching from userspace to the kernel
//! - [`task`]: Task management
//! - [`syscall`]: System call handling and implementation
//! - [`mm`]: Address map using SV39
//! - [`sync`]: Wrap a static data structure inside it so that we are able to access it without any `unsafe`.
//! - [`fs`]: Separate user from file system with some structures
//!
//! The operating system also starts in this module. Kernel code starts
//! executing from `entry.asm`, after which [`rust_main()`] is called to
//! initialize various pieces of functionality. (See its source code for
//! details.)
//!
//! We then call [`task::run_tasks()`] and for the first time go to
//! userspace.

#![allow(missing_docs)]
#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![feature(naked_functions)]

#[macro_use]
extern crate log;

extern crate alloc;

#[macro_use]
extern crate bitflags;

#[path = "boards/qemu.rs"]
mod board;

#[macro_use]
pub mod config;
pub mod boot; // used to set up the initial environment
pub mod drivers;
pub mod fs;
pub mod hal;
pub mod lang_items;
pub mod logging;
pub mod mm;
pub mod signal;
pub mod sync;
pub mod syscall;
pub mod task;
pub mod timer;
pub mod utils;

#[cfg(target_arch = "loongarch64")]
use crate::{
    hal::arch::info::{kernel_layout, print_machine_info},
    hal::trap::{enable_timer_interrupt, init},
    task::add_initproc,
};
pub mod system;
pub mod users;

use crate::{config::VIRT_ADDR_OFFSET, hal::utils::console::CONSOLE};
use config::FLAG;
use core::arch::{asm, global_asm};

pub fn clear_bss() {
    extern "C" {
        fn sbss();
        fn ebss();
    }
    unsafe {
        core::slice::from_raw_parts_mut(
            sbss as usize as *mut u128, 
            (ebss as usize - sbss as usize) / core::mem::size_of::<u128>(),
        )
        .fill(0);
    }
}

#[no_mangle]
pub fn main(cpu: usize) -> ! {
    clear_bss();
    println!("{}", FLAG);
    println!("[kernel] Hello, world!");
    println!("cpu: {}", cpu);
    logging::init();
    log::error!("Logging init success");

    mm::init();
    info!("Memory management initialized");
    hal::trap::init();
    #[cfg(target_arch = "loongarch64")]
    print_machine_info();
    hal::trap::enable_timer_interrupt();
    #[cfg(target_arch = "riscv64")]
    timer::set_next_trigger();

    fs::list_apps();
    task::add_initproc();
    //fs::init();

    task::run_tasks();
    panic!("Unreachable section for kernel!");
}
