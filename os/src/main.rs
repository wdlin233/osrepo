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
#![deny(warnings)]
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
mod console;
pub mod config;
pub mod drivers;
pub mod fs;
pub mod lang_items;
pub mod logging;
pub mod mm;
pub mod sbi;
pub mod sync;
pub mod syscall;
pub mod task;
pub mod timer;
pub mod trap;
pub mod hal;
#[cfg(target_arch = "loongarch64")]
mod loongarch;
#[cfg(target_arch = "loongarch64")]
pub mod boot;
#[cfg(target_arch = "loongarch64")]
use crate::{
    trap::enable_timer_interrupt,
    task::add_initproc,
};

use core::arch::global_asm;
use crate::console::CONSOLE;
use config::FLAG;
use crate::hal::{
    clear_bss,
};
#[cfg(target_arch = "loongarch64")]
use crate::hal::{
    info::{print_machine_info, kernel_layout},
};

#[cfg(target_arch = "riscv64")]
global_asm!(include_str!("entry.asm"));


#[cfg(target_arch = "riscv64")]
#[no_mangle]
/// the rust entry-point of os
pub fn rust_main() -> ! {
    clear_bss();
    println!("{}", FLAG);
    println!("[kernel] Hello, world!");
    logging::init();
    mm::init();
    mm::remap_test();
    trap::init();
    trap::enable_timer_interrupt();
    timer::set_next_trigger();
    fs::list_apps();
    task::add_initproc();
    task::run_tasks();
    panic!("Unreachable in rust_main!");
}

#[cfg(target_arch = "loongarch64")]
#[no_mangle]
fn main(cpu: usize) {
    use fs::list_apps;
    use task::add_initproc;

    clear_bss();
    println!("{}", FLAG);
    println!("[kernel] Hello, world!");
    println!("cpu: {}", cpu);
    logging::init();
    log::error!("Logging init success");
    // rtc_init(); println!("CURRENT TIME {:?}", rtc_time_read());
    kernel_layout();

    mm::init();
    trap::init();
    print_machine_info();
    println!("machine info success");
    // sata 硬盘 ahci_init()

    enable_timer_interrupt();
    list_apps();
    add_initproc();   
    task::run_tasks();
    panic!("Unreachable section for loongarch64");
}