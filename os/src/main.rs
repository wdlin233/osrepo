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
pub mod drivers;
pub mod fs;
pub mod lang_items;
pub mod logging;
pub mod mm;
pub mod signal;
pub mod sync;
pub mod syscall;
pub mod system;
pub mod task;
pub mod timer;
pub mod trap;
pub mod users;
pub mod utils;

use crate::{
    config::KERNEL_ADDR_OFFSET,
    syscall::syscall,
    task::{current_task, suspend_current_and_run_next},
};
use config::FLAG;

use core::arch::{asm, global_asm, naked_asm};
use polyhal::percpu::get_local_thread_pointer;
use polyhal::{percpu, println};
use polyhal_boot::define_entry;
use polyhal_trap::trap::TrapType::{self, *};
use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};

#[no_mangle]
pub fn main(hartid: usize) -> ! {
    println!("{}", FLAG);
    println!("[kernel] Hello, world!");
    println!("cpu: {}", hartid);
    logging::init();
    log::error!("Logging init success");
    check_percpu(hartid);

    mm::init();
    fs::init();
    fs::list_apps();

    task::init_kernel_page();
    task::add_initproc();
    task::run_tasks();
    panic!("Unreachable section for kernel!");
}

#[percpu]
static mut TEST_PERCPU: usize = 0;

fn check_percpu(hartid: usize) {
    log::debug!(
        "hart {} percpu base: {:#x}",
        hartid,
        get_local_thread_pointer()
    );
    assert_eq!(*TEST_PERCPU, 0);
    *TEST_PERCPU.ref_mut() = hartid;
    assert_eq!(*TEST_PERCPU, hartid);
}

fn secondary(hartid: usize) {
    check_percpu(hartid);
    println!("Secondary Hart ID: {}", hartid);
    loop {}
}

define_entry!(main, secondary);
