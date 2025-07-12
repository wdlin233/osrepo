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

use crate::{config::KERNEL_ADDR_OFFSET, hal::{clear_bss, utils::console::CONSOLE}, signal::{send_signal_to_thread, SignalFlags}, syscall::syscall, task::{current_task, suspend_current_and_run_next}};
use config::FLAG;

use polyhal_trap::trap::TrapType::{self, *};
use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};
use polyhal_boot::define_entry;
use polyhal::percpu::get_local_thread_pointer;
use polyhal::{percpu, println};
use core::arch::{global_asm, asm};

#[polyhal::arch_interrupt]
fn kernel_interrupt(ctx: &mut TrapFrame, trap_type: TrapType) {
    trace!("trap_type @ {:x?} {:#x?}", trap_type, ctx);
    match trap_type {
        Breakpoint => return,
        SysCall => {
            // jump to next instruction anyway
            ctx.syscall_ok();
            let args = ctx.args();
            // get system call return value
            // info!("syscall: {}", ctx[TrapFrameArgs::SYSCALL]);

            let result = syscall(ctx[TrapFrameArgs::SYSCALL], [args[0], args[1], args[2], args[3], args[4], args[5]]);
            // cx is changed during sys_exec, so we have to call it again
            ctx[TrapFrameArgs::RET] = result as usize;
        }
        StorePageFault(_paddr) | LoadPageFault(_paddr) | InstructionPageFault(_paddr) => {
            /*
            println!(
                "[kernel] {:?} in application, bad addr = {:#x}, bad instruction = {:#x}, kernel killed it.",
                scause.cause(),
                stval,
                current_trap_cx().sepc,
            );
            */
            send_signal_to_thread(current_task().unwrap().gettid(), SignalFlags::SIGSEGV);
        }
        IllegalInstruction(_) => {
            send_signal_to_thread(current_task().unwrap().gettid(), SignalFlags::SIGILL);
        }
        Timer => {
            suspend_current_and_run_next();
        }
        _ => {
            warn!("unsuspended trap type: {:?}", trap_type);
        }
    }
    // // handle signals (handle the sent signal)
    // // println!("[K] trap_handler:: handle_signals");
    // handle_signals();

    // // check error signals (if error then exit)
    // if let Some((errno, msg)) = check_signals_error_of_current() {
    //     println!("[kernel] {}", msg);
    //     exit_current_and_run_next(errno);
    // }
}

#[no_mangle]
pub fn main(hartid: usize) -> ! {
    println!("{}", FLAG);
    println!("[kernel] Hello, world!");
    println!("cpu: {}", hartid);
    logging::init();
    log::error!("Logging init success");
    check_percpu(hartid);

    mm::init();

    fs::list_apps();
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