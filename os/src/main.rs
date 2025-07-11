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

use crate::{config::KERNEL_ADDR_OFFSET, hal::{clear_bss, utils::console::CONSOLE}};
use config::FLAG;
use polyhal_trap::{trap::TrapType, trapframe::TrapFrame};
use core::arch::{global_asm, asm};

#[polyhal::arch_interrupt]
fn kernel_interrupt(_ctx: &mut TrapFrame, _trap_type: TrapType) {
    // // trace!("trap_type @ {:x?} {:#x?}", trap_type, ctx);
    unimplemented!()
    // match trap_type {
    //     Breakpoint => return,
    //     SysCall => {
    //         // jump to next instruction anyway
    //         ctx.syscall_ok();
    //         let args = ctx.args();
    //         // get system call return value
    //         // info!("syscall: {}", ctx[TrapFrameArgs::SYSCALL]);

    //         let result = syscall(ctx[TrapFrameArgs::SYSCALL], [args[0], args[1], args[2]]);
    //         // cx is changed during sys_exec, so we have to call it again
    //         ctx[TrapFrameArgs::RET] = result as usize;
    //     }
    //     StorePageFault(_paddr) | LoadPageFault(_paddr) | InstructionPageFault(_paddr) => {
    //         /*
    //         println!(
    //             "[kernel] {:?} in application, bad addr = {:#x}, bad instruction = {:#x}, kernel killed it.",
    //             scause.cause(),
    //             stval,
    //             current_trap_cx().sepc,
    //         );
    //         */
    //         current_add_signal(SignalFlags::SIGSEGV);
    //     }
    //     IllegalInstruction(_) => {
    //         current_add_signal(SignalFlags::SIGILL);
    //     }
    //     Timer => {
    //         suspend_current_and_run_next();
    //     }
    //     _ => {
    //         warn!("unsuspended trap type: {:?}", trap_type);
    //     }
    // }
    // // handle signals (handle the sent signal)
    // // println!("[K] trap_handler:: handle_signals");
    // handle_signals();

    // // check error signals (if error then exit)
    // if let Some((errno, msg)) = check_signals_error_of_current() {
    //     println!("[kernel] {}", msg);
    //     exit_current_and_run_next(errno);
    // }
}

/// ADD KERNEL_ADDR_OFFSET and jump to rust_main
#[no_mangle]
pub fn trampoline(hartid: usize) {
    unsafe {
        asm!("add sp, sp, {}", in(reg) KERNEL_ADDR_OFFSET);
        asm!("la t0, main");
        asm!("add t0, t0, {}", in(reg) KERNEL_ADDR_OFFSET);
        asm!("mv a0, {}", in(reg) hartid);
        asm!("jalr zero, 0(t0)");
    }
}

#[no_mangle]
pub fn main(hartid: usize) -> ! {
    clear_bss();
    println!("{}", FLAG);
    println!("[kernel] Hello, world!");
    println!("cpu: {}", hartid);
    logging::init();
    log::error!("Logging init success");
    
    mm::init();
    #[cfg(target_arch = "riscv64")] 
    mm::remap_test();
    hal::trap::init();
    #[cfg(target_arch = "loongarch64")] 
    print_machine_info();
    hal::trap::enable_timer_interrupt();
    #[cfg(target_arch = "riscv64")] 
    timer::set_next_trigger();

    fs::list_apps();
    task::add_initproc();
    task::run_tasks();
    panic!("Unreachable section for kernel!");
}