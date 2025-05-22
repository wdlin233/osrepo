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

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

#[macro_use]
extern crate log;

extern crate alloc;

#[macro_use]
extern crate bitflags;

#[macro_use]
mod console;
pub mod config;
pub mod drivers;
pub mod fs;
pub mod lang_items;
pub mod logging;
pub mod mm;
pub mod sync;
pub mod syscall;
pub mod task;
pub mod timer;
pub mod loaders;

use polyhal::{common::PageAlloc, mem::get_mem_areas, PhysAddr};
//use polyhal::{common::PageAlloc, mem::get_mem_areas, PhysAddr};
use polyhal_boot::define_entry;
use polyhal_trap::{
    trap::TrapType::{self, *},
    trapframe::{TrapFrame, TrapFrameArgs},
};
use crate::{
    syscall::syscall,
    task::{
        check_signals_error_of_current, current_add_signal, exit_current_and_run_next,
        handle_signals, suspend_current_and_run_next, SignalFlags,
    },
};


/// kernel interrupt
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

            let result = syscall(ctx[TrapFrameArgs::SYSCALL], [args[0], args[1], args[2], args[3]]);
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
            current_add_signal(SignalFlags::SIGSEGV);
        }
        IllegalInstruction(_) => {
            current_add_signal(SignalFlags::SIGILL);
        }
        Timer => {
            suspend_current_and_run_next();
        }
        _ => {
            warn!("unsuspended trap type: {:?}", trap_type);
        }
    }
    // handle signals (handle the sent signal)
    // println!("[K] trap_handler:: handle_signals");
    handle_signals();

    // check error signals (if error then exit)
    if let Some((errno, msg)) = check_signals_error_of_current() {
        println!("[kernel] {}", msg);
        exit_current_and_run_next(errno);
    }
}

// fn clear_bss() {
//     extern "C" {
//         fn sbss();
//         fn ebss();
//     }
//     unsafe {
//         core::slice::from_raw_parts_mut(sbss as usize as *mut u8, ebss as usize - sbss as usize)
//             .fill(0);
//     }
// }

fn main(hartid: usize) {
    trace!("hartid: {}", hartid);
    if hartid != 0 {
        return;
    }
    //clear_bss();
    println!("[kernel] Hello, world!");
    mm::init_heap();
    logging::init();
    println!("init logging");
    // polyhal::init_interrupt(); done in polyhal::CPU::rust_main()

    polyhal::common::init(&PageAllocImpl);
    get_mem_areas().for_each(|(start, size)| {
        println!("init memory region {:#x} - {:#x}", start, start + size);
        mm::add_frames_range(*start, start + size);
    });

    fs::list_apps();
    task::init_kernel_page();
    task::add_initproc();
    task::run_tasks();
    panic!("Unreachable in main function of kernel!");
}

define_entry!(main);

pub struct PageAllocImpl;

impl PageAlloc for PageAllocImpl {
    #[inline]
    fn alloc(&self) -> PhysAddr {
        mm::frame_alloc_persist().expect("can't find memory page")
    }

    #[inline]
    fn dealloc(&self, paddr: PhysAddr) {
        mm::frame_dealloc(paddr)
    }
}