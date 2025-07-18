use polyhal::{println, VirtAddr};
use polyhal_trap::{
    trap::{
        run_user_task,
        TrapType::{self, *},
    },
    trapframe::{TrapFrame, TrapFrameArgs},
};

use crate::{
    signal::{
        check_if_any_sig_for_current_task, handle_signal, send_signal_to_thread, SignalFlags,
        SignalStack,
    },
    syscall::syscall,
    task::{
        current_task, current_trap_cx, exit_current_and_run_next, suspend_current_and_run_next,
    },
    timer::get_time,
};

/// trap entry for TaskContext
#[no_mangle]
pub fn trap_entry() {
    info!("(trap_entry) into trap entry");
    loop {
        // if let Some(signo) = check_if_any_sig_for_current_task() {
        //     debug!("(trap_entry) found signo in trap_return");
        //     handle_signal(signo);
        // }
        let ctx = current_trap_cx();
        run_user_task(ctx);
    }
}

/// TrapContext or TrapFrame entry
#[polyhal::arch_interrupt]
fn kernel_interrupt(ctx: &mut TrapFrame, trap_type: TrapType) {
    trace!("trap_type @ {:x?} {:#x?}", trap_type, ctx);
    // let in_kernel_time = get_time();
    // current_task()
    //     .unwrap()
    //     .inner_exclusive_access()
    //     .set_utime(in_kernel_time);

    match trap_type {
        Breakpoint => return,
        SysCall => {
            // jump to next instruction anyway
            debug!("in  trap, to syscall");
            ctx.syscall_ok();
            let args = ctx.args();
            // get system call return value
            // info!("syscall: {}", ctx[TrapFrameArgs::SYSCALL]);

            let result = syscall(
                ctx[TrapFrameArgs::SYSCALL],
                [args[0], args[1], args[2], args[3], args[4], args[5]],
            );
            // cx is changed during sys_exec, so we have to call it again
            ctx[TrapFrameArgs::RET] = result as usize;
        }
        StorePageFault(paddr) | LoadPageFault(paddr) | InstructionPageFault(paddr) => {
            let mut res: bool;
            {
                debug!("in page fault trap");
                let process = current_task().unwrap();
                let inner = process.inner_exclusive_access();
                debug!("233");
                res = inner
                    .memory_set
                    .lazy_page_fault(VirtAddr::from(paddr).floor(), trap_type);
                if !res {
                    res = inner
                        .memory_set
                        .cow_page_fault(VirtAddr::from(paddr).floor(), trap_type);
                }
            }
            if !res {
                error!(
                    "[kernel] trap_handler: bad paddr = {:#x}, kernel killed it.",
                    paddr,
                );
                send_signal_to_thread(current_task().unwrap().gettid(), SignalFlags::SIGSEGV);
            }
        }
        IllegalInstruction(_) => {
            debug!("in trap, illegal instruction");
            send_signal_to_thread(current_task().unwrap().gettid(), SignalFlags::SIGILL);
            exit_current_and_run_next(-3);
        }
        Timer => {
            suspend_current_and_run_next();
        }
        _ => {
            warn!("unsuspended trap type: {:?}", trap_type);
            exit_current_and_run_next(-2);
        }
    }

    // handle signals (handle the sent signal)
    // println!("[K] trap_handler:: handle_signals");
    if let Some(signo) = check_if_any_sig_for_current_task() {
        info!("(kernel_interrupt) Handle signal");
        handle_signal(signo, trap_type);
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct MachineContext {
    gp: [usize; 32],
    //pub fp: [usize; 32],
    //pub fcsr: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UserContext {
    pub flags: usize,
    pub link: usize,
    pub stack: SignalStack,
    pub sigmask: SignalFlags,
    pub __pad: [u8; 128],
    pub mcontext: MachineContext,
}

pub trait MachineContextConversion {
    fn as_mctx(&self) -> MachineContext;
    fn copy_from_mctx(&mut self, mctx: MachineContext);
}

impl MachineContextConversion for TrapFrame {
    #[inline]
    fn as_mctx(&self) -> MachineContext {
        let mut x = [0; 32];
        x.copy_from_slice(&self.x);
        x[0] = self.sepc; // x0 寄存器永远为0,暂时借用一下,用于保存sepc
        MachineContext { gp: self.x }
    }

    #[inline]
    fn copy_from_mctx(&mut self, mctx: MachineContext) {
        self.x.copy_from_slice(&mctx.gp);
        self.sepc = self.x[0];
        self.x[0] = 0; // x0 寄存器永远为0,清除 sepc
    }
}
