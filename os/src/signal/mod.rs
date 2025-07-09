pub mod sigact;
pub mod signal;

use core::mem::size_of;

use alloc::sync::Arc;
use log::debug;
use polyhal_trap::trapframe::TrapFrameArgs;
use crate::hal::trap::context::MachineContextConversion;
pub use sigact::*;
pub use signal::*;

#[cfg(target_arch = "loongarch64")]
use loongarch64::register::estat::{Exception, Trap};
#[cfg(target_arch = "riscv64")]
use riscv::register::scause::{self, Exception, Trap};

use crate::{
    config::USER_STACK_SIZE, hal::trap::{MachineContext, UserContext}, mm::translated_refmut, task::{
        current_task, exit_current_and_run_next, ProcessControlBlock, THREAD_GROUP, TID_TO_TASK
        //    THREAD_GROUP, TID_TO_TASK
    }, utils::{SysErrNo, SyscallRet}
};

pub const SIG_MAX_NUM: usize = 33;
pub const SIG_ERR: usize = usize::MAX;
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

extern "C" {
    pub fn sigreturn_trampoline();
}

pub fn check_if_any_sig_for_current_task() -> Option<usize> {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();

    inner.sig_pending
        .difference(inner.sig_mask) // 差集，待处理且没有被阻塞的信号
        .peek_front()
}

pub fn handle_signal(signo: usize) {
    let process = current_task().unwrap();
    let mut inner = process.inner_exclusive_access();
    let signal = SignalFlags::from_sig(signo);
    debug!("[handle_signal] signo={},handle signal {:?}", signo, signal);
    let sig_action = inner.sig_table.action(signo);
    inner.sig_pending.remove(signal);
    drop(inner);
    drop(process);
    if sig_action.customed {
        setup_frame(signo, sig_action);
    } else {
        debug!("sa_handler:{:#x}", sig_action.act.sa_handler as usize);
        // 就在S模式运行,转换成fn(i32)
        if sig_action.act.sa_handler != 1 {
            if sig_action.act.sa_handler == exit_current_and_run_next as usize {
                exit_current_and_run_next((signo + 128) as i32);
            }
        }
    }
}
/// 在用户态栈空间构建一个 Frame
/// 构建这个帧的目的就是为了执行完信号处理程序后返回到内核态，
/// 并恢复原来内核栈的内容
pub fn setup_frame(signo: usize, sig_action: KSigAction) {
    debug!("customed sa_handler={:#x}", sig_action.act.sa_handler);

    let process = current_task().unwrap();
    let mut inner = process.inner_exclusive_access();

    let trap_cx = inner.get_trap_cx();
    let mut user_sp = trap_cx[TrapFrameArgs::SP];

    // if this syscall wants to restart
    if scause::read().cause() == Trap::Exception(Exception::UserEnvCall)
        && trap_cx[TrapFrameArgs::ARG0] == SysErrNo::ERESTART as usize // a0
    {
        // and if `SA_RESTART` is set
        if sig_action.act.sa_flags.contains(SigActionFlags::SA_RESTART) {
            debug!("[do_signal] syscall will restart after sigreturn");
            // back to `ecall`
            trap_cx[TrapFrameArgs::SEPC] -= 4;
            // restore syscall parameter `a0`
            unimplemented!("syscall restart not implemented yet");
            //trap_cx[TrapFrameArgs::ARG0] = trap_cx.origin_a0;
        } else {
            debug!("[do_signal] syscall was interrupted");
            // will return EINTR after sigreturn
            trap_cx[TrapFrameArgs::ARG0] = SysErrNo::EINTR as usize;
        }
    }

    let token = inner.memory_set.token();
    if !sig_action.act.sa_flags.contains(SigActionFlags::SA_SIGINFO) {
        // 处理函数 (*sa_handler)(int);
        // 保存 Trap 上下文
        user_sp = user_sp - size_of::<MachineContext>();
        *translated_refmut(token, user_sp as *mut MachineContext) = trap_cx.as_mctx();
        
        // signal mask
        user_sp = user_sp - size_of::<SignalFlags>();
        *translated_refmut(token, user_sp as *mut SignalFlags) = inner.sig_mask;
        
        // 不是 sigInfo
        user_sp = user_sp - size_of::<usize>();
        *translated_refmut(token, user_sp as *mut usize) = 0;
    } else {
        // (*sa_sigaction)(int, siginfo_t *, void *) 第三个参数指向UserContext
        let uctx_addr = user_sp - size_of::<UserContext>();
        let siginfo_addr = uctx_addr - size_of::<SigInfo>();
        let sig_sp = siginfo_addr;
        let sig_size = sig_sp - (inner.user_stack_top - USER_STACK_SIZE);
        // debug!("sig_size={:#x}", sig_size);
        *translated_refmut(token, uctx_addr as *mut UserContext) = UserContext {
            flags: 0,
            link: 0,
            stack: SignalStack::new(sig_sp, sig_size),
            sigmask: inner.sig_mask,
            __pad: [0u8; 128],
            mcontext: trap_cx.as_mctx(),
        };
        // a2
        trap_cx[TrapFrameArgs::ARG2] = uctx_addr;
        *translated_refmut(token, siginfo_addr as *mut SigInfo) = SigInfo::new(signo, 0, 0);
        // a1
        trap_cx[TrapFrameArgs::ARG1] = siginfo_addr;

        user_sp = sig_sp;
        // 是 sigInfo
        user_sp = user_sp - size_of::<usize>();
        *translated_refmut(token, user_sp as *mut usize) = usize::MAX; 
    }

    // checkout(Magic Num)
    user_sp -= size_of::<usize>();
    *translated_refmut(token, user_sp as *mut usize) = 0xdeadbeef;
    // a0
    trap_cx[TrapFrameArgs::ARG0] = signo;
    // sp
    trap_cx[TrapFrameArgs::SP] = user_sp;
    // 修改Trap
    trap_cx[TrapFrameArgs::SEPC] = sig_action.act.sa_handler;
    // ra
    trap_cx[TrapFrameArgs::RA] = if sig_action
        .act
        .sa_flags
        .contains(SigActionFlags::SA_RESTORER)
    {
        sig_action.act.sa_restore
    } else {
        sigreturn_trampoline as usize
    };
    inner.sig_mask |= sig_action.act.sa_mask | SignalFlags::from_sig(signo);
}
/// 恢复栈帧
pub fn restore_frame() -> SyscallRet {
    let process = current_task().unwrap();
    let mut inner = process.inner_exclusive_access();

    let trap_cx = inner.get_trap_cx();
    let mut user_sp = trap_cx[TrapFrameArgs::SP];

    let token = inner.memory_set.token();
    let checkout = *translated_refmut(token, user_sp as *mut usize);
    assert!(checkout == 0xdeadbeef, "restore frame checkout error!");
    user_sp += size_of::<usize>();

    // sigInfo标志位
    let sa_siginfo = *translated_refmut(token, user_sp as *mut usize) == usize::MAX;
    user_sp += size_of::<usize>();

    if !sa_siginfo {
        // signal mask
        // inner.sig_mask = get_data(token, user_sp as *const SignalFlags);
        inner.sig_mask = *translated_refmut(token, user_sp as *mut SignalFlags);
        user_sp += size_of::<SignalFlags>();
        // Trap cx
        let mctx = *translated_refmut(token, user_sp as *mut MachineContext);
        trap_cx.copy_from_mctx(mctx);
    } else {
        user_sp += size_of::<SigInfo>();
        let base_ptr = user_sp as *const SignalFlags;
        let offset_bytes_mask = 2 * size_of::<usize>() + size_of::<SignalStack>();
        inner.sig_mask = *translated_refmut(
            token,
            unsafe {
                base_ptr.byte_add(offset_bytes_mask) as *mut SignalFlags
            }
        );
        let offset_bytes_mctex = 2 * size_of::<usize>()
                + size_of::<SignalStack>()
                + size_of::<SignalFlags>()
                + 128;
        let mctx = *translated_refmut(
            token,
            unsafe {
                base_ptr.byte_add(offset_bytes_mctex) as *mut MachineContext
            }
        );
        trap_cx.copy_from_mctx(mctx);
    }
    debug!("[restore_frame!] sepc= {:#x}", trap_cx.sepc);
    Ok(trap_cx[TrapFrameArgs::ARG0])
}

/// 向当前进程添加信号，加至 sig_pending 中
pub fn add_signal(process: Arc<ProcessControlBlock>, signal: SignalFlags) {
    let mut inner = process.inner_exclusive_access();
    inner.sig_pending |= signal;
}
/// 向线程组中的所有进程添加信号
pub fn send_signal_to_thread_group(pid: usize, sig: SignalFlags) {
    let thread_group = THREAD_GROUP.exclusive_access();
    if let Some(processes) = thread_group.get(&pid) {
        for process in processes.iter() {
            add_signal(process.clone(), sig);
        }
    }
}

pub fn send_signal_to_thread(tid: usize, sig: SignalFlags) {
    let pid2pcb = TID_TO_TASK.exclusive_access();
    if let Some(process) = pid2pcb.get(&tid) {
        add_signal(Arc::clone(process), sig);
    }
}

pub fn send_signal_to_thread_of_proc(pid: usize, tid: usize, sig: SignalFlags) {
    let pid2pcb = TID_TO_TASK.exclusive_access();
    if let Some(task) = pid2pcb.get(&tid) {
        if task.getpid() == pid {
            add_signal(Arc::clone(task), sig);
        }
    }
}

// 目前的进程组只是一个进程的所有子进程的集合
pub fn send_signal_to_process_group(_pid: usize, _sig: SignalFlags) {
    todo!()
}

/// 向除自身以及 `init` 进程之外的所有进程发送信号
pub fn send_access_signal(tid: usize, sig: SignalFlags) {
    TID_TO_TASK.exclusive_access()
        .iter()
        .filter(|(k, _)| **k != tid && **k != 0)
        .for_each(|(_, task)| add_signal(task.clone(), sig));
}
