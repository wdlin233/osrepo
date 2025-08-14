use log::debug;

use super::options::SignalMaskFlag;
use crate::{
    mm::{translated_ref, translated_refmut},
    signal::{
        restore_frame, send_signal_to_thread, send_signal_to_thread_of_proc, KSigAction, SigAction,
        SigInfo, SignalFlags, SIG_MAX_NUM,
    },
    task::{current_process, current_task, exit_current_and_run_next},
    timer::TimeSpec,
    utils::SysErrNo,
};

pub fn sys_sig_return() -> isize {
    restore_frame()
}

pub fn sys_sigprocmask(how: u32, set: *const SignalFlags, old_set: *mut SignalFlags) -> isize {
    debug!("in sys sig proc mask");
    let process = current_process();
    let mut inner = process.inner_exclusive_access();
    let how = SignalMaskFlag::from_bits(how)
        .ok_or(SysErrNo::EINVAL)
        .unwrap();
    let token = inner.get_user_token();
    drop(inner);
    drop(process);
    let task = current_task().unwrap();
    let mut task_inner = task.inner_exclusive_access();
    if old_set as usize != 0 {
        *translated_refmut(token, old_set as *mut SignalFlags) = task_inner.sig_mask;
    }

    if set as usize != 0 {
        //let mask = unsafe { *set };
        let mask = *translated_ref(token, set);

        // let mut blocked = &mut task_inner.sig_mask;
        match how {
            SignalMaskFlag::SIG_BLOCK => task_inner.sig_mask |= mask,
            SignalMaskFlag::SIG_UNBLOCK => task_inner.sig_mask &= !mask,
            SignalMaskFlag::SIG_SETMASK => task_inner.sig_mask = mask,
            _ => return SysErrNo::EINVAL as isize,
        }
    }
    0
}

pub fn sys_sigaction(signo: usize, act: *const SigAction, old_act: *mut SigAction) -> isize {
    if signo > SIG_MAX_NUM {
        return SysErrNo::EINVAL as isize;
    }

    let process = current_process();
    let inner = process.inner_exclusive_access();
    if old_act as usize != 0 {
        let sig_act = inner.sig_table.action(signo).act;
        *translated_refmut(inner.get_user_token(), old_act) = sig_act;
    }
    if act as usize != 0 {
        //let new_act = data_flow!({ *act });
        let new_act = *translated_ref(inner.get_user_token(), act);
        let new_sig: KSigAction = if new_act.sa_handler == 0 {
            KSigAction::new(signo, false)
        } else if new_act.sa_handler == 1 {
            // 忽略
            KSigAction::ignore()
        } else {
            let customed = new_act.sa_handler != exit_current_and_run_next as usize;
            KSigAction {
                act: new_act,
                customed,
            }
        };
        inner.sig_table.set_action(signo, new_sig);
    }
    0
}

pub fn sys_sigtimedwait(
    _sig: *const SignalFlags,
    _info: *const SigInfo,
    _timeout: *const TimeSpec,
) -> isize {
    // fake implementation
    return 0;
}

pub fn sys_tkill(tid: usize, signo: usize) -> isize {
    let sig = SignalFlags::from_sig(signo);
    send_signal_to_thread(tid, sig);
    0
}

pub fn sys_tgkill(tgid: usize, tid: usize, signo: usize) -> isize {
    let sig = SignalFlags::from_sig(signo);
    send_signal_to_thread_of_proc(tgid, tid, sig);
    0
}
