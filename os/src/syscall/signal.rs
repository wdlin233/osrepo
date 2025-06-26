use log::debug;

use super::options::SignalMaskFlag;
use crate::{
    mm::{translated_ref, translated_refmut},
    signal::SignalFlags,
    task::current_process,
    utils::SysErrNo,
};

pub fn sys_sigprocmask(how: u32, set: *const SignalFlags, old_set: *mut SignalFlags) -> isize {
    debug!("in sys sig proc mask");
    let process = current_process();
    let mut inner = process.inner_exclusive_access();
    let how = SignalMaskFlag::from_bits(how)
        .ok_or(SysErrNo::EINVAL)
        .unwrap();

    if old_set as usize != 0 {
        *translated_refmut(inner.get_user_token(), old_set as *mut SignalFlags) = inner.sig_mask;
    }
    if set as usize != 0 {
        //let mask = unsafe { *set };
        let mask = *translated_ref(inner.get_user_token(), set);
        // let mut blocked = &mut task_inner.sig_mask;
        match how {
            SignalMaskFlag::SIG_BLOCK => inner.sig_mask |= mask,
            SignalMaskFlag::SIG_UNBLOCK => inner.sig_mask &= !mask,
            SignalMaskFlag::SIG_SETMASK => inner.sig_mask = mask,
            _ => return SysErrNo::EINVAL as isize,
        }
    }
    0
}
