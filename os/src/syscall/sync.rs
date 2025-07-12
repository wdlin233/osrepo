use super::process::TimeVal;
use crate::mm::translated_ref;
use crate::task::{block_current_and_run_next, current_task, current_user_token};
use crate::timer::{add_timer, get_time_ms};
use alloc::sync::Arc;
/// sleep syscall
pub fn sys_sleep(req: *const TimeVal) -> isize {
    // trace!(
    //     "kernel:pid[{}] tid[{}] sys_sleep",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     current_task()
    //         .unwrap()
    //         .inner_exclusive_access()
    //         .res
    //         .as_ref()
    //         .unwrap()
    //         .tid
    // );
    let re: TimeVal;
    let token = current_user_token();
    re = *translated_ref(token, req);
    //debug!("the expected sec is:{}",re.sec);
    let expire_ms = get_time_ms() + re.sec * 1000;
    let task = current_task().unwrap();
    add_timer(expire_ms, task);
    block_current_and_run_next();
    0
}