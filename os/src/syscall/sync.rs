use super::process::TimeVal;
use crate::mm::translated_ref;
use crate::task::{block_current_and_run_next, current_task};
use crate::timer::{add_futex_timer, get_time_ms};
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
    re = *translated_ref(req);
    //debug!("the expected sec is:{}",re.sec);
    let expire_ms = get_time_ms() + re.sec * 1000;
    let task = current_task().unwrap();
    add_futex_timer(expire_ms, task);
    block_current_and_run_next();
    0
}