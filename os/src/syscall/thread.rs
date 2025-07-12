use crate::{
    hal::trap::{trap_handler},
    task::{add_task, current_task},
};
use alloc::sync::Arc;
/// get current thread id syscall
pub fn sys_gettid() -> isize {
    current_task()
        .unwrap()
        .gettid() as isize
}