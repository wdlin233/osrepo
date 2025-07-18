//! Implementation of process [`ProcessControlBlock`] and task(thread) management mechanism
//!
//! Here is the entry for task scheduling required by other modules
//! (such as syscall or clock interrupt).
//! By suspending or exiting the current task, you can
//! modify the task state, manage the task queue through TASK_MANAGER (in task/manager.rs) ,
//! and switch the control flow through PROCESSOR (in task/processor.rs) .
//!
//! Be careful when you see [`__switch`]. Control flow around this function
//! might not be what you expect.

mod aux;
mod alloc;
mod manager;
mod process;
mod processor;
mod stride;
mod futex;

use crate::fs::{open, OpenFlags, NONE_MODE};
use crate::println;
use crate::task::manager::{add_stopping_task, insert_into_tid2task, wakeup_parent};
use crate::task::process::TaskStatus;
use crate::timer::remove_timer;
use crate::alloc::{sync::Arc, vec::Vec};
use lazy_static::*;
use manager::fetch_task;
use polyhal::kcontext::KContext;
use spin::Lazy;

use crate::signal::{send_signal_to_thread_group, SignalFlags};
pub use aux::{Aux, AuxType};
pub use alloc::{pid_alloc, KernelStack, PidHandle};
pub use manager::{
    add_block_task, add_task, tid2task, process_num, remove_from_tid2task, remove_task,
    wakeup_task, wakeup_task_by_pid, THREAD_GROUP, PROCESS_GROUP, insert_into_process_group,
    insert_into_thread_group, move_child_process_to_init, remove_all_from_thread_group,
    TID_TO_TASK, wakeup_futex_task,
};
pub use process::{
    ProcessControlBlock, ProcessControlBlockInner, RobustList, Tms, TmsInner,
};
pub use processor::{
    current_task, current_trap_cx, mmap, munmap, run_tasks,
    schedule, take_current_task, init_kernel_page
};
pub use futex::{FutexKey, futex_wait, futex_wake_up, futex_requeue};

use core::arch::{asm, global_asm};
use core::sync::atomic::AtomicU32;

/// Make current task suspended and switch to the next task
pub fn suspend_current_and_run_next() {
    info!("(suspend_current_and_run_next) suspending current task and running next task");
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- access current TCB exclusively
    let mut task_inner = task.inner_exclusive_access();
    let task_cx_ptr = &mut task_inner.task_cx as *mut KContext;
    // Change status to Ready
    task_inner.task_status = TaskStatus::Ready;
    drop(task_inner);
    // ---- release current TCB

    // push back to ready queue.
    add_task(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr);
}

/// Make current task blocked and switch to the next task.
pub fn block_current_and_run_next() {
    info!("(block_current_and_run_next) blocking current task and running next task");
    let task = take_current_task().unwrap();
    let mut task_inner = task.inner_exclusive_access();
    let task_cx_ptr = &mut task_inner.task_cx as *mut KContext;
    task_inner.task_status = TaskStatus::Blocked;
    drop(task_inner);
    add_block_task(task);
    debug!("blocking, to schedule");
    schedule(task_cx_ptr);
}

use crate::board::QEMUExit;

/// Exit the current 'Running' task and run the next task in task list.
pub fn exit_current_and_run_next(exit_code: i32) {
    info!("(exit_current_and_run_next) exit code: {}", exit_code);
    let task = take_current_task().unwrap();
    let mut inner = task.inner_exclusive_access();

    if inner.clear_child_tid != 0 {
        unimplemented!("clear child tid is not implemented yet");
    }
    
    remove_from_tid2task(task.gettid());
    inner.dealloc_user_res();
    inner.task_status = TaskStatus::Zombie;

    drop(inner);

    {
        let thread_group = THREAD_GROUP.exclusive_access();
        if let Some(tasks) = thread_group.get(&task.getpid()) {
            if tasks.iter().all(|t| t.inner_exclusive_access().is_zombie()) {
                drop(thread_group);
                send_signal_to_thread_group(
                    task.getppid(),
                    SignalFlags::SIGCHLD
                );
                let mut task_inner = task.inner_exclusive_access();
                task_inner.recycle();
                if task_inner.sig_table.not_exited() {
                    task_inner.sig_table.set_exit_code(exit_code);
                }
                wakeup_parent(task.getppid());
            }
        }
    }
    drop(task);
    // we do not have to save task context
    let mut _unused = KContext::blank();
    schedule(&mut _unused as *mut _);
}

#[cfg(target_arch = "riscv64")]
global_asm!(include_str!("initproc_rv.S"));
#[cfg(target_arch = "loongarch64")]
global_asm!(include_str!("initproc_la.S"));
pub static INITPROC: Lazy<Arc<ProcessControlBlock>> = Lazy::new(|| {
    // debug!("kernel: INITPROC is being initialized");
    unsafe {
        extern "C" {
            fn initproc_rv_start();
            fn initproc_rv_end();
        }
        let start = initproc_rv_start as usize as *const usize as *const u8;
        let len = initproc_rv_end as usize - initproc_rv_start as usize;
        let data = core::slice::from_raw_parts(start, len);
        ProcessControlBlock::new(data)
    }
});

///Add init process to the manager
pub fn add_initproc() {
    add_task(INITPROC.clone());
    insert_into_tid2task(0, &INITPROC);
    insert_into_thread_group(0, &INITPROC);
    info!("kernel: INITPROC is added to the task manager");
}

/// the inactive(blocked) tasks are removed when the PCB is deallocated.(called by exit_current_and_run_next)
pub fn remove_inactive_task(task: Arc<ProcessControlBlock>) {
    remove_task(Arc::clone(&task));
    //trace!("kernel: remove_inactive_task .. remove_timer");
    remove_timer(Arc::clone(&task));
    //add_task(INITPROC.clone());
    //将主线程退出的那些处于等待的子线程也删除掉
}

pub fn exit_current_group_and_run_next(exit_code: i32) {
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    let mut exit_code = exit_code;
    if inner.sig_table.not_exited() {
        //设置进程的SIGNAL_GROUP_EXIT标志并把终止代号放到current->signal->group_exit_code字段
        inner.sig_table.set_exit_code(exit_code);
        let pid = task.getpid();
        drop(inner);
        drop(task);
        send_signal_to_thread_group(pid, SignalFlags::SIGKILL);
    } else {
        exit_code = inner.sig_table.exit_code();
        drop(inner);
        drop(task);
    }

    exit_current_and_run_next(exit_code);
}

pub static CURRENT_UID: Lazy<AtomicU32> = Lazy::new(|| AtomicU32::new(0));

pub fn current_uid() -> u32 {
    CURRENT_UID.load(core::sync::atomic::Ordering::SeqCst)
}

pub fn change_current_uid(uid: u32) {
    CURRENT_UID.store(uid, core::sync::atomic::Ordering::SeqCst);
}