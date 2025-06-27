//! Implementation of process [`ProcessControlBlock`] and task(thread) [`TaskControlBlock`] management mechanism
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
mod context;
mod id;
mod manager;
mod process;
mod processor;
mod stride;
mod switch;
#[allow(clippy::module_inception)]
mod task;

use self::id::TaskUserRes;
//use crate::drivers::BLOCK_DEVICE;
//use crate::fs::ext4::ROOT_INO;
use crate::fs::{open, OpenFlags, NONE_MODE};
use crate::println;
use crate::task::manager::add_stopping_task;
use crate::timer::remove_timer;
use alloc::{sync::Arc, vec::Vec};
use lazy_static::*;
use manager::fetch_task;
use spin::Lazy;
use switch::__switch;

use crate::signal::{send_signal_to_thread_group, SignalFlags};
pub use aux::{Aux, AuxType};
pub use context::TaskContext;
pub use id::{pid_alloc, KernelStack, PidHandle, IDLE_PID};
pub use manager::{
    add_block_task, add_task, pid2process, remove_from_pid2process, remove_task, wakeup_task,
    wakeup_task_by_pid,
    THREAD_GROUP,
};
pub use process::{CloneFlags, Tms, TmsInner, ProcessControlBlock, ProcessControlBlockInner};
#[cfg(target_arch = "loongarch64")]
pub use processor::current_trap_addr;
#[cfg(target_arch = "riscv64")]
pub use processor::{current_kstack_top, current_trap_cx_user_va};
pub use processor::{
    current_process, current_task, current_trap_cx, current_user_token, mmap, munmap, run_tasks,
    schedule, take_current_task,
};
pub use task::{TaskControlBlock, TaskStatus};

#[cfg(target_arch = "riscv64")]
pub use id::kstack_alloc;

use core::arch::asm;

/// Make current task suspended and switch to the next task
pub fn suspend_current_and_run_next() {
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- access current TCB exclusively
    let mut task_inner = task.inner_exclusive_access();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
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
    let task = take_current_task().unwrap();
    let mut task_inner = task.inner_exclusive_access();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    task_inner.task_status = TaskStatus::Blocked;
    drop(task_inner);
    add_block_task(task);
    debug!("blocking, to schedule");
    schedule(task_cx_ptr);
}

use crate::board::QEMUExit;

/// Exit the current 'Running' task and run the next task in task list.
pub fn exit_current_and_run_next(exit_code: i32) {
    // trace!(
    //     "kernel: pid[{}] exit_current_and_run_next",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    // take from Processor
    let task = take_current_task().unwrap();
    let mut task_inner = task.inner_exclusive_access();
    let process = task.process.upgrade().unwrap();
    let tid = task_inner.res.as_ref().unwrap().tid;
    let num = process.get_task_len();
    // record exit code
    task_inner.exit_code = Some(exit_code);
    task_inner.res = None;
    // here we do not remove the thread since we are still using the kstack
    // it will be deallocated when sys_waittid is called
    drop(task_inner);
    // Move the task to stop-wait status, to avoid kernel stack from being freed
    #[cfg(target_arch = "riscv64")]
    if tid == 0 {
        add_stopping_task(task);
    } else {
        drop(task);
    }
    #[cfg(target_arch = "loongarch64")]
    drop(task);
    // however, if this is the main thread of current process
    // the process should terminate at once
    if num == 1 {
        let pid = process.getpid();
        if pid == 1 { // to shutdown
            println!(
                "[kernel] Idle process exit with exit_code {} ...",
                exit_code
            );
            #[cfg(target_arch = "riscv64")]
            if exit_code != 0 {
                //crate::sbi::shutdown(255); //255 == -1 for err hint
                crate::board::QEMU_EXIT_HANDLE.exit_failure();
            } else {
                //crate::sbi::shutdown(0); //0 for success hint
                crate::board::QEMU_EXIT_HANDLE.exit_success();
            }
        }
        remove_from_pid2process(pid);
        let mut process_inner = process.inner_exclusive_access();
        // mark this process as a zombie process
        process_inner.is_zombie = true;
        // record exit code of main process
        process_inner.exit_code = exit_code;
        // wakeup his parent

        let parent = process_inner.parent.clone().unwrap();
        wakeup_task_by_pid(parent.upgrade().unwrap().getpid());

        // deallocate user res (including tid/trap_cx/ustack) of all threads
        // it has to be done before we dealloc the whole memory_set
        // otherwise they will be deallocated twice
        let mut recycle_res = Vec::<TaskUserRes>::new();
        for task in process_inner.tasks.iter().filter(|t| t.is_some()) {
            let task = task.as_ref().unwrap();
            // if other tasks are Ready in TaskManager or waiting for a timer to be
            // expired, we should remove them.
            //
            // Mention that we do not need to consider Mutex/Semaphore since they
            // are limited in a single process. Therefore, the blocked tasks are
            // removed when the PCB is deallocated.
            //trace!("kernel: exit_current_and_run_next .. remove_inactive_task");
            remove_inactive_task(Arc::clone(&task));
            let mut task_inner = task.inner_exclusive_access();
            if let Some(res) = task_inner.res.take() {
                recycle_res.push(res);
            }
        }
        // dealloc_tid and dealloc_user_res require access to PCB inner, so we
        // need to collect those user res first, then release process_inner
        // for now to avoid deadlock/double borrow problem.
        drop(process_inner);
        recycle_res.clear();
        //debug!("recycle res ok");
        let mut process_inner = process.inner_exclusive_access();
        process_inner.children.clear();
        // deallocate other data in user space i.e. program code/data section
        process_inner.memory_set.recycle_data_pages();
        // drop file descriptors
        if let Some(fd_table) = Arc::get_mut(&mut process_inner.fd_table) {
            fd_table.clear();
        }
        // remove all tasks, release all threads
        process_inner.tasks.clear();
        //debug!("all clear ok");
        //debug!("after clear, the parent fd table len is :{}",)
        #[cfg(target_arch = "loongarch64")]
        // 使得原来的TLB表项无效掉，否则下一个进程与当前退出的进程号相同会导致
        // 无法正确进行地址转换
        unsafe {
            asm!("invtlb 0x4,{},$r0",in(reg) pid);
        }
    }
    drop(process);
    // we do not have to save task context
    let mut _unused = TaskContext::zero_init();
    schedule(&mut _unused as *mut _);
}

pub static INITPROC: Lazy<Arc<ProcessControlBlock>> = Lazy::new(|| {
    debug!("kernel: INITPROC is being initialized");

    let initproc = open("/initproc", OpenFlags::O_RDONLY, NONE_MODE)
        .expect("open initproc error!")
        .file()
        .expect("initproc can not be abs file!");
    debug!("kernel: INITPROC opened successfully");
    let elf_data = initproc.inode.read_all().unwrap();
    let res = ProcessControlBlock::new(&elf_data);
    res
});

///Add init process to the manager
pub fn add_initproc() {
    let _initproc = INITPROC.clone();
}

/// Check if the current task has any signal to handle
pub fn check_signals_of_current() -> Option<(i32, &'static str)> {
    let process = current_process();
    let process_inner = process.inner_exclusive_access();
    process_inner.signals.check_error()
}

/// Add signal to the current task
pub fn current_add_signal(signal: SignalFlags) {
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    process_inner.signals |= signal;
}

/// the inactive(blocked) tasks are removed when the PCB is deallocated.(called by exit_current_and_run_next)
pub fn remove_inactive_task(task: Arc<TaskControlBlock>) {
    remove_task(Arc::clone(&task));
    //trace!("kernel: remove_inactive_task .. remove_timer");
    remove_timer(Arc::clone(&task));
    //add_task(INITPROC.clone());
    //将主线程退出的那些处于等待的子线程也删除掉
}

pub fn current_uid() -> u32 {
    //CUR_UID.load(core::sync::atomic::Ordering::SeqCst)
    //unimplemented!()
    let current = current_task().unwrap();
    current.process.upgrade().unwrap().getuid() as u32
}

pub fn current_token() -> usize {
    // get_proc_by_hartid(hart_id()).token()
    #[cfg(target_arch = "riscv64")]
    return riscv::register::satp::read().bits();

    unimplemented!()
}

pub fn exit_current_group_and_run_next(exit_code: i32) {
    let process = current_process();
    let mut inner = process.inner_exclusive_access();
    let mut exit_code = exit_code;
    if inner.sig_table.not_exited() {
        //设置进程的SIGNAL_GROUP_EXIT标志并把终止代号放到current->signal->group_exit_code字段
        inner.sig_table.set_exit_code(exit_code);
        let pid = process.getpid();
        drop(inner);
        drop(process);
        send_signal_to_thread_group(pid, SignalFlags::SIGKILL);
    } else {
        exit_code = inner.sig_table.exit_code();
        drop(inner);
        drop(process);
    }

    exit_current_and_run_next(exit_code);
}