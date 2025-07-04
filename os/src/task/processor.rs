//! Implementation of [`Processor`] and Intersection of control flow
//!
//! Here, the continuous operation of user apps in CPU is maintained,
//! the current running state of CPU is recorded,
//! and the replacement and transfer of control flow of different applications are executed.

use super::__switch;
use super::{fetch_task, TaskStatus};
use super::{ProcessControlBlock, TaskContext, TaskControlBlock};
#[cfg(target_arch = "loongarch64")]
use crate::config::PAGE_SIZE_BITS;
use crate::hal::trap::TrapContext;
use crate::mm::MapPermission;
use crate::sync::UPSafeCell;
use crate::syscall::MmapFlags;
use crate::timer::check_timer;
use alloc::sync::Arc;
use core::arch::asm;
//use core::str::next_code_point;
use lazy_static::*;
#[cfg(target_arch = "loongarch64")]
use loongarch64::register::{asid, pgdl};

/// Processor management structure
pub struct Processor {
    /// The task currently executing on the current processor
    current: Option<Arc<TaskControlBlock>>,

    ///The basic control flow of each core, helping to select and switch process
    idle_task_cx: TaskContext,
}

impl Processor {
    pub fn new() -> Self {
        Self {
            current: None,
            idle_task_cx: TaskContext::zero_init(),
        }
    }

    ///Get mutable reference to `idle_task_cx`
    fn get_idle_task_cx_ptr(&mut self) -> *mut TaskContext {
        // info!(
        //     "get_idle_task_cx_ptr: idle task cx ptr: {:p}",
        //     &self.idle_task_cx
        // );
        &mut self.idle_task_cx as *mut _
    }

    ///Get current task in moving semanteme
    pub fn take_current(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.current.take()
    }

    ///Get current task in cloning semanteme
    pub fn current(&self) -> Option<Arc<TaskControlBlock>> {
        self.current.as_ref().map(Arc::clone)
    }
}

lazy_static! {
    pub static ref PROCESSOR: UPSafeCell<Processor> = unsafe { UPSafeCell::new(Processor::new()) };
}

///The main part of process execution and scheduling
///Loop `fetch_task` to get the process that needs to run, and switch the process through `__switch`
pub fn run_tasks() {
    loop {
        let mut processor = PROCESSOR.exclusive_access();
        if let Some(task) = fetch_task() {
            let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
            // access coming task TCB exclusively
            #[cfg(target_arch = "riscv64")]
            task.process
                .upgrade()
                .unwrap()
                .inner_exclusive_access()
                .tms
                .set_begin();
            #[cfg(target_arch = "loongarch64")]
            let pid = task.process.upgrade().unwrap().getpid();
            #[cfg(target_arch = "loongarch64")]
            {
                //应用进程号
                let pgd = task.get_user_token() << PAGE_SIZE_BITS;
                pgdl::set_base(pgd); //设置根页表基地址
                asid::set_asid(pid); //设置ASID
            }
            // debug!(
            //     "run_tasks: pid: {}, tid: {}",
            //     task.process.upgrade().unwrap().getpid(),
            //     task.inner_exclusive_access().res.as_ref().unwrap().tid
            // );
            let mut task_inner = task.inner_exclusive_access();
            let next_task_cx_ptr = &task_inner.task_cx as *const TaskContext;
            task_inner.task_status = TaskStatus::Running;
            #[cfg(target_arch = "loongarch64")]
            // 在进行线程切换的时候
            // 地址空间是相同的，并且pgd也是相同的
            // 每个线程都有自己的内核栈和用户栈，用户栈互相隔离
            // 在进入用户态后应该每个线程的地址转换是相同的
            unsafe {
                asm!("invtlb 0x4,{},$r0",in(reg) pid);
            }

            // release coming task_inner manually
            drop(task_inner);
            // release coming task TCB manually
            processor.current = Some(task);
            // release processor manually
            drop(processor);
            unsafe {
                __switch(idle_task_cx_ptr, next_task_cx_ptr);
            }
        } else {
            //warn!("no tasks available in run_tasks");
            check_timer();
        }
    }
}

/// Get current task through take, leaving a None in its place
pub fn take_current_task() -> Option<Arc<TaskControlBlock>> {
    PROCESSOR.exclusive_access().take_current()
}

/// Get a copy of the current task
pub fn current_task() -> Option<Arc<TaskControlBlock>> {
    PROCESSOR.exclusive_access().current()
}

/// get current process
pub fn current_process() -> Arc<ProcessControlBlock> {
    current_task().unwrap().process.upgrade().unwrap()
}

/// Get the current user token(addr of page table)
pub fn current_user_token() -> usize {
    let task = current_task().unwrap();
    task.get_user_token()
}

/// Get the mutable reference to trap context of current task
pub fn current_trap_cx() -> &'static mut TrapContext {
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .get_trap_cx()
}

#[cfg(target_arch = "riscv64")]
/// get the user virtual address of trap context
pub fn current_trap_cx_user_va() -> usize {
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .res
        .as_ref()
        .unwrap()
        .trap_cx_user_va()
}

#[cfg(target_arch = "riscv64")]
/// get the top addr of kernel stack
pub fn current_kstack_top() -> usize {
    current_task().unwrap().kstack.get_top()
}

#[cfg(target_arch = "loongarch64")]
pub fn current_trap_addr() -> usize {
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .get_trap_addr()
}

/// Return to idle control flow for new scheduling
pub fn schedule(switched_task_cx_ptr: *mut TaskContext) {
    let mut processor = PROCESSOR.exclusive_access();
    let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
    drop(processor);
    //debug!("in schedule, to switch, currrent ra is : {},current sp is :{}, next ra is :{}, next sp is : {}",unsafe{(*switched_task_cx_ptr).get_ra()},unsafe{(*switched_task_cx_ptr).get_sp()},unsafe{(*idle_task_cx_ptr).get_ra()},unsafe{(*idle_task_cx_ptr).get_sp()});
    unsafe {
        __switch(switched_task_cx_ptr, idle_task_cx_ptr);
    }
}

/// Create a MapArea for the current task
pub fn mmap(
    addr: usize,
    len: usize,
    port: MapPermission,
    flags: MmapFlags,
    fd: Option<Arc<crate::fs::OSInode>>,
    off: usize,
) -> usize {
    current_process()
        .inner_exclusive_access()
        .memory_set
        .mmap(addr, len, port, flags, fd, off)
}

/// Unmap the MapArea for the current task
pub fn munmap(addr: usize, len: usize) -> isize {
    current_task()
        .unwrap()
        .process
        .upgrade()
        .unwrap()
        .inner_exclusive_access()
        .memory_set
        .munmap(addr, len)
}
