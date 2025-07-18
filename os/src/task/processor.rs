//! Implementation of [`Processor`] and Intersection of control flow
//!
//! Here, the continuous operation of user apps in CPU is maintained,
//! the current running state of CPU is recorded,
//! and the replacement and transfer of control flow of different applications are executed.

use super::{fetch_task, TaskStatus};
use super::{ProcessControlBlock};
#[cfg(target_arch = "loongarch64")]
use crate::config::PAGE_SIZE_BITS;
use crate::mm::MapPermission;
use crate::sync::UPSafeCell;
use crate::syscall::MmapFlags;
use crate::task::{add_task, change_current_uid, process};
use crate::timer::check_timer;
use alloc::sync::Arc;
use lazyinit::LazyInit;
use polyhal::kcontext::{context_switch, context_switch_pt, KContext};
use polyhal::{PageTable, PageTableWrapper};
use polyhal_trap::trapframe::TrapFrame;
use core::arch::asm;
//use core::str::next_code_point;
use lazy_static::*;

/// Processor management structure
pub struct Processor {
    /// The task currently executing on the current processor
    current: Option<Arc<ProcessControlBlock>>,

    ///The basic control flow of each core, helping to select and switch process
    idle_task_cx: KContext,
}

impl Processor {
    pub fn new() -> Self {
        Self {
            current: None,
            idle_task_cx: KContext::blank(),
        }
    }

    ///Get mutable reference to `idle_task_cx`
    fn get_idle_task_cx_ptr(&mut self) -> *mut KContext {
        // info!(
        //     "get_idle_task_cx_ptr: idle task cx ptr: {:p}",
        //     &self.idle_task_cx
        // );
        &mut self.idle_task_cx as *mut _
    }

    ///Get current task in moving semanteme
    pub fn take_current(&mut self) -> Option<Arc<ProcessControlBlock>> {
        self.current.take()
    }

    ///Get current task in cloning semanteme
    pub fn current(&self) -> Option<Arc<ProcessControlBlock>> {
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
        //let mut processor = PROCESSOR.exclusive_access();
        //let idle_task_cx_ptr = PROCESSOR.exclusive_access().get_idle_task_cx_ptr();
        //info!("(run_tasks) idle task cx ptr: {:p}", idle_task_cx_ptr);
        info!("(run_tasks) in run_tasks loop beginning.");
        if let Some(current_task) = take_current_task() {
            let idle_task_cx_ptr = PROCESSOR.exclusive_access().get_idle_task_cx_ptr();
        
            let mut current_inner = current_task.inner_exclusive_access();
            check_timer();
            if let Some(next_task) = fetch_task() {
                debug!(
                    "(run_tasks) next task tid: {}, pid: {}",
                    next_task.gettid(),
                    next_task.getpid()
                );
                let mut next_inner = next_task.inner_exclusive_access();
                let next_task_cx_ptr = &next_inner.task_cx as *const KContext;
                next_inner.task_status = TaskStatus::Running;
                let next_token = next_inner.memory_set.token_pt(); // for activating
                change_current_uid(next_task.getuid() as u32);
                drop(next_inner);
                drop(current_inner);
                PROCESSOR.exclusive_access().current = Some(next_task);
                add_task(current_task);
                unsafe {
                    context_switch_pt(idle_task_cx_ptr, next_task_cx_ptr, next_token);    
                }
            } else {
                debug!("(run_tasks) no next task, continue with current task");
                current_inner.task_status = TaskStatus::Running;
                let current_task_cx_ptr = &current_inner.task_cx as *const KContext;
                drop(current_inner);
                PROCESSOR.exclusive_access().current = Some(current_task);
                unsafe {
                    context_switch(idle_task_cx_ptr, current_task_cx_ptr);
                }
            }
        } else {
            let idle_task_cx_ptr = PROCESSOR.exclusive_access().get_idle_task_cx_ptr();
            info!("(run_tasks) it is first schedule, idle task cx ptr: {:p}", idle_task_cx_ptr);
            if let Some(task) = fetch_task() {
                // access coming task TCB exclusively
                let mut task_inner = task.inner_exclusive_access();
                // TODO timer
                task_inner
                    .tms
                    .set_begin();
                let next_task_cx_ptr = &task_inner.task_cx as *const KContext;
                task_inner.task_status = TaskStatus::Running;
                let token = task_inner.memory_set.token_pt(); // activate memoryset
                drop(task_inner);
                PROCESSOR.exclusive_access().current = Some(task);
                info!(
                    "(run_tasks) switching from idle task cx ptr: {:p} to next task cx ptr: {:p}",
                    idle_task_cx_ptr,
                    next_task_cx_ptr
                );
                unsafe {
                    context_switch_pt(idle_task_cx_ptr, next_task_cx_ptr, token);
                }
                check_timer();
            }
        }
    }
}

/// Get current task through take, leaving a None in its place
pub fn take_current_task() -> Option<Arc<ProcessControlBlock>> {
    debug!("(take_current_task) taking current task");
    PROCESSOR.exclusive_access().take_current()
}

/// Get a copy of the current task
pub fn current_task() -> Option<Arc<ProcessControlBlock>> {
    PROCESSOR.exclusive_access().current()
}

/// Get the mutable reference to trap context of current task
pub fn current_trap_cx() -> &'static mut TrapFrame {
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .get_trap_cx()
}

static BOOT_PAGE_TABLE: LazyInit<PageTable> = LazyInit::new();

/// Return to idle control flow for new scheduling
pub fn schedule(switched_task_cx_ptr: *mut KContext) {
    let mut processor = PROCESSOR.exclusive_access();
    let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
    drop(processor);
    //debug!("in schedule, to switch, currrent ra is : {},current sp is :{}, next ra is :{}, next sp is : {}",unsafe{(*switched_task_cx_ptr).get_ra()},unsafe{(*switched_task_cx_ptr).get_sp()},unsafe{(*idle_task_cx_ptr).get_ra()},unsafe{(*idle_task_cx_ptr).get_sp()});
    unsafe {
        context_switch_pt(switched_task_cx_ptr, idle_task_cx_ptr, *BOOT_PAGE_TABLE);
    }
}

pub fn init_kernel_page() {
    BOOT_PAGE_TABLE.init_once(PageTable::current());
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
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .memory_set
        .mmap(addr, len, port, flags, fd, off)
}

/// Unmap the MapArea for the current task
pub fn munmap(addr: usize, len: usize) -> isize {
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .memory_set
        .munmap(addr, len)
}
