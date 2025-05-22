//! Types related to task management & Functions for completely changing TCB

use super::id::TaskUserRes;
use super::{KernelStack, ProcessControlBlock};
use crate::sync::UPSafeCell;
use crate::task::current_task;
use alloc::sync::{Arc, Weak};
use polyhal::kcontext::{read_current_tp, KContext, KContextArgs};
use polyhal::PageTable;
use polyhal_trap::trap::run_user_task;
use polyhal_trap::trapframe::TrapFrame;
use core::cell::RefMut;

/// Task control block structure
pub struct TaskControlBlock {
    /// immutable
    pub process: Weak<ProcessControlBlock>,
    /// Kernel stack corresponding to PID
    pub kstack: KernelStack,
    /// mutable
    inner: UPSafeCell<TaskControlBlockInner>,
}

impl TaskControlBlock {
    /// Get the mutable reference of the inner TCB
    pub fn inner_exclusive_access(&self) -> RefMut<'_, TaskControlBlockInner> {
        self.inner.exclusive_access()
    }
    /// Get the address of app's page table
    pub fn get_user_token(&self) -> PageTable {
        let process = self.process.upgrade().unwrap();
        let inner = process.inner_exclusive_access();
        inner.memory_set.token()
    }
}

pub struct TaskControlBlockInner {
    pub res: Option<TaskUserRes>,
    /// The physical page number of the frame where the trap context is placed
    pub trap_cx: TrapFrame,
    /// Save task context
    pub task_cx: KContext,

    /// Maintain the execution status of the current process
    pub task_status: TaskStatus,
    /// It is set when active exit or execution error occurs
    pub exit_code: Option<i32>,

    /// backup trap context
    pub trap_ctx_backup: Option<TrapFrame>,
}

impl TaskControlBlockInner {
    pub fn get_trap_cx(&self) -> &'static mut TrapFrame {
        let paddr = &self.trap_cx as *const TrapFrame as usize as *mut TrapFrame;
        // let paddr: PhysAddr = self.trap_cx.into();
        // unsafe { paddr.get_mut_ptr::<TrapFrame>().as_mut().unwrap() }
        unsafe { paddr.as_mut().unwrap() }
    }

    #[allow(unused)]
    fn get_status(&self) -> TaskStatus {
        self.task_status
    }
}

impl TaskControlBlock {
    /// Create a new task
    pub fn new(
        process: Arc<ProcessControlBlock>,
        ustack_base: usize,
        alloc_user_res: bool,
    ) -> Self {
        let res = TaskUserRes::new(Arc::clone(&process), ustack_base, alloc_user_res);
        let kstack = KernelStack::new();
        Self {
            process: Arc::downgrade(&process),
            inner: unsafe {
                UPSafeCell::new(TaskControlBlockInner {
                    res: Some(res),
                    trap_cx: TrapFrame::new(),
                    task_cx: blank_kcontext(kstack.get_position().1),
                    task_status: TaskStatus::Ready,
                    exit_code: None,
                    trap_ctx_backup: None,
                })
            },
            kstack: kstack,
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
/// The execution status of the current process
pub enum TaskStatus {
    /// ready to run
    Ready,
    /// running
    Running,
    /// blocked
    Blocked,
}

fn task_entry() {
    trace!("os::task::task_entry");
    let task = current_task()
        .unwrap()
        .inner
        .exclusive_access()
        .get_trap_cx() as *mut TrapFrame;
    // run_user_task_forever(unsafe { task.as_mut().unwrap() })
    let ctx_mut = unsafe { task.as_mut().unwrap() };
    loop {
        run_user_task(ctx_mut);
    }
}

fn blank_kcontext(ksp: usize) -> KContext {
    let mut kcx = KContext::blank();
    kcx[KContextArgs::KPC] = task_entry as usize;
    kcx[KContextArgs::KSP] = ksp;
    kcx[KContextArgs::KTP] = read_current_tp();
    kcx
}

// pub struct KernelStack {
//     inner: Arc<[u128; KERNEL_STACK_SIZE / size_of::<u128>()]>,
// }

// impl KernelStack {
//     pub fn new() -> Self {
//         Self {
//             inner: Arc::new([0u128; KERNEL_STACK_SIZE / size_of::<u128>()]),
//         }
//     }

//     pub fn get_position(&self) -> (usize, usize) {
//         let bottom = self.inner.as_ptr() as usize;
//         (bottom, bottom + KERNEL_STACK_SIZE)
//     }
// }
