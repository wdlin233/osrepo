//! Types related to task management & Functions for completely changing TCB

use super::id::TaskUserRes;
use super::{KernelStack, ProcessControlBlock, TaskContext};
use crate::hal::trap::TrapContext;
use crate::{mm::PhysPageNum, sync::UPSafeCell};
use alloc::sync::{Arc, Weak};
use core::cell::RefMut;
#[cfg(target_arch = "riscv64")]
use super::{kstack_alloc};

#[cfg(target_arch = "riscv64")]
/// Task control block structure
pub struct TaskControlBlock {
    /// immutable
    pub process: Weak<ProcessControlBlock>,
    /// Kernel stack corresponding to PID
    pub kstack: KernelStack,
    /// mutable
    inner: UPSafeCell<TaskControlBlockInner>,
}
#[cfg(target_arch = "loongarch64")]
pub struct TaskControlBlock {
    // immutable
    pub process: Weak<ProcessControlBlock>, //所属进程
    // mutable
    inner: UPSafeCell<TaskControlBlockInner>,
}

impl TaskControlBlock {
    /// Get the mutable reference of the inner TCB
    pub fn inner_exclusive_access(&self) -> RefMut<'_, TaskControlBlockInner> {
        self.inner.exclusive_access()
    }
    /// Get the address of app's page table
    pub fn get_user_token(&self) -> usize {
        let process = self.process.upgrade().unwrap();
        let inner = process.inner_exclusive_access();
        inner.memory_set.token()
    }
}

#[cfg(target_arch = "riscv64")]
pub struct TaskControlBlockInner {
    pub res: Option<TaskUserRes>,
    /// The physical page number of the frame where the trap context is placed
    pub trap_cx_ppn: PhysPageNum,
    /// Save task context
    pub task_cx: TaskContext,

    /// Maintain the execution status of the current process
    pub task_status: TaskStatus,
    /// It is set when active exit or execution error occurs
    pub exit_code: Option<i32>,
}
#[cfg(target_arch = "loongarch64")]
pub struct TaskControlBlockInner {
    pub kstack: KernelStack,      //每个线程都存在内核栈，其trap上下文位于内核栈上
    pub res: Option<TaskUserRes>, //线程资源
    pub task_cx: TaskContext,     //线程上下文
    pub task_status: TaskStatus,  //线程状态
    pub exit_code: Option<i32>,   //线程退出码
}

impl TaskControlBlockInner {
    #[cfg(target_arch = "riscv64")]
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        self.trap_cx_ppn.get_mut()
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        self.kstack.get_trap_cx()
    }

    #[allow(unused)]
    fn get_status(&self) -> TaskStatus {
        self.task_status
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn get_trap_addr(&self) -> usize {
        self.kstack.get_trap_addr()
    }
}

impl TaskControlBlock {
    #[cfg(target_arch = "riscv64")]
    /// Create a new task
    pub fn new(
        process: Arc<ProcessControlBlock>,
        ustack_base: usize,
        alloc_user_res: bool,
    ) -> Self {
        let res = TaskUserRes::new(Arc::clone(&process), ustack_base, alloc_user_res);
        let trap_cx_ppn = res.trap_cx_ppn();
        let kstack = kstack_alloc();
        let kstack_top = kstack.get_top();
        Self {
            process: Arc::downgrade(&process),
            kstack,
            inner: unsafe {
                UPSafeCell::new(TaskControlBlockInner {
                    res: Some(res),
                    trap_cx_ppn,
                    task_cx: TaskContext::goto_trap_return(kstack_top),
                    task_status: TaskStatus::Ready,
                    exit_code: None,
                })
            },
        }
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn new(
        process: Arc<ProcessControlBlock>,
        ustack_base: usize,
        alloc_user_res: bool,
    ) -> Self {
        debug!("Entering TaskControlBlock::new");
        let res = TaskUserRes::new(Arc::clone(&process), ustack_base, alloc_user_res);
        // info!("Finish TaskUserRes::new!");
        let kstack = KernelStack::new();
        let kstack_top = kstack.get_trap_addr(); //存放了trap上下文后的地址
        // debug!("create task: kstack_top={:#x}", kstack_top);
        Self {
            process: Arc::downgrade(&process),
            inner: unsafe {
                UPSafeCell::new(TaskControlBlockInner {
                    kstack,
                    res: Some(res),
                    task_cx: TaskContext::goto_restore(kstack_top),
                    task_status: TaskStatus::Ready,
                    exit_code: None,
                })
            },
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


