//! Types related to task management & Functions for completely changing TCB

use super::id::{trap_cx_bottom_from_tid, ustack_bottom_from_tid, TaskUserRes};
#[cfg(target_arch = "riscv64")]
use super::kstack_alloc;
use super::{KernelStack, ProcessControlBlock, TaskContext};
use crate::hal::trap::TrapContext;
use crate::{mm::PhysPageNum, sync::UPSafeCell};
use alloc::sync::{Arc, Weak};
use core::cell::RefMut;
use spin::MutexGuard;

/// Task control block structure
pub struct TaskControlBlock {
    /// immutable
    pub process: Weak<ProcessControlBlock>, //所属进程
    /// Kernel stack corresponding to PID
    #[cfg(target_arch = "riscv64")]
    pub kstack: KernelStack,
    /// mutable
    inner: UPSafeCell<TaskControlBlockInner>,
}

pub struct TaskControlBlockInner {
    pub res: Option<TaskUserRes>,
    pub tid: usize,
    /// The physical page number of the frame where the trap context is placed
    #[cfg(target_arch = "riscv64")]
    pub trap_cx_ppn: PhysPageNum,
    //每个线程都存在内核栈，其trap上下文位于内核栈上
    #[cfg(target_arch = "loongarch64")]
    pub kstack: KernelStack,

    /// Save task context, 线程上下文
    pub task_cx: TaskContext,
    /// Maintain the execution status of the current process
    pub task_status: TaskStatus,
    /// It is set when active exit or execution error occurs
    pub exit_code: Option<i32>,
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

impl TaskControlBlockInner {
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        #[cfg(target_arch = "riscv64")]
        {
            debug!(
                "in tcb inner, get trap cx, trap cx ppn is : {}",
                self.trap_cx_ppn.0
            );
            self.trap_cx_ppn.get_mut()
        }
        #[cfg(target_arch = "loongarch64")]
        {
            self.kstack.get_trap_cx()
        }
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
    pub fn alloc_user_res(&mut self) {
        let process = self.process.upgrade().unwrap();
        let process_inner = process.inner_exclusive_access();
        debug!("in alloc , give tid, tid is : {}", self.tid());
        let ustack_bottom = ustack_bottom_from_tid(self.tid());
        let ustack_top = ustack_bottom + USER_STACK_SIZE;
        process_inner.memory_set.insert_framed_area(
            ustack_bottom.into(),
            ustack_top.into(),
            MapPermission::default() | MapPermission::W,
            MapAreaType::Stack,
        );

        #[cfg(target_arch = "riscv64")]
        {
            debug!("to get trap cx bottom, give tid, like up");
            let trap_cx_bottom = trap_cx_bottom_from_tid(self.tid());
            let trap_cx_top = trap_cx_bottom + PAGE_SIZE;
            //debug!("to map trap cx info");
            process_inner.memory_set.insert_framed_area(
                trap_cx_bottom.into(),
                trap_cx_top.into(),
                MapPermission::R | MapPermission::W,
                MapAreaType::Trap,
            );
        }
    }
    #[cfg(target_arch = "riscv64")]
    /// The physical page number(ppn) of the trap context for a task with tid
    pub fn trap_cx_ppn(&self, tid: usize) -> PhysPageNum {
        debug!(
            "in get trap cx ppn , self tid is : {}, tid is : {}",
            self.tid(),
            tid
        );
        let process = self.process.upgrade().unwrap();
        let process_inner = process.inner_exclusive_access();
        let trap_cx_bottom_va: VirtAddr = trap_cx_bottom_from_tid(tid).into();
        process_inner
            .memory_set
            .translate(trap_cx_bottom_va.into())
            .unwrap()
            .ppn()
    }
    /// Create a new task
    pub fn new(
        process: Arc<ProcessControlBlock>,
        ustack_base: usize,
        alloc_user_res: bool,
    ) -> Self {
        //debug!("in tcb new");
        //let res = TaskUserRes::new(Arc::clone(&process), ustack_base, alloc_user_res);
        let tid = process.inner_exclusive_access().alloc_tid();
        if alloc_user_res {
            self.alloc_user_res();
        }
        let (kstack, kstack_top, _trap_cx_ppn) = {
            #[cfg(target_arch = "riscv64")]
            {
                let trap_cx_ppn = self.trap_cx_ppn(self.tid());
                debug!("(TaskControlBlock, new) trap cx ppn is : {}", trap_cx_ppn.0);
                let kstack = kstack_alloc();
                let kstack_top = kstack.get_top();
                (Some(kstack), kstack_top, Some(trap_cx_ppn))
            }
            #[cfg(target_arch = "loongarch64")]
            {
                // info!("Finish TaskUserRes::new!");
                let kstack = KernelStack::new();
                let kstack_top = kstack.get_trap_addr(); //存放了trap上下文后的地址
                                                         // debug!("create task: kstack_top={:#x}", kstack_top);
                (Some(kstack), kstack_top, Some(0)) // Some(0) as None to avoid gerneric type
            }
        };
        Self {
            process: Arc::downgrade(&process),
            #[cfg(target_arch = "riscv64")]
            kstack: kstack.unwrap(),
            inner: unsafe {
                UPSafeCell::new(TaskControlBlockInner {
                    tid,
                    #[cfg(target_arch = "loongarch64")]
                    kstack: kstack.unwrap(),
                    res: Some(res),
                    #[cfg(target_arch = "riscv64")]
                    trap_cx_ppn: _trap_cx_ppn.unwrap(),
                    task_cx: TaskContext::goto_trap_return(kstack_top),
                    task_status: TaskStatus::Ready,
                    exit_code: None,
                })
            },
        }
    }

    pub fn tid(&self) -> usize {
        let inner = self.inner_exclusive_access();
        let id = inner.tid;
        id
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
