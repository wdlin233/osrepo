//! Types related to task management & Functions for completely changing TCB

use super::id::{trap_cx_bottom_from_tid, ustack_bottom_from_tid};
#[cfg(target_arch = "riscv64")]
use super::kstack_alloc;
use super::{KernelStack, ProcessControlBlock, TaskContext};
use crate::config::{
    KERNEL_STACK_SIZE, PAGE_SIZE, TRAMPOLINE, USER_HEAP_SIZE, USER_STACK_SIZE, USER_STACK_TOP,
    USER_TRAP_CONTEXT_TOP,
};
use crate::hal::trap::TrapContext;
use crate::mm::{MapAreaType, MapPermission, PhysPageNum, VPNRange, VirtAddr, VirtPageNum};
use crate::sync::UPSafeCell;
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
    //pub res: Option<TaskUserRes>,
    pub tid: usize,
    pub ptid: usize,
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
    pub fn ustack_top(&self, _get_self: bool) -> usize {
        debug!("in ustack top,  tid is :{}", self.tid);
        ustack_bottom_from_tid(self.tid) + USER_STACK_SIZE
    }
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
    pub fn alloc_user_res(&self) {
        let process = self.process.upgrade().unwrap();
        let process_inner = process.inner_exclusive_access();
        debug!("in alloc , give tid, tid is : {}", self.tid());
        let ustack_bottom = ustack_bottom_from_tid(self.tid());
        let ustack_top = ustack_bottom + USER_STACK_SIZE;
        info!(
            "in alloc_user_res, ustack_bottom: {:#x}, ustack_top: {:#x}",
            ustack_bottom, ustack_top
        );
        process_inner.memory_set.insert_framed_area(
            ustack_bottom.into(),
            ustack_top.into(),
            MapPermission::default() | MapPermission::W,
            MapAreaType::Stack,
        );
        info!(
            "in alloc_user_res, ustack_bottom: {:#x}, ustack_top: {:#x}",
            ustack_bottom, ustack_top
        );
        let trap_cx_bottom = trap_cx_bottom_from_tid(self.tid());
        let trap_cx_top = trap_cx_bottom + PAGE_SIZE;
        #[cfg(target_arch = "riscv64")] 
        process_inner.memory_set.insert_framed_area(
            trap_cx_bottom.into(),
            trap_cx_top.into(),
            MapPermission::R | MapPermission::W,
            MapAreaType::Trap,
        );
        #[cfg(target_arch = "loongarch64")] 
        process_inner.memory_set.insert_framed_area(
            trap_cx_bottom.into(),
            trap_cx_top.into(),
            MapPermission::W | MapPermission::NX,
            MapAreaType::Trap,
        );
    }
    #[cfg(target_arch = "riscv64")]
    pub fn set_user_trap(&self) {
        let trap_cx_ppn = self.trap_cx_ppn(self.tid());
        let mut inner = self.inner_exclusive_access();
        inner.trap_cx_ppn = trap_cx_ppn;
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
    #[cfg(target_arch = "riscv64")]
    /// The bottom usr vaddr (low addr) of the trap context for a task with tid
    pub fn trap_cx_user_va(&self) -> usize {
        //debug!("in tcb, trap cx user va");
        trap_cx_bottom_from_tid(self.tid())
    }
    /// Create a new task
    pub fn new(process: Arc<ProcessControlBlock>, alloc_user_res: bool, parent_tid: usize) -> Self {
        let tid = process.inner_exclusive_access().alloc_tid();
        debug!("in tcb new, the tid is : {}", tid);
        let (kstack, kstack_top) = {
            #[cfg(target_arch = "riscv64")]
            {
                let kstack = kstack_alloc();
                let kstack_top = kstack.get_top();
                (Some(kstack), kstack_top)
            }
            #[cfg(target_arch = "loongarch64")]
            {
                // info!("Finish TaskUserRes::new!");
                let kstack = KernelStack::new();
                let kstack_top = kstack.get_trap_addr(); //存放了trap上下文后的地址
                                                         // debug!("create task: kstack_top={:#x}", kstack_top);
                (Some(kstack), kstack_top)
            }
        };
        let mut new_task = TaskControlBlock {
            process: Arc::downgrade(&process),
            #[cfg(target_arch = "riscv64")]
            kstack: kstack.unwrap(),
            inner: unsafe {
                UPSafeCell::new(TaskControlBlockInner {
                    tid,
                    ptid: parent_tid,
                    #[cfg(target_arch = "loongarch64")]
                    kstack: kstack.unwrap(),
                    #[cfg(target_arch = "riscv64")]
                    trap_cx_ppn: PhysPageNum(0),
                    task_cx: TaskContext::goto_trap_return(kstack_top),
                    task_status: TaskStatus::Ready,
                    exit_code: None,
                })
            },
        };
        if alloc_user_res {
            new_task.alloc_user_res();
            //new_task.alloc_user_trap();
        }
        #[cfg(target_arch = "riscv64")]
        {
            //new_task.alloc_user_trap();
            if alloc_user_res {
                let trap_cx_ppn = new_task.trap_cx_ppn(tid);
                //let trap_cx_ppn = new_task.trap_cx_ppn(new_task.tid());
                new_task.inner_exclusive_access().trap_cx_ppn = trap_cx_ppn;
            } else {
                //let trap_cx_ppn = new_task.trap_cx_ppn(parent_tid);
                let trap_cx_ppn = new_task.trap_cx_ppn(parent_tid);
                new_task.inner_exclusive_access().trap_cx_ppn = trap_cx_ppn;
            }
        }
        new_task
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
