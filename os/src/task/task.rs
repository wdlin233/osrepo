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
use crate::mm::{
    flush_tlb, MapAreaType, MapPermission, PhysAddr, PhysPageNum, VPNRange, VirtAddr, VirtPageNum,
};
use crate::signal::SignalFlags;
use crate::sync::UPSafeCell;
use alloc::alloc::alloc;
use alloc::string::ToString;
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
    ///trap_va
    pub trap_va: VirtAddr,

    pub ustack_top: VirtAddr,

    pub sig_mask: SignalFlags,
    /// signal pending
    pub sig_pending: SignalFlags,
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
    pub fn ustack_top(&self) -> usize {
        self.ustack_top.0
    }
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        debug!(
            "in tcb inner, get trap cx, trap cx ppn is : {}",
            self.trap_cx_ppn.0
        );
        self.trap_cx_ppn.get_mut()
    }
    pub fn trap_cx_bottom(&self) -> VirtAddr {
        self.trap_va
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
    /// The bottom usr vaddr (low addr) of the trap context for a task with tid
    pub fn trap_cx_user_va(&self) -> usize {
        //trap_cx_bottom_from_tid(self.tid())
        let inner = self.inner_exclusive_access();
        let va = inner.trap_cx_bottom();
        debug!("tcb, trap cx user va is : {:#x}", va.0);
        va.0
    }

    pub fn user_stack_top(&self) -> usize {
        let inner = self.inner_exclusive_access();
        let va = inner.ustack_top();
        va
    }

    /// Create a new task
    pub fn new(
        process: Arc<ProcessControlBlock>,
        alloc_user_res: bool,
        alloc_ustack: bool,
        parent_tid: usize,
    ) -> Self {
        let tid = process.inner_exclusive_access().alloc_tid();
        debug!("in tcb new, the tid is : {}", tid);
        let (kstack, kstack_top) = {
            #[cfg(target_arch = "riscv64")]
            {
                let kstack = kstack_alloc();
                let kstack_top = kstack.get_top();
                (Some(kstack), kstack_top)
            }
        };
        let sig_mask = SignalFlags::empty();
        let sig_pending = SignalFlags::empty();
        let mut new_task = TaskControlBlock {
            process: Arc::downgrade(&process),
            #[cfg(target_arch = "riscv64")]
            kstack: kstack.unwrap(),
            inner: unsafe {
                UPSafeCell::new(TaskControlBlockInner {
                    tid,
                    ptid: parent_tid,
                    sig_mask,
                    sig_pending,
                    #[cfg(target_arch = "loongarch64")]
                    kstack: kstack.unwrap(),
                    #[cfg(target_arch = "riscv64")]
                    trap_cx_ppn: PhysPageNum(0),
                    trap_va: VirtAddr(0),
                    ustack_top: VirtAddr(0),
                    task_cx: TaskContext::goto_trap_return(kstack_top),
                    task_status: TaskStatus::Ready,
                    exit_code: None,
                })
            },
        };
        // if alloc_user_res {
        //     new_task.alloc_user_res(alloc_ustack);
        //     //new_task.alloc_user_trap();
        // }
        new_task.alloc_user_res(alloc_ustack);
        // #[cfg(target_arch = "riscv64")]
        // {
        //     //new_task.alloc_user_trap();
        //     if alloc_user_res {
        //         let trap_cx_ppn = new_task.trap_cx_ppn(tid);
        //         //let trap_cx_ppn = new_task.trap_cx_ppn(new_task.tid());
        //         new_task.inner_exclusive_access().trap_cx_ppn = trap_cx_ppn;
        //     } else {
        //         //let trap_cx_ppn = new_task.trap_cx_ppn(parent_tid);
        //         let trap_cx_ppn = new_task.trap_cx_ppn(parent_tid);
        //         new_task.inner_exclusive_access().trap_cx_ppn = trap_cx_ppn;
        //     }
        // }
        new_task
    }

    fn new_sig(&self) {
        let mut inner = self.inner_exclusive_access();
        inner.sig_mask = SignalFlags::empty();
        inner.sig_pending = SignalFlags::empty();
    }
    pub fn alloc_user_res(&self, alloc_ustack: bool) {
        let process = self.process.upgrade().unwrap();
        let process_inner = process.inner_exclusive_access();
        debug!("in alloc , give tid, tid is : {}", self.tid());
        let mut ustack_bottom: usize = 0;
        let mut ustack_top: usize = 0;
        if alloc_ustack {
            (ustack_bottom, ustack_top) = process_inner.memory_set.insert_framed_area_with_hint(
                USER_STACK_TOP,
                USER_STACK_SIZE,
                MapPermission::default() | MapPermission::W,
                MapAreaType::Stack,
            );
            let mut inner = self.inner_exclusive_access();
            inner.ustack_top = VirtAddr::from(ustack_top);
            drop(inner);
        } else {
            let mut inner = self.inner_exclusive_access();
            inner.ustack_top = VirtAddr::from(0);
            drop(inner);
        }

        let (trap_cx_bottom, _) = process_inner.memory_set.insert_framed_area_with_hint(
            USER_TRAP_CONTEXT_TOP,
            PAGE_SIZE,
            MapPermission::R | MapPermission::W,
            MapAreaType::Trap,
        );
        debug!("alloc res, trap bottom is : {:#x}", trap_cx_bottom);
        let trap_cx_ppn = process_inner
            .memory_set
            .translate(VirtAddr::from(trap_cx_bottom).floor())
            .unwrap()
            .ppn();

        let mut inner = self.inner_exclusive_access();
        inner.trap_va = trap_cx_bottom.into();
        inner.trap_cx_ppn = trap_cx_ppn;
    }

    pub fn dealloc_user_res(&self) {
        let inner = self.inner_exclusive_access();
        let process = self.process.upgrade().unwrap();
        let process_inner = process.inner_exclusive_access();
        if inner.ustack_top.0 != 0 {
            process_inner.memory_set.remove_area_with_start_vpn(
                VirtAddr::from(inner.ustack_top.0 - USER_STACK_SIZE).floor(),
            );
        }
        process_inner
            .memory_set
            .remove_area_with_start_vpn(inner.trap_va.floor());
        flush_tlb();
    }
    pub fn tid(&self) -> usize {
        let inner = self.inner_exclusive_access();
        let id = inner.tid;
        id
    }
    pub fn ptid(&self) -> usize {
        let inner = self.inner_exclusive_access();
        let id = inner.ptid;
        id
    }

    pub fn pid(&self) -> usize {
        let process = self.process.upgrade().unwrap();
        process.getpid()
    }
    pub fn get_sig_mask(&self) -> SignalFlags {
        let inner = self.inner_exclusive_access();
        inner.sig_mask
    }
    pub fn set_sig_mask(&self, sig_mask: SignalFlags) {
        let mut inner = self.inner_exclusive_access();
        inner.sig_mask = sig_mask;
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
