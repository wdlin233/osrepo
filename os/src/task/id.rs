//! Allocator for pid, task user resource, kernel stack using a simple recycle strategy.

use super::ProcessControlBlock;
use crate::config::{
    KERNEL_STACK_SIZE, PAGE_SIZE, TRAMPOLINE, USER_HEAP_SIZE, USER_STACK_SIZE, USER_STACK_TOP,
    USER_TRAP_CONTEXT_TOP,
};
use crate::hal::trap::TrapContext;
#[cfg(target_arch = "riscv64")]
use crate::mm::KERNEL_SPACE;
use crate::mm::{frame_alloc, translated_ref, FrameTracker, PhysAddr};
use crate::mm::{MapAreaType, MapPermission, PhysPageNum, VPNRange, VirtAddr, VirtPageNum};
use crate::phys_to_virt;
use crate::sync::UPSafeCell;
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use lazy_static::*;
use lwext4_rust::file::PAGE_MASK;
//use virtio_drivers::PAGE_SIZE;

/// Allocator with a simple recycle strategy
pub struct RecycleAllocator {
    current: usize,
    recycled: Vec<usize>,
}

impl RecycleAllocator {
    /// Create a new allocator
    pub fn new(start: usize) -> Self {
        RecycleAllocator {
            current: start,
            recycled: Vec::new(),
        }
    }
    /// allocate a new item
    pub fn alloc(&mut self) -> usize {
        info!(
            "(RecycleAllocator, alloc) recycle allocator alloc: current id {}, recycled {:?}",
            self.current, self.recycled
        );
        if let Some(id) = self.recycled.pop() {
            info!(
                "(RecycleAllocator, alloc) recycle allocator alloc: recycled id {}",
                id
            );
            id
        } else {
            self.current += 1;
            return self.current - 1;
        }
    }
    /// deallocate an item
    pub fn dealloc(&mut self, id: usize) {
        assert!(id < self.current);
        assert!(
            !self.recycled.iter().any(|i| *i == id),
            "id {} has been deallocated!",
            id
        );
        info!(
            "(RecycleAllocator, dealloc) recycle allocator dealloc: id {}",
            id
        );
        self.recycled.push(id);
    }
}

lazy_static! {
    /// Glocal allocator for pid
    static ref PID_ALLOCATOR: UPSafeCell<RecycleAllocator> =
        unsafe { UPSafeCell::new(RecycleAllocator::new(1)) };
        static ref TID_ALLOCATOR: UPSafeCell<RecycleAllocator> =
        unsafe { UPSafeCell::new(RecycleAllocator::new(1)) };

        static ref HEAP_ID_ALLOCATOR: UPSafeCell<RecycleAllocator> =
        unsafe { UPSafeCell::new(RecycleAllocator::new(0)) };
}
#[cfg(target_arch = "riscv64")]
lazy_static! {
    /// Global allocator for kernel stack
    static ref KSTACK_ALLOCATOR: UPSafeCell<RecycleAllocator> =
        unsafe { UPSafeCell::new(RecycleAllocator::new(0)) };
}

/// The idle task's pid is 0
pub const IDLE_PID: usize = 0;

pub struct HeapidHandle(pub usize);

/// Allocate a new PID
pub fn heap_id_alloc() -> HeapidHandle {
    HeapidHandle(HEAP_ID_ALLOCATOR.exclusive_access().alloc())
}

/// A handle to a pid
pub struct PidHandle(pub usize);

// impl Drop for PidHandle {
//     fn drop(&mut self) {
//         // trace!("drop pid {}", self.0);
//         PID_ALLOCATOR.exclusive_access().dealloc(self.0);
//     }
// }
pub fn pid_dealloc(id: usize) {
    PID_ALLOCATOR.exclusive_access().dealloc(id);
}

/// Allocate a new PID
pub fn pid_alloc() -> PidHandle {
    PidHandle(PID_ALLOCATOR.exclusive_access().alloc())
}

pub struct TidHandle(pub usize);

/// Allocate a new PID
pub fn tid_alloc() -> TidHandle {
    TidHandle(TID_ALLOCATOR.exclusive_access().alloc())
}
pub fn tid_dealloc(id: usize) {
    TID_ALLOCATOR.exclusive_access().dealloc(id);
}

#[cfg(target_arch = "riscv64")]
/// Return (bottom, top) of a kernel stack in kernel space.
pub fn kernel_stack_position(app_id: usize) -> (usize, usize) {
    //debug!("in kernel stack position, app id is : {}", app_id);
    let top = TRAMPOLINE - app_id * (KERNEL_STACK_SIZE + PAGE_SIZE);
    let bottom = top - KERNEL_STACK_SIZE;
    //debug!("kstack bottom is : {}, top is : {}", bottom, top);
    (bottom, top)
}

#[cfg(target_arch = "riscv64")]
/// Kernel stack for a task
pub struct KernelStack(pub usize);

#[cfg(target_arch = "loongarch64")]
pub struct KernelStack {
    pub frame: FrameTracker,
}

#[cfg(target_arch = "riscv64")]
/// Allocate a kernel stack for a task
pub fn kstack_alloc() -> KernelStack {
    //debug!("in kstack alloc");
    let kstack_id = KSTACK_ALLOCATOR.exclusive_access().alloc();
    //debug!("kstack id is : {}", kstack_id);
    let (kstack_bottom, kstack_top) = kernel_stack_position(kstack_id);
    //debug!("to map kernel space");
    KERNEL_SPACE.exclusive_access().insert_framed_area(
        kstack_bottom.into(),
        kstack_top.into(),
        MapPermission::R | MapPermission::W,
        MapAreaType::Stack,
    );
    KernelStack(kstack_id)
}

#[cfg(target_arch = "riscv64")]
impl Drop for KernelStack {
    fn drop(&mut self) {
        debug!("to drop kernel stack");
        let (kernel_stack_bottom, _) = kernel_stack_position(self.0);
        let kernel_stack_bottom_va: VirtAddr = kernel_stack_bottom.into();
        KERNEL_SPACE
            .exclusive_access()
            .remove_area_with_start_vpn(kernel_stack_bottom_va.into());
        KSTACK_ALLOCATOR.exclusive_access().dealloc(self.0);
    }
}

/// Create a kernelstack
/// 在loongArch平台上，并不需要根据pid在内核空间分配内核栈
/// 内核态并不处于页表翻译模式，而是以类似于直接管理物理内存的方式管理
/// 因此这里会直接申请对应大小的内存空间
/// 但这也会造成内核栈无法被保护的状态
impl KernelStack {
    #[cfg(target_arch = "loongarch64")]
    pub fn new() -> Self {
        frame_alloc().map(|frame| KernelStack { frame }).unwrap()
    }

    #[cfg(target_arch = "riscv64")]
    /// return the top of the kernel stack
    pub fn get_top(&self) -> usize {
        debug!("in kernel stack, to get top");
        let (_, kernel_stack_top) = kernel_stack_position(self.0);
        kernel_stack_top
    }
    #[cfg(target_arch = "loongarch64")]
    fn get_virt_top(&self) -> usize {
        let top: PhysAddr = self.frame.ppn.into();
        let top = phys_to_virt!(top.0 + PAGE_SIZE);
        top
    }
    /// Push a variable of type T into the top of the KernelStack and return its raw pointer
    pub fn push_on_top<T>(&self, value: T) -> *mut T
    where
        T: Sized,
    {
        #[cfg(target_arch = "riscv64")]
        let kernel_stack_top = self.get_top();
        #[cfg(target_arch = "loongarch64")]
        let kernel_stack_top = self.get_virt_top();
        let ptr_mut = (kernel_stack_top - core::mem::size_of::<T>()) as *mut T;
        unsafe {
            *ptr_mut = value;
        }
        ptr_mut
    }

    #[cfg(target_arch = "loongarch64")]
    pub fn copy_from_other(&mut self, kernel_stack: &KernelStack) -> &mut Self {
        //需要从kernel_stack复制到self
        let trap_context = kernel_stack.get_trap_cx().clone();
        self.push_on_top(trap_context);
        self
    }
    /// 返回trap上下文的可变引用
    /// 用于修改返回值
    #[cfg(target_arch = "loongarch64")]
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        let cx = self.get_virt_top() - core::mem::size_of::<TrapContext>();
        unsafe { &mut *(cx as *mut TrapContext) }
    }

    /// 返回trap上下文的位置，用于初始化trap上下文
    #[cfg(target_arch = "loongarch64")]
    pub fn get_trap_addr(&self) -> usize {
        let addr = self.get_virt_top() - core::mem::size_of::<TrapContext>();
        addr
    }
}

/// User Resource for a task
pub struct TaskUserRes {
    /// task id
    pub tid: usize,
    /// user stack base
    pub ustack_base: usize,
    /// process belongs to
    pub process: Weak<ProcessControlBlock>,
    //
    pub is_exec: bool,
}

#[cfg(target_arch = "riscv64")]
/// Return the bottom addr (low addr) of the trap context for a task
fn trap_cx_bottom_from_tid(tid: usize) -> usize {
    //debug!("in trap cx bottom from tid, the tid is : {}", tid);
    USER_TRAP_CONTEXT_TOP - tid * PAGE_SIZE
}
/// Return the bottom addr (high addr) of the user stack for a task
fn ustack_bottom_from_tid(_ustack_base: usize, tid: usize) -> usize {
    USER_STACK_TOP - tid * (PAGE_SIZE + USER_STACK_SIZE)
}

// fn uheap_bottom_from_tid(tid: usize) -> usize {
//     HEAP_BASE + tid * HEAP_SIZE
// }

// fn uheap_top_from_tid(tid: usize) -> usize {
//     uheap_bottom_from_tid(tid) - PAGE_SIZE - 1
// }

impl TaskUserRes {
    /// Create a new TaskUserRes (Task User Resource)
    pub fn new(
        process: Arc<ProcessControlBlock>,
        ustack_base: usize,
        alloc_user_res: bool,
    ) -> Self {
        //debug!("in task user res new");
        let tid = process.inner_exclusive_access().alloc_tid();
        // debug!(
        //     "in task user res new, ustack_base:{},tid:{}",
        //     ustack_base, tid
        // );
        //let is_exec = alloc_user_res;
        let is_exec = true;
        // let user_hp = if is_exec {
        //     uheap_bottom_from_tid(tid)
        // } else {
        //     uheap_bottom_from_tid(tid - 1)
        // };
        // let user_sp = if is_exec {
        //     debug!("get user sp, give tid");
        //     ustack_bottom_from_tid(ustack_base, tid) + USER_STACK_SIZE
        // } else {
        //     debug!("get user sp,give  tid");
        //     ustack_bottom_from_tid(ustack_base, tid - 1) + USER_STACK_SIZE
        // };
        //debug!("in taskuserres new,user_sp(brk):{}",user_sp);

        let mut task_user_res = Self {
            tid,
            ustack_base,
            process: Arc::downgrade(&process),
            // heap_bottom: user_hp,
            // program_brk: user_hp,
            is_exec,
        };
        if alloc_user_res {
            //debug!("to alloc user res");
            task_user_res.alloc_user_res();
        }
        task_user_res
    }

    ///get tid
    pub fn gettid(&self) -> usize {
        self.tid
    }

    /// Allocate user resource for a task
    pub fn alloc_user_res(&mut self) {
        //debug!("in alloc user res");
        let process = self.process.upgrade().unwrap();
        let mut process_inner = process.inner_exclusive_access();

        // alloc user stack
        //debug!("to get ustack bottom, give tid, tid is : {}", self.tid);
        let ustack_bottom = ustack_bottom_from_tid(self.ustack_base, self.tid);
        let ustack_top = ustack_bottom + USER_STACK_SIZE;
        // self.heap_bottom = ustack_top + PAGE_SIZE;
        // self.program_brk = ustack_top + PAGE_SIZE;

        // debug!(
        //     "ustack_bottom = {},ustack_top = {}",
        //     ustack_bottom, ustack_top
        // );
        process_inner.memory_set.insert_framed_area(
            ustack_bottom.into(),
            ustack_top.into(),
            MapPermission::default() | MapPermission::W,
            MapAreaType::Stack,
        );

        // alloc user heap
        // debug!("heap_bottom = {},program_brk = {}",self.heap_bottom,self.program_brk);
        // process_inner.memory_set.insert_framed_area(
        //     self.heap_bottom.into(),
        //     self.program_brk.into(),
        //     MapPermission::default() | MapPermission::W,
        //     MapAreaType::Brk,
        // );
        // alloc trap_cx
        #[cfg(target_arch = "riscv64")]
        {
            debug!("to get trap cx bottom, give tid, like up");
            let trap_cx_bottom = trap_cx_bottom_from_tid(self.tid);
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

    /// Deallocate user resource for a task
    fn dealloc_user_res(&self) {
        // dealloc tid
        let process = self.process.upgrade().unwrap();
        let mut process_inner = process.inner_exclusive_access();
        // dealloc ustack manually
        let ustack_bottom_va: VirtAddr = ustack_bottom_from_tid(self.ustack_base, self.tid).into();
        process_inner
            .memory_set
            .remove_area_with_start_vpn(ustack_bottom_va.into());
        // dealloc user heap manually
        // let heap_bottom_va: VirtAddr = self.heap_bottom.into();
        // process_inner
        //     .memory_set
        //     .remove_area_with_start_vpn(heap_bottom_va.into());
        // dealloc trap_cx manually
        #[cfg(target_arch = "riscv64")]
        {
            debug!("in dealloc user res");
            if self.is_exec {
                let trap_cx_bottom_va: VirtAddr = trap_cx_bottom_from_tid(self.tid).into();
                process_inner
                    .memory_set
                    .remove_area_with_start_vpn(trap_cx_bottom_va.into());
            } else {
                let trap_cx_bottom_va: VirtAddr = trap_cx_bottom_from_tid(self.tid - 1).into();
                process_inner
                    .memory_set
                    .remove_area_with_start_vpn(trap_cx_bottom_va.into());
            }
        }
    }

    #[allow(unused)]
    /// alloc task id
    /// Used in RV
    pub fn alloc_tid(&mut self) {
        self.tid = self
            .process
            .upgrade()
            .unwrap()
            .inner_exclusive_access()
            .alloc_tid();
    }
    /// dealloc task id
    pub fn dealloc_tid(&self) {
        let process = self.process.upgrade().unwrap();
        let mut process_inner = process.inner_exclusive_access();
        process_inner.dealloc_tid(self.tid);
    }
    #[cfg(target_arch = "riscv64")]
    /// The bottom usr vaddr (low addr) of the trap context for a task with tid
    pub fn trap_cx_user_va(&self) -> usize {
        //debug!("in task user res, trap cx user va, to get trap cx bottom from tid");
        if self.is_exec {
            trap_cx_bottom_from_tid(self.tid)
        } else {
            trap_cx_bottom_from_tid(self.tid - 1)
        }
    }
    #[cfg(target_arch = "riscv64")]
    /// The physical page number(ppn) of the trap context for a task with tid
    pub fn trap_cx_ppn(&self) -> PhysPageNum {
        debug!("in task user res, trap cx ppn , self tid is : {}", self.tid);
        let process = self.process.upgrade().unwrap();
        let process_inner = process.inner_exclusive_access();
        //let trap_cx_bottom_va: VirtAddr = trap_cx_bottom_from_tid(self.tid).into();
        if self.is_exec {
            // get self trap cx
            debug!("to get self trap cx, give tid");
            let trap_cx_bottom_va: VirtAddr = trap_cx_bottom_from_tid(self.tid).into();
            process_inner
                .memory_set
                .translate(trap_cx_bottom_va.into())
                .unwrap()
                .ppn()
        } else {
            // get parent trap cx
            debug!("to get parent trap cx, give tid");
            let trap_cx_bottom_va: VirtAddr = trap_cx_bottom_from_tid(self.tid - 1).into();
            process_inner
                .memory_set
                .translate(trap_cx_bottom_va.into())
                .unwrap()
                .ppn()
        }
    }
    /// the bottom addr (low addr) of the user stack for a task
    pub fn ustack_base(&self) -> usize {
        self.ustack_base
    }
    /// the top addr (high addr) of the user stack for a task
    pub fn ustack_top(&self, _get_self: bool) -> usize {
        debug!(
            "in ustack top, ustack base is :{}, tid is :{}",
            self.ustack_base, self.tid
        );
        ustack_bottom_from_tid(self.ustack_base, self.tid) + USER_STACK_SIZE
        // if _get_self {
        //     ustack_bottom_from_tid(self.ustack_base, self.tid) + USER_STACK_SIZE
        // } else {
        //     ustack_bottom_from_tid(self.ustack_base, self.tid - 1) + USER_STACK_SIZE
        // }
    }
}

impl Drop for TaskUserRes {
    fn drop(&mut self) {
        self.dealloc_tid();
        self.dealloc_user_res();
    }
}
