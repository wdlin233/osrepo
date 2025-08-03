//! Allocator for pid, task user resource, kernel stack using a simple recycle strategy.

use super::ProcessControlBlock;
use crate::config::{
    KERNEL_STACK_SIZE, PAGE_SIZE, TRAMPOLINE, USER_HEAP_BOTTOM, USER_HEAP_SIZE, USER_STACK_SIZE,
    USER_STACK_TOP, USER_TRAP_CONTEXT_TOP,
};
use crate::hal::trap::TrapContext;
use crate::mm::KERNEL_SPACE;
use crate::mm::{frame_alloc, translated_ref, FrameTracker, PhysAddr};
use crate::mm::{MapAreaType, MapPermission, PhysPageNum, VPNRange, VirtAddr, VirtPageNum};
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
    static ref KSTACK_ALLOCATOR: UPSafeCell<RecycleAllocator> =
        unsafe { UPSafeCell::new(RecycleAllocator::new(0)) };
}

/// The idle task's pid is 0
pub const IDLE_PID: usize = 0;

pub struct HeapidHandle(pub usize);

/// A handle to a pid
pub struct PidHandle(pub usize);

// impl Drop for PidHandle {
//     fn drop(&mut self) {
//         // trace!("drop pid {}", self.0);
//         PID_ALLOCATOR.exclusive_access().dealloc(self.0);
//     }
// }

impl Drop for HeapidHandle {
    fn drop(&mut self) {
        HEAP_ID_ALLOCATOR.exclusive_access().dealloc(self.0);
    }
}

pub fn pid_dealloc(id: usize) {
    PID_ALLOCATOR.exclusive_access().dealloc(id);
}

/// Allocate a new PID
pub fn pid_alloc() -> PidHandle {
    PidHandle(PID_ALLOCATOR.exclusive_access().alloc())
}
// pub fn heap_id_alloc() -> HeapidHandle {
//     HeapidHandle(HEAP_ID_ALLOCATOR.exclusive_access().alloc())
// }
pub fn heap_id_alloc() -> usize {
    HEAP_ID_ALLOCATOR.exclusive_access().alloc()
}
pub fn heap_id_dealloc(id: usize) {
    HEAP_ID_ALLOCATOR.exclusive_access().dealloc(id);
}
pub struct TidHandle(pub usize);

/// Allocate a new PID
pub fn tid_alloc() -> TidHandle {
    TidHandle(TID_ALLOCATOR.exclusive_access().alloc())
}
pub fn tid_dealloc(id: usize) {
    TID_ALLOCATOR.exclusive_access().dealloc(id);
}

/// Return (bottom, top) of a kernel stack in kernel space.
pub fn kernel_stack_position(app_id: usize) -> (usize, usize) {
    //debug!("in kernel stack position, app id is : {}", app_id);
    // TODO: How about low address such as 0x6000_0000 instead of TRAMPOLINE?
    let top = TRAMPOLINE - app_id * (KERNEL_STACK_SIZE + PAGE_SIZE);
    let bottom = top - KERNEL_STACK_SIZE;
    //debug!("kstack bottom is : {}, top is : {}", bottom, top);
    (bottom, top)
}

/// Kernel stack for a task
pub struct KernelStack(pub usize);

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
    /// return the top of the kernel stack
    pub fn get_top(&self) -> usize {
        debug!("in kernel stack, to get top");
        let (_, kernel_stack_top) = kernel_stack_position(self.0);
        kernel_stack_top
    }
    /// Push a variable of type T into the top of the KernelStack and return its raw pointer
    pub fn push_on_top<T>(&self, value: T) -> *mut T
    where
        T: Sized,
    {
        let kernel_stack_top = self.get_top();
        let ptr_mut = (kernel_stack_top - core::mem::size_of::<T>()) as *mut T;
        unsafe {
            *ptr_mut = value;
        }
        ptr_mut
    }
}

/// Return the bottom addr (low addr) of the trap context for a task
pub fn trap_cx_bottom_from_tid(tid: usize) -> usize {
    //debug!("in trap cx bottom from tid, the tid is : {}", tid);
    USER_TRAP_CONTEXT_TOP - tid * PAGE_SIZE
}
/// Return the bottom addr (high addr) of the user stack for a task
pub fn ustack_bottom_from_tid(tid: usize) -> usize {
    USER_STACK_TOP - tid * (PAGE_SIZE + USER_STACK_SIZE)
}

pub fn heap_bottom_from_id(id: usize) -> usize {
    USER_HEAP_BOTTOM + id * (USER_HEAP_SIZE + PAGE_SIZE)
}
