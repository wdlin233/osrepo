//! Allocator for pid, task user resource, kernel stack using a simple recycle strategy.

use super::ProcessControlBlock;
use crate::config::{
    KERNEL_STACK_SIZE, KSTACK_TOP, PAGE_SIZE, TRAMPOLINE, USER_HEAP_SIZE, USER_STACK_SIZE, USER_STACK_TOP, USER_TRAP_CONTEXT_TOP
};
use crate::hal::trap::TrapContext;
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
        unsafe { UPSafeCell::new(RecycleAllocator::new(1)) };
}

/// heapid wrapper
pub struct HeapidHandle(pub usize);

/// Allocate a new PID
pub fn heap_id_alloc() -> HeapidHandle {
    HeapidHandle(HEAP_ID_ALLOCATOR.exclusive_access().alloc())
}

impl Drop for HeapidHandle {
    fn drop(&mut self) {
        HEAP_ID_ALLOCATOR.exclusive_access().dealloc(self.0);
    }
}



/// pid wrapper
pub struct PidHandle(pub usize);

/// Allocate a new PID
pub fn pid_alloc() -> PidHandle {
    PidHandle(PID_ALLOCATOR.exclusive_access().alloc())
}

/// 之前在这里发生过错误，姑且先继续保持着 Drop
impl Drop for PidHandle {
    fn drop(&mut self) {
        PID_ALLOCATOR.exclusive_access().dealloc(self.0);
    }
}



/// tid wrapper
pub struct TidHandle(pub usize);

/// Allocate a new PID
pub fn tid_alloc() -> TidHandle {
    TidHandle(TID_ALLOCATOR.exclusive_access().alloc())
}

impl Drop for TidHandle {
    fn drop(&mut self) {
        TID_ALLOCATOR.exclusive_access().dealloc(self.0);
    }
}



/// Return (bottom, top) of a kernel stack in kernel space.
pub fn kernel_stack_position(app_id: usize) -> (usize, usize) {
    let top = KSTACK_TOP - app_id * (KERNEL_STACK_SIZE + PAGE_SIZE);
    let bottom = top - KERNEL_STACK_SIZE;
    (bottom, top)
}

/// Kernel stack for a process
pub struct KernelStack {
    tid: usize,
}

impl KernelStack {
    pub fn new(tid_handle: &TidHandle) -> Self {
        let (kstack_bottom, kstack_top) = kernel_stack_position(tid_handle.0);
        KERNEL_SPACE.exclusive_access().insert_framed_area(
            kstack_bottom.into(),
            kstack_top.into(),
            (MapPermission::R | MapPermission::W),
            MapAreaType::Stack,
        );
        KernelStack(kstack_id)
    }

    /// return the top of the kernel stack
    pub fn get_top(&self) -> usize {
        debug!("(KernelStack), get_top");
        let (_, kernel_stack_top) = kernel_stack_position(self.tid);
        kernel_stack_top
    }
    ///
    pub fn pos(&self) -> (usize, usize) {
        kernel_stack_position(self.tid)
    }
    pub fn bottom(&self) -> usize {
        let (kernel_stack_bottom, _) = kernel_stack_position(self.tid);
        kernel_stack_bottom
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        KERNEL_SPACE.exclusive_access().remove_area_with_start_vpn(
            self.bottom().into(),
        );
    }
}