//! Implementation of [`FrameAllocator`] which
//! controls all the frames in the operating system.
use crate::sync::UPSafeCell;
use alloc::sync::Arc;
use alloc::vec::Vec;
use polyhal::pagetable::PAGE_SIZE;
use lazy_static::*;
use polyhal::PhysAddr;
use crate::println;
use buddy_system_allocator::FrameAllocator;

lazy_static! {
    /// frame allocator instance through lazy_static!
    pub static ref FRAME_ALLOCATOR: UPSafeCell<FrameAllocator<32>> =
        unsafe { UPSafeCell::new(FrameAllocator::new()) };
}

pub fn add_frame_range(mm_start: usize, mm_end: usize) {
    extern "C" {
        fn _end();
    }
    let mm_start = if mm_start <= mm_end && mm_end > _end as usize {
        (_end as usize + PAGE_SIZE - 1) / PAGE_SIZE
    } else {
        mm_start / PAGE_SIZE
    };
    let mm_end = mm_end / PAGE_SIZE;
    FRAME_ALLOCATOR.exclusive_access().add_frame(mm_start, mm_end);
}

/// Allocate a physical page frame in FrameTracker style
pub fn frame_alloc(count: usize) -> PhysAddr {
    let ppn = FRAME_ALLOCATOR
        .exclusive_access()
        .alloc(count)
        .expect("can't find memory page");
    PhysAddr::new(ppn << 12)
}

/// Deallocate a physical page frame with a given ppn
pub fn frame_dealloc(paddr: PhysAddr) {
    FRAME_ALLOCATOR.exclusive_access().dealloc(paddr.raw() >> 12, 1);
}

 use crate::mm::PhysPageNum;
#[derive(Clone)]
pub struct FrameTracker {
    /// physical page number
    pub ppn: PhysPageNum,
}