//! Implementation of [`FrameAllocator`] which
//! controls all the frames in the operating system.
use core::{
    fmt::{self, Debug, Formatter},
    mem::size_of,
};

use crate::sync::UPSafeCell;
use alloc::sync::Arc;
use alloc::vec::Vec;
use polyhal::pagetable::PAGE_SIZE;
use lazy_static::*;
use polyhal::{pa, PhysAddr};
use crate::println;
use buddy_system_allocator::FrameAllocator;

lazy_static! {
    /// frame allocator instance through lazy_static!
    pub static ref FRAME_ALLOCATOR: UPSafeCell<FrameAllocator<32>> =
        unsafe { UPSafeCell::new(FrameAllocator::new()) };
}

pub fn add_frame_range(mm_start: usize, mm_end: usize) {
    unsafe {
        core::slice::from_raw_parts_mut(
            pa!(mm_start).get_mut_ptr::<u128>(),
            (mm_end - mm_start) / size_of::<u128>(),
        )
        .fill(0);
    }
    let start = (mm_start + 0xfff) / PAGE_SIZE;
    FRAME_ALLOCATOR.exclusive_access().add_frame(start, mm_end / PAGE_SIZE);
}

/// Allocate a physical page frame in FrameTracker style
pub fn frame_alloc() -> Option<Arc<FrameTracker>> {
    FRAME_ALLOCATOR
        .exclusive_access()
        .alloc(1)
        .map(|x| pa!(x * PAGE_SIZE))
        .map(FrameTracker::new)
        .inspect(|x| x.paddr.clear_len(PAGE_SIZE))
}

pub fn frame_alloc_persist() -> Option<PhysAddr> {
    FRAME_ALLOCATOR
        .exclusive_access()
        .alloc(1)
        .map(|x| pa!(x * PAGE_SIZE))
        .inspect(|x| x.clear_len(PAGE_SIZE))
}

#[allow(unused)]
pub fn frames_alloc(count: usize) -> Option<Vec<Arc<FrameTracker>>> {
    let start = FRAME_ALLOCATOR
        .exclusive_access()
        .alloc(count)
        .map(|x| pa!(x * PAGE_SIZE))?;
    let ret = (0..count)
        .into_iter()
        .map(|idx| (start + idx * PAGE_SIZE))
        .map(FrameTracker::new)
        .inspect(|x| x.paddr.clear_len(PAGE_SIZE))
        .collect();
    Some(ret)
}

/// Deallocate a physical page frame with a given ppn
pub fn frame_dealloc(paddr: PhysAddr) {
    FRAME_ALLOCATOR.exclusive_access().dealloc(paddr.raw() / PAGE_SIZE, 1);
}

#[derive(Clone)]
pub struct FrameTracker {
    pub paddr: PhysAddr,
}

impl FrameTracker {
    pub fn new(paddr: PhysAddr) -> Arc<Self> {
        // page cleaning
        paddr.clear_len(PAGE_SIZE);
        Arc::new(Self { paddr })
    }
}

impl Debug for FrameTracker {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("FrameTracker:PA={:?}", self.paddr))
    }
}

impl Drop for FrameTracker {
    fn drop(&mut self) {
        trace!("drop frame tracker: {:?}", self.paddr);
        frame_dealloc(self.paddr);
    }
}