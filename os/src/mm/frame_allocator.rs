//! Implementation of [`FrameAllocator`] which
//! controls all the frames in the operating system.
use super::{PhysAddr, PhysPageNum};
use crate::config::MEMORY_END;
use crate::mm::address::KernelAddr;
use crate::sync::UPSafeCell;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};
use lazy_static::*;
use crate::virt_to_phys;
use crate::println;

/// tracker for physical page frame allocation and deallocation
#[derive(Clone)]
pub struct FrameTracker {
    /// physical page number
    pub ppn: PhysPageNum,
}

impl FrameTracker {
    /// Create a new FrameTracker
    pub fn new(ppn: PhysPageNum) -> Self {
        // page cleaning
        let bytes_array = ppn.get_bytes_array();
        for i in bytes_array {
            *i = 0;
        }
        Self { ppn }
    }
}

impl Debug for FrameTracker {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("FrameTracker:PPN={:#x}", self.ppn.0))
    }
}

impl Drop for FrameTracker {
    fn drop(&mut self) {
        frame_dealloc(self.ppn);
    }
}

trait FrameAllocator {
    fn new() -> Self;
    fn alloc(&mut self) -> Option<PhysPageNum>;
    fn dealloc(&mut self, ppn: PhysPageNum);
    fn alloc_coniguous(&mut self, count: usize) -> (Vec<PhysPageNum>, PhysPageNum);
}
/// an implementation for frame allocator
pub struct StackFrameAllocator {
    current: usize,
    end: usize,
    recycled: Vec<usize>,
}

impl StackFrameAllocator {
    pub fn init(&mut self, l: PhysPageNum, r: PhysPageNum) {
        self.current = l.0;
        self.end = r.0;
        // trace!("last {} Physical Frames.", self.end - self.current);
    }
}
impl FrameAllocator for StackFrameAllocator {
    fn new() -> Self {
        Self {
            current: 0,
            end: 0,
            recycled: Vec::new(),
        }
    }
    fn alloc(&mut self) -> Option<PhysPageNum> {
        if let Some(ppn) = self.recycled.pop() {
            Some(ppn.into())
        } else if self.current == self.end {
            None
        } else {
            self.current += 1;
            Some((self.current - 1).into())
        }
    }
    fn dealloc(&mut self, ppn: PhysPageNum) {
        let ppn = ppn.0;
        // validity check
        if ppn >= self.current || self.recycled.iter().any(|&v| v == ppn) {
            panic!("Frame ppn={:#x} has not been allocated!", ppn);
        }
        // recycle
        self.recycled.push(ppn);
    }
    fn alloc_coniguous(&mut self, count: usize) -> (Vec<PhysPageNum>, PhysPageNum) {
        let mut ret = Vec::with_capacity(count);
        let root_ppn = self.current;
        for _ in 0..count {
            if self.current == self.end {
                panic!("No more physical frames available for allocation!");
            } else {
                self.current += 1;
                ret.push((self.current - 1).into());
            }
        }
        (ret, root_ppn.into())
    }
}

type FrameAllocatorImpl = StackFrameAllocator;

lazy_static! {
    /// frame allocator instance through lazy_static!
    pub static ref FRAME_ALLOCATOR: UPSafeCell<FrameAllocatorImpl> =
        unsafe { UPSafeCell::new(FrameAllocatorImpl::new()) };
}
/// initiate the frame allocator using `ekernel` and `MEMORY_END`
pub fn init_frame_allocator() {
    extern "C" {
        fn ekernel();
    }
    FRAME_ALLOCATOR.exclusive_access().init(
        PhysAddr::from(KernelAddr::from(ekernel as usize)).ceil(),
        PhysAddr::from(KernelAddr::from(MEMORY_END)).floor(),
    );
    #[cfg(target_arch = "loongarch64")]
    {
        println!(
            "frame range: {:#x}-{:#x}",
            PhysAddr::from(virt_to_phys!(ekernel as usize)).ceil().0,
            PhysAddr::from(virt_to_phys!(MEMORY_END)).floor().0
        );
        FRAME_ALLOCATOR.exclusive_access().init(
            PhysAddr::from(virt_to_phys!(ekernel as usize)).ceil(),
            PhysAddr::from(virt_to_phys!(MEMORY_END)).floor(),
        );
    }
}

/// Allocate a physical page frame in FrameTracker style
pub fn frame_alloc() -> Option<Arc<FrameTracker>> {
    FRAME_ALLOCATOR
        .exclusive_access()
        .alloc()
        .map(FrameTracker::new)
        .map(Arc::new)
}

/// Deallocate a physical page frame with a given ppn
pub fn frame_dealloc(ppn: PhysPageNum) {
    FRAME_ALLOCATOR.exclusive_access().dealloc(ppn);
}

/// Frame allocation for contiguous frames
pub fn frame_alloc_contiguous(count: usize) -> (Vec<FrameTracker>, PhysPageNum) {
    let (frames, root_ppn) = FRAME_ALLOCATOR.exclusive_access().alloc_coniguous(count);
    let frame_trackers: Vec<FrameTracker> = frames.iter().map(|&p| FrameTracker::new(p)).collect();
    (frame_trackers, root_ppn)    
}
