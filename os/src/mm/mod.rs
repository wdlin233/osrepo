//! Memory management implementation
//!
//! SV39 page-based virtual-memory architecture for RV64 systems, and
//! everything about memory management, like frame allocator, page table,
//! map area and memory set, is implemented here.
//!
//! Every task or process has a memory_set to control its virtual memory.
mod address;
mod frame_allocator;
mod heap_allocator;
mod memory_set;
mod page_table;
mod vpn_range;

pub use address::{PhysAddr, PhysPageNum, StepByOne, VirtAddr, VirtPageNum, copy_to_virt};
pub use frame_allocator::{frame_alloc, frame_alloc_persist, frame_dealloc, frames_alloc, FrameTracker};
pub use memory_set::{MapPermission, MemorySet};
pub use page_table::{
    translated_byte_buffer, translated_ref, translated_refmut, translated_str,
    PageTableEntry, UserBuffer, UserBufferIterator,
};

