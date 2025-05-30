//! Memory management implementation
//!
//! SV39 page-based virtual-memory architecture for RV64 systems, and
//! everything about memory management, like frame allocator, page table,
//! map area and memory set, is implemented here.
//!
//! Every task or process has a memory_set to control its virtual memory.
mod address;
mod memory_set;
mod page_table;
mod frame_allocator; // frame allocator

#[cfg(target_arch = "riscv64")]
mod heap_allocator;

#[cfg(target_arch = "loongarch64")]
pub mod system_allocator; // heap allocator


use address::VPNRange;
pub use address::{PhysAddr, PhysPageNum, StepByOne, VirtAddr, VirtPageNum, copy_to_virt};
pub use frame_allocator::{frame_alloc, frame_dealloc, FrameTracker};
pub use memory_set::remap_test;
pub use memory_set::{kernel_token, MapPermission, MemorySet, KERNEL_SPACE};
use page_table::PTEFlags;
pub use page_table::{
    translated_byte_buffer, translated_ref, translated_refmut, translated_str, PageTable,
    PageTableEntry, UserBuffer, UserBufferIterator,
};
use crate::{
    loongarch::VIRT_BIAS,
};

#[cfg(target_arch = "loongarch64")]
use crate::mm::system_allocator::init_heap;

/// initiate heap allocator, frame allocator and kernel space
pub fn init() {
    #[cfg(target_arch = "riscv64")]
    heap_allocator::init_heap();
    #[cfg(target_arch = "loongarch64")]
    system_allocator::init_heap();

    frame_allocator::init_frame_allocator();
    
    #[cfg(target_arch = "riscv64")]
    KERNEL_SPACE.exclusive_access().activate();
}

#[macro_export]
macro_rules! virt_to_phys {
    ($va:expr) => {
        $va - crate::loongarch::VIRT_BIAS
    };
}
/// Translate a physical address to a virtual address.
#[macro_export]
macro_rules! phys_to_virt {
    ($pa:expr) => {
        $pa + crate::loongarch::VIRT_BIAS
    };
}
