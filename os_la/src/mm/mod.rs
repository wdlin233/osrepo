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
mod page_fault_handler;
mod map_area;
mod group;

#[cfg(target_arch = "riscv64")]
mod heap_allocator;
#[cfg(target_arch = "loongarch64")]
pub mod system_allocator; // heap allocator


use address::VPNRange;
pub use address::{insert_bad_address, is_bad_address, remove_bad_address, PhysAddr, PhysPageNum, StepByOne, VirtAddr, VirtPageNum, copy_to_virt};
pub use frame_allocator::{frame_alloc, frame_dealloc, FrameTracker, frame_alloc_contiguous};
pub use memory_set::MemorySet;
use page_table::PTEFlags;
pub use page_table::{
    translated_byte_buffer, translated_ref, translated_refmut, translated_str, PageTable,
    PageTableEntry, UserBuffer, UserBufferIterator, safe_translated_byte_buffer,
};
pub use map_area::{MapArea, MapAreaType, MapPermission, MmapFile};
#[cfg(target_arch = "riscv64")]
pub use memory_set::{KERNEL_SPACE, kernel_token, remap_test};
#[cfg(target_arch = "riscv64")]
pub use map_area::MapType;

#[cfg(target_arch = "loongarch64")]
use crate::{
    config::VIRT_BIAS,
};

#[cfg(target_arch = "loongarch64")]
use crate::mm::system_allocator::init_heap;

/// initiate heap allocator, frame allocator and kernel space
pub fn init() {
    #[cfg(target_arch = "riscv64")]
    heap_allocator::init_heap();
    #[cfg(target_arch = "loongarch64")]
    system_allocator::init_heap();
    info!("Heap allocator initialized");

    frame_allocator::init_frame_allocator();
    info!("Frame allocator initialized");

    #[cfg(target_arch = "riscv64")]
    KERNEL_SPACE.exclusive_access().activate();
}

#[macro_export]
macro_rules! virt_to_phys {
    ($va:expr) => {
        $va - crate::config::VIRT_BIAS
    };
}
/// Translate a physical address to a virtual address.
#[macro_export]
macro_rules! phys_to_virt {
    ($pa:expr) => {
        $pa + crate::config::VIRT_BIAS
    };
}
