//! Memory management implementation
//!
//! SV39 page-based virtual-memory architecture for RV64 systems, and
//! everything about memory management, like frame allocator, page table,
//! map area and memory set, is implemented here.
//!
//! Every task or process has a memory_set to control its virtual memory.
mod address;
mod frame_allocator; // frame allocator
mod group;
mod map_area;
mod memory_set;
mod page_fault_handler;
mod page_table;
mod shm;
mod heap_allocator;

pub use address::VPNRange;
pub use address::{
    copy_to_virt, insert_bad_address, is_bad_address, remove_bad_address, PhysAddr, PhysPageNum,
    StepByOne, VirtAddr, VirtPageNum,
};
pub use frame_allocator::{frame_alloc, frame_dealloc, FrameTracker};
#[cfg(target_arch = "riscv64")]
pub use map_area::MapType;
pub use map_area::{MapArea, MapAreaType, MapPermission, MmapFile};
#[cfg(target_arch = "riscv64")]
pub use memory_set::{kernel_token, remap_test, KERNEL_SPACE};
pub use memory_set::{MemorySet, MemorySetInner};
use page_table::PTEFlags;
pub use page_table::{
    flush_tlb, put_data, safe_translated_byte_buffer, translated_byte_buffer, translated_ref,
    translated_refmut, translated_str, PageTable, PageTableEntry, UserBuffer, UserBufferIterator,
};
pub use shm::*;

/// initiate heap allocator, frame allocator and kernel space
pub fn init() {
    heap_allocator::init_heap();
    info!("Heap allocator initialized");

    frame_allocator::init_frame_allocator();
    info!("Frame allocator initialized");

    #[cfg(target_arch = "riscv64")]
    KERNEL_SPACE.exclusive_access().activate();
    #[cfg(target_arch = "riscv64")]
    remap_test();
}

#[macro_export]
macro_rules! virt_to_phys {
    ($va:expr) => {
        $va - 0x9000_0000_0000_0000
    };
}
/// Translate a physical address to a virtual address.
#[macro_export]
macro_rules! phys_to_virt {
    ($pa:expr) => {
        $pa + 0x9000_0000_0000_0000
    };
}
