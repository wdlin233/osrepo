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
mod heap_allocator;

pub use address::VPNRange;
pub use address::{
    copy_to_virt, insert_bad_address, is_bad_address, remove_bad_address, PhysAddr, PhysPageNum,
    StepByOne, VirtAddr, VirtPageNum,
};
pub use frame_allocator::{frame_alloc, frame_dealloc, FrameTracker};
pub use map_area::MapType;
pub use map_area::{MapArea, MapAreaType, MapPermission, MmapFile};
#[cfg(target_arch = "riscv64")]
pub use memory_set::{kernel_token, remap_test, KERNEL_SPACE};
pub use memory_set::{MemorySet, MemorySetInner};
use page_table::PTEFlags;
pub use page_table::{
    flush_tlb, safe_translated_byte_buffer, translated_byte_buffer, translated_ref,
    translated_refmut, translated_str, PageTable, PageTableEntry, UserBuffer, UserBufferIterator,
};

use polyhal::common::PageAlloc;
use polyhal::instruction::{ebreak, shutdown};
use polyhal::mem::{get_fdt, get_mem_areas};
use polyhal::println;

pub struct PageAllocImpl;

impl PageAlloc for PageAllocImpl {
    fn alloc(&self) -> polyhal::PhysAddr {
        frame_allocator::frame_alloc(1)
    }

    fn dealloc(&self, paddr: polyhal::PhysAddr) {
        frame_allocator::frame_dealloc(paddr);
    }
}

/// initiate heap allocator, frame allocator and kernel space
pub fn init() {
    heap_allocator::init_heap();
    info!("Heap allocator initialized");
    polyhal::common::init(&PageAllocImpl);
    get_mem_areas().for_each(|(start, size)| {
        println!("init memory region {:#x} - {:#x}", start, start + size);
        frame_allocator::add_frame_range(*start, start + size);
    });

    if let Ok(fdt) = get_fdt() {
        fdt.all_nodes().for_each(|x| {
            if let Some(mut compatibles) = x.compatible() {
                log::debug!("Node Compatiable: {:?}", compatibles.next());
            }
        });
    }

    // test
    ebreak();
    //shutdown();
}