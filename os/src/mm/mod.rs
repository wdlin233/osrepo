//! Memory management implementation
//!
//! SV39 page-based virtual-memory architecture for RV64 systems, and
//! everything about memory management, like frame allocator, page table,
//! map area and memory set, is implemented here.
//!
//! Every task or process has a memory_set to control its virtual memory.
//mod address;
mod frame_allocator; // frame allocator
mod group;
mod map_area;
mod memory_set;
mod page_fault_handler;
mod page_table;
mod heap_allocator;
mod addr_range;

pub use frame_allocator::{frame_alloc, frame_dealloc, frames_alloc, FrameTracker};
pub use map_area::{MapArea, MapAreaType, MapPermission, MmapFile, MapType};
pub use memory_set::{MemorySet, MemorySetInner};
pub use page_table::{
    translated_byte_buffer, translated_ref,
    translated_refmut, translated_str, UserBuffer, UserBufferIterator,
};
pub use addr_range::{insert_bad_address, is_bad_address, remove_bad_address, BAD_ADDRESS, VAddrRange};

use polyhal::common::PageAlloc;
use polyhal::instruction::{ebreak, shutdown};
use polyhal::mem::{get_fdt, get_mem_areas};
use polyhal::println;

pub struct PageAllocImpl;

impl PageAlloc for PageAllocImpl {
    #[inline]
    fn alloc(&self) -> polyhal::PhysAddr {
        frame_allocator::frame_alloc_persist().expect("No memory left to allocate")
    }

    #[inline]
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