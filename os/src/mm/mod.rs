//! Memory management implementation
//!
//! SV39 page-based virtual-memory architecture for RV64 systems, and
//! everything about memory management, like frame allocator, page table,
//! map area and memory set, is implemented here.
//!
//! Every task or process has a memory_set to control its virtual memory.
mod frame_allocator;
mod heap_allocator;
mod memory_set;
mod page_table;
mod vpn_range;

pub use frame_allocator::{frame_alloc, frame_alloc_persist, frame_dealloc, frames_alloc,  add_frames_range, FrameTracker};
pub use memory_set::{MapPermission, MemorySet};
pub use page_table::{
    translated_byte_buffer, translated_ref, translated_refmut, translated_str,
    UserBuffer, UserBufferIterator,
};
pub use heap_allocator::init_heap;
use polyhal::VirtAddr;
use crate::{config::PAGE_SIZE, task::current_user_token};

/// write a value(`$T`) to the virtual address(dst)
pub fn copy_to_virt<T>(src: &T, dst: *mut T) {
    let src_buf_ptr: *const u8 = unsafe { core::mem::transmute(src) };
    let dst_buf_ptr: *mut u8 = unsafe { core::mem::transmute(dst) };
    let len = core::mem::size_of::<T>();

    let dst_frame_buffers = translated_byte_buffer(current_user_token(), dst_buf_ptr, len);

    let mut offset = 0;
    for dst_frame in dst_frame_buffers {
        dst_frame.copy_from_slice(
            unsafe { core::slice::from_raw_parts(src_buf_ptr.add(offset), dst_frame.len()) },
        );
        offset += dst_frame.len();
    }
}

/// iterator for phy/virt page number
pub trait StepByOne {
    /// step by one element(page number)
    fn step(&mut self);
}

impl StepByOne for VirtAddr {
    fn step(&mut self) {
        let addr = self.get_mut_ptr() as *const usize as usize;
        *self = VirtAddr::new(addr + PAGE_SIZE);
    }
}
