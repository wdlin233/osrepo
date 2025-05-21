//! Implementation of [`PageTableEntry`] and [`PageTable`].
use super::{PhysPageNum};
use alloc::string::String;
use alloc::vec::Vec;
use bitflags::*;
use polyhal::pagetable::PageTable;
use _core::slice;
use _core::str::from_utf8_unchecked;
use alloc::string::{ToString};

bitflags! {
    /// page table entry flags
    pub struct PTEFlags: u8 {
        const V = 1 << 0;
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const A = 1 << 6;
        const D = 1 << 7;
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
/// page table entry structure
pub struct PageTableEntry {
    /// bits of page table entry
    pub bits: usize,
}

impl PageTableEntry {
    /// Create a new page table entry
    pub fn new(ppn: PhysPageNum, flags: PTEFlags) -> Self {
        PageTableEntry {
            bits: ppn.0 << 10 | flags.bits as usize,
        }
    }
    /// Create an empty page table entry
    pub fn empty() -> Self {
        PageTableEntry { bits: 0 }
    }
    /// Get the physical page number from the page table entry
    pub fn ppn(&self) -> PhysPageNum {
        (self.bits >> 10 & ((1usize << 44) - 1)).into()
    }
    /// Get the flags from the page table entry
    pub fn flags(&self) -> PTEFlags {
        PTEFlags::from_bits(self.bits as u8).unwrap()
    }
    /// The page pointered by page table entry is valid?
    pub fn is_valid(&self) -> bool {
        (self.flags() & PTEFlags::V) != PTEFlags::empty()
    }
    /// The page pointered by page table entry is readable?
    pub fn readable(&self) -> bool {
        (self.flags() & PTEFlags::R) != PTEFlags::empty()
    }
    /// The page pointered by page table entry is writable?
    pub fn writable(&self) -> bool {
        (self.flags() & PTEFlags::W) != PTEFlags::empty()
    }
    /// The page pointered by page table entry is executable?
    pub fn executable(&self) -> bool {
        (self.flags() & PTEFlags::X) != PTEFlags::empty()
    }
}

pub fn translated_byte_buffer(_token: PageTable, ptr: *mut u8, len: usize) -> &'static mut [u8] {
    trace!("os::mm::page_table::translated_byte_buffer");
    unsafe { core::slice::from_raw_parts_mut(ptr, len) }
}

/// Load a string from other address spaces into kernel space without an end `\0`.
pub fn translated_str(_token: PageTable, ptr: *const u8) -> String {
    unsafe {
        let len = str_len(ptr);
        from_utf8_unchecked(slice::from_raw_parts(ptr, len)).to_string()
    }
}

unsafe fn str_len(ptr: *const u8) -> usize {
    let mut i = 0;
    loop {
        if *ptr.add(i) == 0 {
            break i;
        }
        i += 1;
    }
}

/// translate a pointer `ptr` in other address space to a immutable u8 slice in kernel address space. NOTICE: the content pointed to by the pointer `ptr` cannot cross physical pages, otherwise translated_byte_buffer should be used.
pub fn translated_ref<T>(_token: PageTable, ptr: *const T) -> &'static T {
    unsafe { ptr.as_ref().unwrap() }
}

/// translate a pointer `ptr` in other address space to a mutable u8 slice in kernel address space. NOTICE: the content pointed to by the pointer `ptr` cannot cross physical pages, otherwise translated_byte_buffer should be used.
pub fn translated_refmut<T>(_token: PageTable, ptr: *mut T) -> &'static mut T {
    unsafe { ptr.as_mut().unwrap() }
}

/// An abstraction over a buffer passed from user space to kernel space
pub struct UserBuffer {
    /// A list of buffers
    pub buffers: Vec<&'static mut [u8]>,
}

impl UserBuffer {
    /// Constuct UserBuffer
    pub fn new(buffers: Vec<&'static mut [u8]>) -> Self {
        Self { buffers }
    }
    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        let mut total: usize = 0;
        for b in self.buffers.iter() {
            total += b.len();
        }
        total
    }
}

impl IntoIterator for UserBuffer {
    type Item = *mut u8;
    type IntoIter = UserBufferIterator;
    fn into_iter(self) -> Self::IntoIter {
        UserBufferIterator {
            buffers: self.buffers,
            current_buffer: 0,
            current_idx: 0,
        }
    }
}

/// An iterator over a UserBuffer
pub struct UserBufferIterator {
    buffers: Vec<&'static mut [u8]>,
    current_buffer: usize,
    current_idx: usize,
}

impl Iterator for UserBufferIterator {
    type Item = *mut u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_buffer >= self.buffers.len() {
            None
        } else {
            let r = &mut self.buffers[self.current_buffer][self.current_idx] as *mut _;
            if self.current_idx + 1 == self.buffers[self.current_buffer].len() {
                self.current_idx = 0;
                self.current_buffer += 1;
            } else {
                self.current_idx += 1;
            }
            Some(r)
        }
    }
}
