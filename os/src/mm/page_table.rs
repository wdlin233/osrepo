//! Implementation of [`PageTableEntry`] and [`PageTable`].
use super::StepByOne;
use alloc::string::String;
use alloc::vec::Vec;
use bitflags::*;
use polyhal::{pagetable::PageTable, VirtAddr};
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

// pub fn translated_byte_buffer(_token: PageTable, ptr: *mut u8, len: usize) -> &'static mut [u8] {
//     trace!("os::mm::page_table::translated_byte_buffer");
//     unsafe { core::slice::from_raw_parts_mut(ptr, len) }
// }

/// 跨页安全地获取用户空间虚拟地址区间的可变切片集合
pub fn translated_byte_buffer(pgtable: PageTable, ptr: *mut u8, len: usize) -> Vec<&'static mut [u8]> {
    let mut start = ptr as usize;
    let end = start + len;
    let mut v = Vec::new();
    while start < end {
        let start_va = VirtAddr::from(start);
        let mut vpn = start_va.floor();
        // 这里假设 page_table.translate 返回 (PhysAddr, MappingFlags)
        let (paddr, _) = pgtable.translate(vpn).expect("invalid address in translated_byte_buffer");
        vpn.step();
        let mut end_va: VirtAddr = vpn.into();
        end_va = end_va.min(VirtAddr::from(end));

        // n = 4?
        let page_offset = start_va.pn_offest(4);
        let slice_end = if end_va.pn_offest(4) == 0 {
            crate::config::PAGE_SIZE
        } else {
            end_va.pn_offest(4)
        };
        let phys_ptr = paddr.get_mut_ptr() as *const usize as usize + page_offset; // 直接用物理地址
        let slice_len = slice_end - page_offset;
        unsafe {
            v.push(core::slice::from_raw_parts_mut(phys_ptr as *mut u8, slice_len));
        }
        start = end_va.into();
    }
    v
}

/// Original ver: Translate&Copy a ptr[u8] array with LENGTH len to a mutable u8 Vec through page table
// pub fn translated_byte_buffer(token: usize, ptr: *const u8, len: usize) -> Vec<&'static mut [u8]> {
//     let page_table = PageTable::from_token(token);
//     let mut start = ptr as usize;
//     let end = start + len;
//     let mut v = Vec::new();
//     while start < end {
//         let start_va = VirtAddr::from(start);
//         let mut vpn = start_va.floor();
//         let ppn = page_table.translate(vpn).unwrap().ppn();
//         vpn.step();
//         let mut end_va: VirtAddr = vpn.into();
//         end_va = end_va.min(VirtAddr::from(end));

//         if end_va.page_offset() == 0 {
//             v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..]);
//         } else {
//             v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..end_va.page_offset()]);
//         }
//         start = end_va.into();
//     }
//     v
// }

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
