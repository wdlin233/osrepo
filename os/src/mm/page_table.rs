//! Implementation of [`PageTableEntry`] and [`PageTable`].
use super::frame_alloc;
use crate::config::KERNEL_PGNUM_OFFSET;
#[cfg(target_arch = "loongarch64")]
use crate::config::{PAGE_SIZE_BITS, PALEN};
use crate::mm::{memory_set, MemorySet};
use crate::timer::get_time;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
#[cfg(target_arch = "loongarch64")]
use bit_field::BitField;
use bitflags::*;
use polyhal::pagetable::PAGE_SIZE;
use polyhal::{pagetable, print, println, MappingFlags, PageTableWrapper, VirtAddr};
use polyhal_trap::trap::TrapType;
use core::{error, slice};
use core::fmt::{self};
use core::str::from_utf8_unchecked;
#[cfg(target_arch = "loongarch64")]
use loongarch64::register::estat::{Exception, Trap};
#[cfg(target_arch = "riscv64")]
use riscv::register::scause::{Exception, Trap};

use core::arch::asm;

use crate::mm::frame_allocator::FrameTracker;

/// Translate&Copy a ptr[u8] array with LENGTH len to a mutable u8 Vec through page table
pub fn translated_byte_buffer(ptr: *mut u8, len: usize) -> &'static mut [u8] {
    info!("(translated_byte_buffer) ptr: {:#x}, len: {}", ptr as usize, len);
    unsafe {
        core::slice::from_raw_parts_mut(ptr, len)
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

/// Translate&Copy a ptr[u8] array end with `\0` to a `String` Vec through page table
pub fn translated_str(ptr: *const u8) -> String {
    unsafe {
        let len = str_len(ptr);
        from_utf8_unchecked(slice::from_raw_parts(ptr, len)).to_string()
    }
}

/// translate a pointer `ptr` in other address space to a immutable u8 slice in kernel address space. NOTICE: the content pointed to by the pointer `ptr` cannot cross physical pages, otherwise translated_byte_buffer should be used.
pub fn translated_ref<T>(ptr: *const T) -> &'static T {
    unsafe {
        ptr.as_ref().unwrap()
    }
}
/// translate a pointer `ptr` in other address space to a mutable u8 slice in kernel address space. NOTICE: the content pointed to by the pointer `ptr` cannot cross physical pages, otherwise translated_byte_buffer should be used.
pub fn translated_refmut<T>(ptr: *mut T) -> &'static mut T {
    unsafe {
        ptr.as_mut().unwrap()
    }
}

// 读取迭代器实现
pub struct Iter<'a> {
    buffers: core::slice::Iter<'a, &'static mut [u8]>,
    current: &'a [u8],
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.is_empty() {
            self.current = self.buffers.next()?;
        }

        let (first, rest) = self.current.split_first()?;
        self.current = rest;
        Some(first)
    }
}

// 可变迭代器实现
pub struct IterMut<'a> {
    buffers: core::slice::IterMut<'a, &'static mut [u8]>,
    current: &'a mut [u8],
}

impl<'a> Iterator for IterMut<'a> {
    type Item = &'a mut u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.is_empty() {
            self.current = self.buffers.next()?;
        }

        // 安全：从当前切片分离出第一个元素
        let slice = core::mem::replace(&mut self.current, &mut []);
        let (first, rest) = slice.split_first_mut()?;
        self.current = rest;
        Some(first)
    }
}

/// An abstraction over a buffer passed from user space to kernel space
pub struct UserBuffer {
    ///U8 vec
    pub buffers: Vec<&'static mut [u8]>,
}

impl UserBuffer {
    ///Create a `UserBuffer` by parameter
    pub fn new(buffers: Vec<&'static mut [u8]>) -> Self {
        //debug!("UserBuffer::new: buffers: {:?}", buffers);
        Self { buffers }
    }
    pub fn new_single(buffer: &'static mut [u8]) -> Self {
        Self {
            buffers: vec![buffer],
        }
    }
    ///Length of `UserBuffer`
    pub fn len(&self) -> usize {
        let mut total: usize = 0;
        for b in self.buffers.iter() {
            total += b.len();
        }
        total
    }
    /// 将内容数组返回
    pub fn read(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        let mut current = 0;
        for sub_buff in self.buffers.iter_mut() {
            let mut sblen = (*sub_buff).len();
            if current + sblen > len {
                sblen = len - current;
            }
            bytes[current..current + sblen].copy_from_slice(&(*sub_buff)[..sblen]);
            current += sblen;
            if current == len {
                return bytes;
            }
        }
        bytes
    }
    /// 将一个Buffer的数据写入UserBuffer，返回写入长度
    pub fn write(&mut self, buff: &[u8]) -> usize {
        let len = self.len().min(buff.len());
        if len == 0 {
            return len;
        }
        let mut current = 0;
        for sub_buff in self.buffers.iter_mut() {
            let mut sblen = (*sub_buff).len();
            if buff.len() > 10 {
                if current + sblen > len {
                    sblen = len - current;
                }
                (*sub_buff)[..sblen].copy_from_slice(&buff[current..current + sblen]);
                current += sblen;
                if current == len {
                    return len;
                }
            } else {
                for j in 0..sblen {
                    (*sub_buff)[j] = buff[current];
                    current += 1;
                    if current == len {
                        return len;
                    }
                }
            }
        }
        return len;
    }
    //在指定位置写入数据
    pub fn write_at(&mut self, offset: usize, buff: &[u8]) -> isize {
        //未被使用，暂不做优化
        let len = buff.len();
        if offset + len > self.len() {
            return -1;
        }
        let mut head = 0; // offset of slice in UBuffer
        let mut current = 0; // current offset of buff

        for sub_buff in self.buffers.iter_mut() {
            let sblen = (*sub_buff).len();
            if head + sblen < offset {
                continue;
            } else if head < offset {
                for j in (offset - head)..sblen {
                    (*sub_buff)[j] = buff[current];
                    current += 1;
                    if current == len {
                        return len as isize;
                    }
                }
            } else {
                //head + sblen > offset and head > offset
                for j in 0..sblen {
                    (*sub_buff)[j] = buff[current];
                    current += 1;
                    if current == len {
                        return len as isize;
                    }
                }
            }
            head += sblen;
        }
        0
    }

    pub fn fill0(&mut self) -> usize {
        for sub_buff in self.buffers.iter_mut() {
            let sblen = (*sub_buff).len();
            for j in 0..sblen {
                (*sub_buff)[j] = 0;
            }
        }
        self.len()
    }

    pub fn fillrandom(&mut self) -> usize {
        //随机数生成方法： 线性计算+噪声+零特殊处理
        let mut random: u8 = (get_time() % 256) as u8;
        for sub_buff in self.buffers.iter_mut() {
            let sblen = (*sub_buff).len();
            for j in 0..sblen {
                if random == 0 {
                    random = (get_time() % 256) as u8;
                }
                random = (((random as usize) * (get_time() / 3 % 256) + 37) % 256) as u8; //生成一个字节大小的随机数
                (*sub_buff)[j] = random;
            }
        }
        self.len()
    }

    pub fn printbuf(&mut self, size: usize) {
        if size == 0 {
            return;
        }
        let mut count: usize = 0;
        for sub_buff in self.buffers.iter_mut() {
            let sblen = (*sub_buff).len();
            for j in 0..sblen {
                print!("{} ", (*sub_buff)[j]);
                count += 1;
                if count == size {
                    println!("");
                    return;
                }
            }
        }
    }

    pub fn clear(&mut self) -> usize {
        self.buffers.clear();
        self.len()
    }

    pub fn as_bytes_mut(&mut self) -> Vec<&'static mut [u8]> {
        unimplemented!()
        // self.buffers.clone()
        //unimplemented!() wrong implmentation
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
/// Iterator of `UserBuffer`
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
