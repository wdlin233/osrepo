//! Implementation of [`PageTableEntry`] and [`PageTable`].
use super::{frame_alloc, FrameTracker, PhysAddr, PhysPageNum, StepByOne, VirtAddr, VirtPageNum};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use bitflags::*;

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

/// page table structure
pub struct PageTable {
    root_ppn: PhysPageNum,
    frames: Vec<FrameTracker>,
}

/// Assume that it won't oom when creating/mapping.
impl PageTable {
    /// Create a new page table
    pub fn new() -> Self {
        let frame = frame_alloc().unwrap();
        PageTable {
            root_ppn: frame.ppn,
            frames: vec![frame],
        }
    }
    /// Temporarily used to get arguments from user space.
    pub fn from_token(satp: usize) -> Self {
        Self {
            root_ppn: PhysPageNum::from(satp & ((1usize << 44) - 1)),
            frames: Vec::new(),
        }
    }
    /// Find PageTableEntry by VirtPageNum, create a frame for a 4KB page table if not exist
    fn find_pte_create(&mut self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        for (i, idx) in idxs.iter().enumerate() {
            let pte = &mut ppn.get_pte_array()[*idx];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                let frame = frame_alloc().unwrap();
                *pte = PageTableEntry::new(frame.ppn, PTEFlags::V);
                self.frames.push(frame);
            }
            ppn = pte.ppn();
        }
        result
    }
    /// Find PageTableEntry by VirtPageNum
    fn find_pte(&self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        for (i, idx) in idxs.iter().enumerate() {
            let pte = &mut ppn.get_pte_array()[*idx];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                return None;
            }
            ppn = pte.ppn();
        }
        result
    }
    /// set the map between virtual page number and physical page number
    #[allow(unused)]
    pub fn map(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) {
        let pte = self.find_pte_create(vpn).unwrap();
        // trace!(
        //     "map vpn {:?} to ppn {:?} with flags {:?}",
        //     vpn, ppn, flags
        // );
        assert!(!pte.is_valid(), "vpn {:?} is mapped before mapping", vpn);
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
    }
    /// remove the map between virtual page number and physical page number
    #[allow(unused)]
    pub fn unmap(&mut self, vpn: VirtPageNum) {
        let pte = self.find_pte(vpn).unwrap();
        assert!(pte.is_valid(), "vpn {:?} is invalid before unmapping", vpn);
        *pte = PageTableEntry::empty();
    }
    /// get the page table entry from the virtual page number
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.find_pte(vpn).map(|pte| *pte)
    }
    /// get the physical address from the virtual address
    pub fn translate_va(&self, va: VirtAddr) -> Option<PhysAddr> {
        self.find_pte(va.clone().floor()).map(|pte| {
            let aligned_pa: PhysAddr = pte.ppn().into();
            let offset = va.page_offset();
            let aligned_pa_usize: usize = aligned_pa.into();
            (aligned_pa_usize + offset).into()
        })
    }
    /// get the token from the page table
    pub fn token(&self) -> usize {
        8usize << 60 | self.root_ppn.0
    }
}

/// Translate&Copy a ptr[u8] array with LENGTH len to a mutable u8 Vec through page table
pub fn translated_byte_buffer(token: usize, ptr: *const u8, len: usize) -> Vec<&'static mut [u8]> {
    let page_table = PageTable::from_token(token);
    let mut start = ptr as usize;
    let end = start + len;
    let mut v = Vec::new();
    while start < end {
        let start_va = VirtAddr::from(start);
        let mut vpn = start_va.floor();
        let ppn = page_table.translate(vpn).unwrap().ppn();
        vpn.step();
        let mut end_va: VirtAddr = vpn.into();
        end_va = end_va.min(VirtAddr::from(end));
        if end_va.page_offset() == 0 {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..]);
        } else {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..end_va.page_offset()]);
        }
        start = end_va.into();
    }
    v
}

/// Translate&Copy a ptr[u8] array end with `\0` to a `String` Vec through page table
pub fn translated_str(token: usize, ptr: *const u8) -> String {
    let page_table = PageTable::from_token(token);
    let mut string = String::new();
    let mut va = ptr as usize;
    loop {
        let ch: u8 = *(page_table
            .translate_va(VirtAddr::from(va))
            .unwrap()
            .get_mut());
        if ch == 0 {
            break;
        }
        string.push(ch as char);
        va += 1;
    }
    string
}

/// translate a pointer `ptr` in other address space to a immutable u8 slice in kernel address space. NOTICE: the content pointed to by the pointer `ptr` cannot cross physical pages, otherwise translated_byte_buffer should be used.
pub fn translated_ref<T>(token: usize, ptr: *const T) -> &'static T {
    let page_table = PageTable::from_token(token);
    page_table
        .translate_va(VirtAddr::from(ptr as usize))
        .unwrap()
        .get_ref()
}

/// translate a pointer `ptr` in other address space to a mutable u8 slice in kernel address space. NOTICE: the content pointed to by the pointer `ptr` cannot cross physical pages, otherwise translated_byte_buffer should be used.
pub fn translated_refmut<T>(token: usize, ptr: *mut T) -> &'static mut T {
    let page_table = PageTable::from_token(token);
    let va = ptr as usize;
    page_table
        .translate_va(VirtAddr::from(va))
        .unwrap()
        .get_mut()
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
    /// 转换为不可变字节切片 (数据拷贝)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.len());
        for buffer in &self.buffers {
            result.extend_from_slice(buffer);
        }
        result
    }

    /// 转换为不可变字节切片引用 (零拷贝)
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            if self.buffers.is_empty() {
                &[]
            } else if self.buffers.len() == 1 {
                &self.buffers[0]
            } else {
                core::slice::from_raw_parts(
                    self.buffers[0].as_ptr(), 
                    self.len()
                )
            }
        }
    }

    /// 转换为可变字节切片 (零拷贝)
    /// 注意：仅在物理内存连续时安全
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            if self.buffers.is_empty() {
                &mut []
            } else if self.buffers.len() == 1 {
                &mut self.buffers[0]
            } else if self.is_physically_contiguous() {
                core::slice::from_raw_parts_mut(
                    self.buffers[0].as_mut_ptr(), 
                    self.len()
                )
            } else {
                panic!("Buffers are not physically contiguous");
            }
        }
    }

    /// 检查所有缓冲区是否物理连续
    fn is_physically_contiguous(&self) -> bool {
        let mut next_ptr = None;
        
        for buffer in &self.buffers {
            let start_ptr = buffer.as_ptr() as usize;
            let end_ptr = start_ptr + buffer.len();
            
            if let Some(expected_next) = next_ptr {
                if start_ptr != expected_next {
                    return false;
                }
            }
            
            next_ptr = Some(end_ptr);
        }
        
        true
    }

    /// 实现读取迭代器
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            buffers: self.buffers.iter(),
            current: &[],
        }
    }

    /// 实现写入迭代器
    pub fn iter_mut(&mut self) -> IterMut<'_> {
        IterMut {
            buffers: self.buffers.iter_mut(),
            current: &mut [],
        }
    }

    /// 高效复制到连续缓冲区
    pub fn copy_to_slice(&self, dest: &mut [u8]) -> usize {
        let mut copied = 0;
        
        for buf in &self.buffers {
            if copied >= dest.len() {
                break;
            }
            
            let to_copy = (buf.len()).min(dest.len() - copied);
            dest[copied..copied + to_copy].copy_from_slice(&buf[..to_copy]);
            copied += to_copy;
        }
        
        copied
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
