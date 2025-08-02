//! Implementation of [`PageTableEntry`] and [`PageTable`].
use super::{frame_alloc, FrameTracker, PhysAddr, PhysPageNum, StepByOne, VirtAddr, VirtPageNum};
#[cfg(target_arch = "loongarch64")]
use crate::config::{PAGE_SIZE_BITS, PALEN};
use crate::mm::MemorySet;
use crate::timer::get_time;
use crate::{print, println};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
#[cfg(target_arch = "loongarch64")]
use bit_field::BitField;
use bitflags::*;
use core::error;
use core::fmt::{self};
#[cfg(target_arch = "loongarch64")]
use loongarch64::register::estat::{Exception, Trap};
#[cfg(target_arch = "riscv64")]
use riscv::register::scause::{Exception, Trap};

use core::arch::asm;
pub fn flush_tlb() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        asm!("sfence.vma");
    }
    // im not sure
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        asm!("tlbflush");
    }
}

#[cfg(target_arch = "riscv64")]
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
#[cfg(target_arch = "loongarch64")]
bitflags! {
    pub struct PTEFlags: usize {
        const V = 1 << 0;
        const D = 1 << 1;
        const PLVL = 1 << 2;
        const PLVH = 1 << 3;
        const MATL = 1 << 4;
        const MATH = 1 << 5;
        const G = 1 << 6;
        const P = 1 << 7;
        const W = 1 << 8;
        const NR = 1 << 61;
        const NX = 1 << 62;
        const RPLV = 1 << 63;
    }
}
#[cfg(target_arch = "loongarch64")]
impl PTEFlags {
    #[allow(unused)]
    fn default() -> Self {
        PTEFlags::V | PTEFlags::MATL | PTEFlags::P | PTEFlags::W
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
/// page table entry structure
pub struct PageTableEntry {
    /// bits of page table entry
    pub bits: usize,
}

#[cfg(target_arch = "loongarch64")]
impl fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PageTableEntry RPLV:{},NX:{},NR:{},PPN:{:#x},W:{},P:{},G:{},MAT:{},PLV:{},D:{},V:{}",
            self.bits.get_bit(63),
            self.bits.get_bit(62),
            self.bits.get_bit(61),
            self.bits.get_bits(14..PALEN),
            self.bits.get_bit(8),
            self.bits.get_bit(7),
            self.bits.get_bit(6),
            self.bits.get_bits(4..=5),
            self.bits.get_bits(2..=3),
            self.bits.get_bit(1),
            self.bits.get_bit(0)
        )
    }
}

impl PageTableEntry {
    /// Create a new page table entry
    pub fn new(ppn: PhysPageNum, flags: PTEFlags) -> Self {
        //info!("PageTableEntry::new: ppn: {:?}, flags: {:?}", ppn, flags);
        #[cfg(target_arch = "riscv64")]
        return PageTableEntry {
            bits: ppn.0 << 10 | flags.bits as usize,
        };
        #[cfg(target_arch = "loongarch64")]
        {
            //debug!("ppn:{:#x}, flags:{:?}", ppn.0, flags);
            let mut bits = 0usize;
            bits.set_bits(14..PALEN, ppn.0); //采用16kb大小的页
            bits = bits | flags.bits;
            PageTableEntry { bits }
        }
    }
    /// Create an empty page table entry
    pub fn empty() -> Self {
        PageTableEntry { bits: 0 }
    }

    /// Get the physical page number from the page table entry
    /// 返回物理页号---页表项
    pub fn ppn(&self) -> PhysPageNum {
        #[cfg(target_arch = "riscv64")]
        return (self.bits >> 10 & ((1usize << 44) - 1)).into();
        #[cfg(target_arch = "loongarch64")]
        return self.bits.get_bits(14..PALEN).into();
    }
    /// Get the flags from the page table entry
    /// 返回标志位
    pub fn flags(&self) -> PTEFlags {
        #[cfg(target_arch = "riscv64")]
        return PTEFlags::from_bits(self.bits as u8).unwrap();
        #[cfg(target_arch = "loongarch64")]
        {
            //debug!("PageTableEntry::flags: bits: {:#x}", self.bits);
            let valid_flags = PTEFlags::V.bits()
                | PTEFlags::D.bits()
                | PTEFlags::PLVL.bits()
                | PTEFlags::PLVH.bits()
                | PTEFlags::MATL.bits()
                | PTEFlags::MATH.bits()
                | PTEFlags::G.bits()
                | PTEFlags::P.bits()
                | PTEFlags::W.bits()
                | PTEFlags::NR.bits()
                | PTEFlags::NX.bits()
                | PTEFlags::RPLV.bits();
            let flags_bits = self.bits & valid_flags;
            PTEFlags::from_bits_truncate(flags_bits)
        }
    }
    // 返回物理页号---页目录项
    // 在一级和二级页目录表中目录项存放的是只有下一级的基地址
    #[cfg(target_arch = "loongarch64")]
    pub fn directory_ppn(&self) -> PhysPageNum {
        (self.bits >> PAGE_SIZE_BITS).into()
    }

    /// The page pointered by page table entry is valid?
    pub fn is_valid(&self) -> bool {
        (self.flags() & PTEFlags::V) != PTEFlags::empty()
    }
    /// The page pointered by page table entry is writable?
    pub fn writable(&self) -> bool {
        (self.flags() & PTEFlags::W) != PTEFlags::empty()
    }
    /// The page pointered by page table entry is readable?
    pub fn readable(&self) -> bool {
        #[cfg(target_arch = "riscv64")]
        return (self.flags() & PTEFlags::R) != PTEFlags::empty();
        #[cfg(target_arch = "loongarch64")]
        return !((self.flags() & PTEFlags::NR) != PTEFlags::empty());
    }
    /// The page pointered by page table entry is executable?
    pub fn executable(&self) -> bool {
        #[cfg(target_arch = "riscv64")]
        return (self.flags() & PTEFlags::X) != PTEFlags::empty();
        #[cfg(target_arch = "loongarch64")]
        return !((self.flags() & PTEFlags::NX) != PTEFlags::empty());
    }
    //设置脏位
    #[cfg(target_arch = "loongarch64")]
    pub fn set_dirty(&mut self) {
        self.bits.set_bit(1, true);
    }
    // 用于判断存放的页目录项是否为0
    // 由于页目录项只保存下一级目录的基地址
    // 因此判断是否是有效的就只需判断是否为0即可
    // 但我不认为这是一个好的设计，将在后续被修改
    #[cfg(target_arch = "loongarch64")]
    pub fn is_zero(&self) -> bool {
        self.bits == 0
    }
    /// 统一用 9 位来做 cow. 在 rv 上这样可以减少接口的改动.
    pub fn is_cow(&self) -> bool {
        self.bits & (1 << 9) != 0
    }
    pub fn set_cow(&mut self) {
        (*self).bits = self.bits | (1 << 9);
    }
    pub fn reset_cow(&mut self) {
        (*self).bits = self.bits & !(1 << 9);
    }
    pub fn reset_w(&mut self) {
        #[cfg(target_arch = "riscv64")]
        return (*self).bits = self.bits & !(1 << 2);
        #[cfg(target_arch = "loongarch64")]
        return (*self).bits = self.bits & !(1 << 8);
    }
    pub fn set_w(&mut self) {
        #[cfg(target_arch = "riscv64")]
        return (*self).bits = self.bits | (1 << 2);
        #[cfg(target_arch = "loongarch64")]
        return (*self).bits = self.bits | (1 << 8);
    }
    pub fn set_map_flags(&mut self, flags: PTEFlags) {
        #[cfg(target_arch = "riscv64")]
        let new_flags: u8 = (self.bits & 0xFF) as u8 | flags.bits().clone();
        #[cfg(target_arch = "loongarch64")]
        let new_flags: usize = (self.bits & 0xFF) as usize | flags.bits().clone();
        self.bits = (self.bits & 0xFFFF_FFFF_FFFF_FF00) | (new_flags as usize);
    }
    pub fn set_flags(&mut self, flags: PTEFlags) {
        //let new_flags: u8 = flags.bits().clone();
        #[cfg(target_arch = "riscv64")]
        let new_flags: u8 = flags.bits().clone();
        #[cfg(target_arch = "loongarch64")]
        let new_flags: usize = flags.bits().clone();
        self.bits = (self.bits & 0xFFFF_FFFF_FFFF_FF00) | (new_flags as usize);
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
    #[cfg(target_arch = "riscv64")]
    pub fn from_token(satp: usize) -> Self {
        Self {
            root_ppn: PhysPageNum::from(satp & ((1usize << 44) - 1)),
            frames: Vec::new(),
        }
    }
    /// Temporarily used to get arguments from user space.
    /// pgd是全局目录基地址，类似于riscv的satp,其是物理地址
    /// 毕竟寄存器和页的偏移等各自不同
    #[cfg(target_arch = "loongarch64")]
    pub fn from_token(pgd: usize) -> Self {
        Self {
            root_ppn: PhysPageNum::from(pgd & ((1usize << 34) - 1)),
            frames: Vec::new(),
        }
    }
    /// Find PageTableEntry by VirtPageNum, create a frame for a 4KB page table if not exist
    pub fn find_pte_create(&mut self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        #[cfg(target_arch = "riscv64")]
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
        #[cfg(target_arch = "loongarch64")]
        for i in 0..3 {
            let pte = &mut ppn.get_pte_array()[idxs[i]];
            if i == 2 {
                //找到叶子节点，叶子节点的页表项是否合法由调用者来处理
                result = Some(pte);
                break;
            }
            if pte.is_zero() {
                let frame = frame_alloc().unwrap();
                // 页目录项只保存地址
                *pte = PageTableEntry {
                    bits: frame.ppn.0 << PAGE_SIZE_BITS,
                };
                self.frames.push(frame);
            }
            ppn = pte.directory_ppn();
        }
        result
    }
    /// Find PageTableEntry by VirtPageNum
    pub fn find_pte(&self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        #[cfg(target_arch = "riscv64")]
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
        #[cfg(target_arch = "loongarch64")]
        for i in 0..3 {
            let pte = &mut ppn.get_pte_array()[idxs[i]];
            if pte.is_zero() {
                return None;
            }
            if i == 2 {
                result = Some(pte);
                break;
            }
            ppn = pte.directory_ppn();
        }
        result
    }
    /// set the map between virtual page number and physical page number
    #[allow(unused)]
    pub fn map(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags, is_cow: bool) {
        let pte = self.find_pte_create(vpn).unwrap();
        // info!(
        //     "map vpn {:?} to ppn {:?} with flags {:?}",
        //     vpn, ppn, flags
        // );
        //debug!("in page table map, find pte create ok");
        assert!(!pte.is_valid(), "vpn {:?} is mapped before mapping", vpn);
        #[cfg(target_arch = "riscv64")]
        {
            *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
            if is_cow {
                pte.set_cow();
            }
        }
        #[cfg(target_arch = "loongarch64")]
        {
            *pte = PageTableEntry::new(ppn, flags | PTEFlags::V | PTEFlags::MATL | PTEFlags::P);
        }
    }
    /// remove the map between virtual page number and physical page number
    pub fn unmap(&mut self, vpn: VirtPageNum) {
        // 如果不存在,即lazy allocation,跳过即可
        if let Some(pte) = self.find_pte(vpn) {
            if pte.is_valid() {
                *pte = PageTableEntry::empty();
            }
        }
    }
    /// get the page table entry from the virtual page number
    /// *pte is equirvalent to pte.clone()
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
        #[cfg(target_arch = "riscv64")]
        return 8usize << 60 | self.root_ppn.0;
        #[cfg(target_arch = "loongarch64")]
        return self.root_ppn.0;
    }
    pub fn set_map_flags(&mut self, vpn: VirtPageNum, flags: PTEFlags) {
        self.find_pte_create(vpn)
            .unwrap()
            .set_map_flags(flags | PTEFlags::V);
    }
    pub fn set_cow(&mut self, vpn: VirtPageNum) {
        self.find_pte_create(vpn).unwrap().set_cow();
    }
    pub fn reset_cow(&mut self, vpn: VirtPageNum) {
        self.find_pte_create(vpn).unwrap().reset_cow();
    }
    pub fn set_w(&mut self, vpn: VirtPageNum) {
        self.find_pte_create(vpn).unwrap().set_w();
    }
    pub fn reset_w(&mut self, vpn: VirtPageNum) {
        self.find_pte_create(vpn).unwrap().reset_w();
    }
    pub fn set_flags(&mut self, vpn: VirtPageNum, flags: PTEFlags) {
        self.find_pte_create(vpn)
            .unwrap()
            .set_flags(flags | PTEFlags::V);
    }
    pub fn clear(&mut self) {
        self.frames.clear();
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

pub fn put_data<T: 'static>(token: usize, ptr: *mut T, data: T) {
    let page_table = PageTable::from_token(token);
    let mut va = VirtAddr::from(ptr as usize);
    let pa = page_table.translate_va(va).unwrap();
    let size = core::mem::size_of::<T>();
    // 若数据跨页，则转换成字节数据写入
    if PhysAddr(pa.0 + size - 1).floor() != pa.floor() {
        let bytes =
            unsafe { core::slice::from_raw_parts(&data as *const _ as usize as *const u8, size) };
        for i in 0..size {
            *(page_table.translate_va(va).unwrap().get_mut()) = bytes[i];
            va.0 = va.0 + 1;
        }
    } else {
        *translated_refmut(token, ptr) = data;
    }
}
/// translate a pointer `ptr` in other address space to a immutable u8 slice in kernel address space. NOTICE: the content pointed to by the pointer `ptr` cannot cross physical pages, otherwise translated_byte_buffer should be used.
pub fn translated_ref<T>(token: usize, ptr: *const T) -> &'static T {
    let page_table = PageTable::from_token(token);
    page_table
        .translate_va(VirtAddr::from(ptr as usize))
        .unwrap()
        .get_ref()
}

pub fn safe_translated_byte_buffer(
    memory_set: Arc<MemorySet>,
    ptr: *const u8,
    len: usize,
) -> Option<Vec<&'static mut [u8]>> {
    debug!("safe_translated_byte_buffer: ptr: {:?}, len: {}", ptr, len);
    let page_table = PageTable::from_token(memory_set.token());
    let mut start = ptr as usize;
    let end = start + len;
    let mut v = Vec::new();
    while start < end {
        let start_va = VirtAddr::from(start);
        let mut vpn = start_va.floor();
        #[cfg(target_arch = "riscv64")]
        match page_table.translate(vpn) {
            None => {
                memory_set.lazy_page_fault(vpn, Trap::Exception(Exception::LoadPageFault));
            }
            Some(ref pte) => {
                if !pte.is_valid() {
                    memory_set.lazy_page_fault(vpn, Trap::Exception(Exception::LoadPageFault));
                }
            }
        }
        #[cfg(target_arch = "loongarch64")]
        if !page_table
            .translate(vpn)
            .map_or(false, |pte| pte.is_valid())
        {
            memory_set.lazy_page_fault(vpn, Trap::Exception(Exception::LoadPageFault));
            // 重新检查
            if !page_table
                .translate(vpn)
                .map_or(false, |pte| pte.is_valid())
            {
                return None;
            }
        }
        //info!("safe_translated_byte_buffer: vpn: {:?}, start_va: {:?}", vpn, start_va);
        let ppn = match page_table.translate(vpn) {
            Some(pte) if pte.is_valid() => pte.ppn(),
            _ => return None,
        };

        #[cfg(target_arch = "riscv64")]
        {
            vpn.step();
            let mut end_va: VirtAddr = vpn.into();
            end_va = end_va.min(VirtAddr::from(end));
            if end_va.page_offset() == 0 {
                v.push(&mut ppn.bytes_array_mut()[start_va.page_offset()..]);
            } else {
                v.push(&mut ppn.bytes_array_mut()[start_va.page_offset()..end_va.page_offset()]);
            }
            info!(
                "safe_translated_byte_buffer: start_va: {:?}, end_va: {:?}, ppn: {:?}",
                start_va, end_va, ppn
            );
            start = end_va.into();
        }
        #[cfg(target_arch = "loongarch64")]
        {
            use crate::config::PAGE_SIZE;
            let phys_addr: PhysAddr = ppn.into();
            let kernel_va = phys_addr.0 | 0x9000_0000_0000_0000;

            // debug!(
            //     "safe_translated_byte_buffer: start_va: {:?}, ppn: {:?}, kernel_va: {:?}",
            //     start_va, ppn, kernel_va
            // );
            // 计算当前页内可访问的字节数
            let page_offset = start_va.page_offset();
            let page_remaining = PAGE_SIZE - page_offset;
            let bytes_in_page = usize::min(page_remaining, end - start);
            // 获取内核虚拟地址的切片
            let slice_start = kernel_va + page_offset;
            let slice =
                unsafe { core::slice::from_raw_parts_mut(slice_start as *mut u8, bytes_in_page) };
            v.push(slice);
            start += bytes_in_page;
        }
    }
    debug!("safe trsnslated byte buffer ok");
    Some(v)
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
