//! Implementation of [`PageTableEntry`] and [`PageTable`].
use super::{frame_alloc, FrameTracker, PhysAddr, PhysPageNum, StepByOne, VirtAddr, VirtPageNum};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use bitflags::*;
use core::fmt::{self};
#[cfg(target_arch = "loongarch64")]
use bit_field::BitField;
#[cfg(target_arch = "loongarch64")]
use crate::config::{PAGE_SIZE_BITS, PALEN};

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
    #[cfg(target_arch = "riscv64")]
    pub fn new(ppn: PhysPageNum, flags: PTEFlags) -> Self {
        PageTableEntry {
            bits: ppn.0 << 10 | flags.bits as usize,
        }
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn new(ppn: PhysPageNum, flags: PTEFlags) -> Self {
        let mut bits = 0usize;
        bits.set_bits(14..PALEN, ppn.0); //采用16kb大小的页
        bits = bits | flags.bits;
        PageTableEntry { bits }
    }
    /// Create an empty page table entry
    pub fn empty() -> Self {
        PageTableEntry { bits: 0 }
    }

    /// Get the physical page number from the page table entry
    #[cfg(target_arch = "riscv64")]
    pub fn ppn(&self) -> PhysPageNum {
        (self.bits >> 10 & ((1usize << 44) - 1)).into()
    }
    /// Get the flags from the page table entry
    #[cfg(target_arch = "riscv64")]
    pub fn flags(&self) -> PTEFlags {
        PTEFlags::from_bits(self.bits as u8).unwrap()
    }
    // 返回物理页号---页表项
    #[cfg(target_arch = "loongarch64")]
    pub fn ppn(&self) -> PhysPageNum {
        self.bits.get_bits(14..PALEN).into()
    }
    // 返回物理页号---页目录项
    // 在一级和二级页目录表中目录项存放的是只有下一级的基地址
    #[cfg(target_arch = "loongarch64")]
    pub fn directory_ppn(&self) -> PhysPageNum {
        (self.bits >> PAGE_SIZE_BITS).into()
    }
    // 返回标志位
    #[cfg(target_arch = "loongarch64")]
    pub fn flags(&self) -> PTEFlags {
        //这里只需要标志位，需要把非标志位的位置清零
        let mut bits = self.bits;
        bits.set_bits(14..PALEN, 0);
        PTEFlags::from_bits(bits).unwrap()
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
    #[cfg(target_arch = "riscv64")]
    pub fn readable(&self) -> bool {
        (self.flags() & PTEFlags::R) != PTEFlags::empty()
    }
    /// The page pointered by page table entry is executable?
    #[cfg(target_arch = "riscv64")]
    pub fn executable(&self) -> bool {
        (self.flags() & PTEFlags::X) != PTEFlags::empty()
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn readable(&self) -> bool {
        !((self.flags() & PTEFlags::NR) != PTEFlags::empty())
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn executable(&self) -> bool {
        !((self.flags() & PTEFlags::NX) != PTEFlags::empty())
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
    #[cfg(target_arch = "riscv64")]
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
    #[cfg(target_arch = "loongarch64")]
    fn find_pte_create(&mut self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
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
    #[cfg(target_arch = "riscv64")]
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
    #[cfg(target_arch = "loongarch64")]
    pub fn find_pte(&self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
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
    pub fn map(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) {
        let pte = self.find_pte_create(vpn).unwrap();
        info!(
            "map vpn {:?} to ppn {:?} with flags {:?}",
            vpn, ppn, flags
        );
        assert!(!pte.is_valid(), "vpn {:?} is mapped before mapping", vpn);
        #[cfg(target_arch = "riscv64")]
        {
            *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
        }
        #[cfg(target_arch = "loongarch64")]
        {
            *pte = PageTableEntry::new(ppn, flags | PTEFlags::V | PTEFlags::MATL | PTEFlags::P);
        }
    }
    /// remove the map between virtual page number and physical page number
    #[allow(unused)]
    pub fn unmap(&mut self, vpn: VirtPageNum) {
        let pte = self.find_pte(vpn).unwrap();
        assert!(pte.is_valid(), "vpn {:?} is invalid before unmapping", vpn);
        *pte = PageTableEntry::empty();
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
    #[cfg(target_arch = "riscv64")]
    pub fn token(&self) -> usize {
        8usize << 60 | self.root_ppn.0
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn token(&self) -> usize {
        self.root_ppn.0
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
