//! PhysAddr, VirtAddr, PhysPageNum, VirtPageNum, raw address

use super::{translated_byte_buffer, PageTableEntry};
use crate::config::VIRT_ADDR_OFFSET;
use crate::phys_to_virt;
use crate::{
    config::{PAGE_SIZE, PAGE_SIZE_BITS},
    task::current_user_token,
};
use core::fmt::{self, Debug, Formatter};
use core::ops::{Add, Sub};

const PA_WIDTH_SV39: usize = 56;
const VA_WIDTH_SV39: usize = 39;
const PPN_WIDTH_SV39: usize = PA_WIDTH_SV39 - PAGE_SIZE_BITS;
const VPN_WIDTH_SV39: usize = VA_WIDTH_SV39 - PAGE_SIZE_BITS;

/// Physical Address
#[repr(C)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct PhysAddr(pub usize);

/// Virtual Address
#[repr(C)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct VirtAddr(pub usize);

/// Physical Page Number PPN
#[repr(C)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct PhysPageNum(pub usize);

/// Virtual Page Number VPN
#[repr(C)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct VirtPageNum(pub usize);

/// Kernel Address
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelAddr(pub usize);

/// Debugging

impl Debug for VirtAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        //f.write_fmt(format_args!("VA:{:#b}", self.0))
        f.write_fmt(format_args!("VA:{:#x}", self.0))
    }
}
impl Debug for VirtPageNum {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("VPN:{:#x}", self.0))
    }
}
impl Debug for PhysAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("PA:{:#x}", self.0))
    }
}
impl Debug for PhysPageNum {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("PPN:{:#x}", self.0))
    }
}

/// T: {PhysAddr, VirtAddr, PhysPageNum, VirtPageNum}
/// T -> usize: T.0
/// usize -> T: usize.into()

/// 实现符号拓展的检查，而不是直接截断
impl From<usize> for PhysAddr {
    fn from(v: usize) -> Self {
        //return Self(v & ((1 << PA_WIDTH_SV39) - 1));
        #[cfg(target_arch = "riscv64")]
        {
            let tmp = (v as isize >> PA_WIDTH_SV39) as isize;
            assert!(tmp == 0 || tmp == -1);
        }
        return Self(v);
    }
}

impl From<usize> for PhysPageNum {
    fn from(v: usize) -> Self {
        #[cfg(target_arch = "riscv64")]
        {
            let tmp = (v as isize >> PPN_WIDTH_SV39) as isize;
            assert!(tmp == 0 || tmp == 255);
        }
        return Self(v);
    }
}

/// 拓展 512GB 虚拟地址空间
impl From<usize> for VirtAddr {
    fn from(v: usize) -> Self {
        //debug!("Converting usize to VirtAddr: {:x}", v);
        #[cfg(target_arch = "riscv64")]
        {
            let tmp = (v as isize >> VA_WIDTH_SV39) as isize;
            assert!(tmp == 0 || tmp == -1);
        }
        return Self(v);
    }
}
impl From<usize> for VirtPageNum {
    fn from(v: usize) -> Self {
        #[cfg(target_arch = "riscv64")]
        {
             let tmp = v >> (VPN_WIDTH_SV39 - 1);
            assert!(tmp == 0 || tmp == (1 << (52 - VPN_WIDTH_SV39 + 1)) - 1);
        }
        return Self(v);
    }
}

impl From<PhysAddr> for usize {
    fn from(v: PhysAddr) -> Self {
        v.0
    }
}
impl From<PhysPageNum> for usize {
    fn from(v: PhysPageNum) -> Self {
        v.0
    }
}

impl From<VirtAddr> for usize {
    fn from(v: VirtAddr) -> Self {
        #[cfg(target_arch = "riscv64")]
        if v.0 >= (1 << (VA_WIDTH_SV39 - 1)) {
            v.0 | (!((1 << VA_WIDTH_SV39) - 1))
        } else {
            v.0
        }
        #[cfg(target_arch = "loongarch64")]
        {
            v.0
        }
    }
}
impl From<VirtPageNum> for usize {
    fn from(v: VirtPageNum) -> Self {
        v.0
    }
}

/// impl From for KernelAddr
impl From<usize> for KernelAddr {
    fn from(v: usize) -> Self {
        Self(v)
    }
}

impl From<PhysAddr> for KernelAddr {
    fn from(v: PhysAddr) -> Self {
        Self(v.0 + VIRT_ADDR_OFFSET)
    }
}

impl From<KernelAddr> for PhysAddr {
    fn from(v: KernelAddr) -> Self {
        Self(v.0 - VIRT_ADDR_OFFSET)
    }
}

impl From<KernelAddr> for VirtAddr {
    fn from(v: KernelAddr) -> Self {
        Self(v.0)
    }
}

impl From<KernelAddr> for PhysPageNum {
    fn from(v: KernelAddr) -> Self {
        PhysAddr::from(v).floor()
    }
}

impl Add for VirtAddr {
    type Output = VirtAddr;
    fn add(self, rhs: Self) -> Self::Output {
        VirtAddr(self.0 + rhs.0)
    }
}
impl Add<usize> for VirtAddr {
    type Output = VirtAddr;
    fn add(self, rhs: usize) -> Self::Output {
        VirtAddr(self.0 + rhs)
    }
}
impl Sub for VirtAddr {
    type Output = VirtAddr;
    fn sub(self, rhs: Self) -> Self::Output {
        VirtAddr(self.0 - rhs.0)
    }
}
impl Sub<usize> for VirtAddr {
    type Output = VirtAddr;
    fn sub(self, rhs: usize) -> Self::Output {
        VirtAddr(self.0 - rhs)
    }
}

impl Add for PhysAddr {
    type Output = PhysAddr;
    fn add(self, rhs: Self) -> Self::Output {
        PhysAddr(self.0 + rhs.0)
    }
}
impl Add<usize> for PhysAddr {
    type Output = PhysAddr;
    fn add(self, rhs: usize) -> Self::Output {
        PhysAddr(self.0 + rhs)
    }
}
impl Sub for PhysAddr {
    type Output = PhysAddr;
    fn sub(self, rhs: Self) -> Self::Output {
        PhysAddr(self.0 - rhs.0)
    }
}
impl Sub<usize> for PhysAddr {
    type Output = PhysAddr;
    fn sub(self, rhs: usize) -> Self::Output {
        PhysAddr(self.0 - rhs)
    }
}

/// impl KernelAddr
impl KernelAddr {
    pub fn get_ref<T>(&self) -> &'static T {
        unsafe { (self.0 as *const T).as_ref().unwrap() }
    }
    ///Get mutable reference to `PhysAddr` value
    pub fn get_mut<T>(&self) -> &'static mut T {
        unsafe { (self.0 as *mut T).as_mut().unwrap() }
    }
}

/// virtual address impl
impl VirtAddr {
    /// Get the (floor) virtual page number
    pub fn floor(&self) -> VirtPageNum {
        VirtPageNum(self.0 / PAGE_SIZE)
    }

    /// Get the (ceil) virtual page number
    pub fn ceil(&self) -> VirtPageNum {
        if self.0 == 0 {
            VirtPageNum(0)
        } else {
            VirtPageNum((self.0 - 1 + PAGE_SIZE) / PAGE_SIZE)
        }
    }

    /// Get the page offset of virtual address
    pub fn page_offset(&self) -> usize {
        self.0 & (PAGE_SIZE - 1)
    }

    /// Check if the virtual address is aligned by page size
    pub fn aligned(&self) -> bool {
        self.page_offset() == 0
    }
}
impl From<VirtAddr> for VirtPageNum {
    fn from(v: VirtAddr) -> Self {
        //info!("Converting VirtAddr to VirtPageNum: {:?} with offset: {:?}", v, v.page_offset());
        assert_eq!(v.page_offset(), 0);
        v.floor()
    }
}
impl From<VirtPageNum> for VirtAddr {
    fn from(v: VirtPageNum) -> Self {
        Self(v.0 << PAGE_SIZE_BITS)
    }
}
impl PhysAddr {
    /// Get the (floor) physical page number
    pub fn floor(&self) -> PhysPageNum {
        PhysPageNum(self.0 / PAGE_SIZE)
    }
    /// Get the (ceil) physical page number
    pub fn ceil(&self) -> PhysPageNum {
        if self.0 == 0 {
            PhysPageNum(0)
        } else {
            PhysPageNum((self.0 - 1 + PAGE_SIZE) / PAGE_SIZE)
        }
    }
    /// Get the page offset of physical address
    pub fn page_offset(&self) -> usize {
        self.0 & (PAGE_SIZE - 1)
    }
    /// Check if the physical address is aligned by page size
    pub fn aligned(&self) -> bool {
        self.page_offset() == 0
    }
}
impl From<PhysAddr> for PhysPageNum {
    fn from(v: PhysAddr) -> Self {
        assert_eq!(v.page_offset(), 0);
        v.floor()
    }
}
impl From<PhysPageNum> for PhysAddr {
    fn from(v: PhysPageNum) -> Self {
        Self(v.0 << PAGE_SIZE_BITS)
    }
}

impl VirtPageNum {
    /// Get the indexes of the page table entry
    pub fn indexes(&self) -> [usize; 3] {
        let mut vpn = self.0;
        let mut idx = [0usize; 3];
        #[cfg(target_arch = "riscv64")]
        for i in (0..3).rev() {
            idx[i] = vpn & 511; // 2^9-1
            vpn >>= 9;
        }
        #[cfg(target_arch = "loongarch64")]
        for i in (0..3).rev() {
            idx[i] = vpn & 2047; //2^11-1, 每页包含2048个页表项
            vpn >>= 11;
        }
        idx
    }
}

#[cfg(target_arch = "riscv64")]
impl PhysAddr {
    /// Get the immutable reference of physical address
    pub fn get_ref<T>(&self) -> &'static T {
        unsafe { (self.0 as *const T).as_ref().unwrap() }
    }
    /// Get the mutable reference of physical address
    pub fn get_mut<T>(&self) -> &'static mut T {
        unsafe { (self.0 as *mut T).as_mut().unwrap() }
    }
}

#[cfg(target_arch = "loongarch64")]
impl PhysAddr {
    pub fn get_mut<T>(&self) -> &'static mut T {
        unsafe { ((phys_to_virt!(self.0)) as *mut T).as_mut().unwrap() }
    }
    pub fn get_ref<T>(&self) -> &'static T {
        unsafe { ((phys_to_virt!(self.0)) as *const T).as_ref().unwrap() }
    }
}

impl PhysPageNum {
    /// Get the reference of page table(array of ptes)
    pub fn get_pte_array(&self) -> &'static mut [PageTableEntry] {
        let pa: PhysAddr = (*self).into();
        let kernel_va = KernelAddr::from(pa).0;
        unsafe { core::slice::from_raw_parts_mut(kernel_va as *mut PageTableEntry, 512) }
    }
    /// Get the reference of page(array of bytes)
    pub fn get_bytes_array(&self) -> &'static mut [u8] {
        let pa: PhysAddr = (*self).into();
        let kernel_va = KernelAddr::from(pa).0;
        unsafe { core::slice::from_raw_parts_mut(kernel_va as *mut u8, 4096) }
    }
    /// Get the mutable reference of physical address
    pub fn get_mut<T>(&self) -> &'static mut T {
        let pa: PhysAddr = (*self).into();
        let kernel_va = KernelAddr::from(pa);
        kernel_va.get_mut()
    }
    pub fn bytes_array_mut(&self) -> &'static mut [u8] {
        let pa: PhysAddr = (*self).into();
        let kernel_va = KernelAddr::from(pa).0;
        unsafe { core::slice::from_raw_parts_mut(kernel_va as *mut u8, PAGE_SIZE) }
    }
}

// #[cfg(target_arch = "loongarch64")]
// impl PhysPageNum {
//     pub fn get_pte_array(&self) -> &'static mut [PageTableEntry] {
//         let pa: PhysAddr = self.clone().into();
//         let va = phys_to_virt!(pa.0);
//         // 每一个页有2048个项目 : 16kb/8 = 2048
//         unsafe { core::slice::from_raw_parts_mut(va as *mut PageTableEntry, 2048) }
//     }
//     pub fn get_bytes_array(&self) -> &'static mut [u8] {
//         let pa: PhysAddr = self.clone().into();
//         let va = phys_to_virt!(pa.0);
//         unsafe { core::slice::from_raw_parts_mut(va as *mut u8, 16 * 1024) }
//     }
//     pub fn get_mut<T>(&self) -> &'static mut T {
//         let pa: PhysAddr = self.clone().into();
//         pa.get_mut()
//     }
// }

/// iterator for phy/virt page number
pub trait StepByOne {
    /// step by one element(page number)
    fn step(&mut self);
}
impl StepByOne for VirtPageNum {
    fn step(&mut self) {
        self.0 += 1;
    }
}
impl StepByOne for PhysPageNum {
    fn step(&mut self) {
        self.0 += 1;
    }
}

#[derive(Copy, Clone, Debug)]
/// a simple range structure for type T
pub struct SimpleRange<T>
where
    T: StepByOne + Copy + PartialEq + PartialOrd + Debug,
{
    l: T,
    r: T,
}
impl<T> SimpleRange<T>
where
    T: StepByOne + Copy + PartialEq + PartialOrd + Debug,
{
    pub fn new(start: T, end: T) -> Self {
        assert!(start <= end, "start {:?} > end {:?}!", start, end);
        Self { l: start, r: end }
    }
    pub fn get_start(&self) -> T {
        self.l
    }
    pub fn get_end(&self) -> T {
        self.r
    }
    pub fn range(&self) -> (T, T) {
        (self.l, self.r)
    }
}
impl<T> IntoIterator for SimpleRange<T>
where
    T: StepByOne + Copy + PartialEq + PartialOrd + Debug,
{
    type Item = T;
    type IntoIter = SimpleRangeIterator<T>;
    fn into_iter(self) -> Self::IntoIter {
        SimpleRangeIterator::new(self.l, self.r)
    }
}
/// iterator for the simple range structure
pub struct SimpleRangeIterator<T>
where
    T: StepByOne + Copy + PartialEq + PartialOrd + Debug,
{
    current: T,
    end: T,
}
impl<T> SimpleRangeIterator<T>
where
    T: StepByOne + Copy + PartialEq + PartialOrd + Debug,
{
    pub fn new(l: T, r: T) -> Self {
        Self { current: l, end: r }
    }
}
impl<T> Iterator for SimpleRangeIterator<T>
where
    T: StepByOne + Copy + PartialEq + PartialOrd + Debug,
{
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current == self.end {
            None
        } else {
            let t = self.current;
            self.current.step();
            Some(t)
        }
    }
}
/// a simple range structure for virtual page number
pub type VPNRange = SimpleRange<VirtPageNum>;

/// write a value(`$T`) to the virtual address(dst)
/// utilized in RV64 only
pub fn copy_to_virt<T>(src: &T, dst: *mut T) {
    let src_buf_ptr: *const u8 = unsafe { core::mem::transmute(src) };
    let dst_buf_ptr: *mut u8 = unsafe { core::mem::transmute(dst) };
    let len = core::mem::size_of::<T>();
    let dst_frame_buffers = translated_byte_buffer(current_user_token(), dst_buf_ptr, len);
    let mut offset = 0;
    for dst_frame in dst_frame_buffers {
        dst_frame.copy_from_slice(unsafe {
            core::slice::from_raw_parts(src_buf_ptr.add(offset), dst_frame.len())
        });
        offset += dst_frame.len();
    }
}

use hashbrown::HashSet;
use spin::{lazy::Lazy, Mutex};

//坏地址表，mmap映射坏地址时加入此表
static BAD_ADDRESS: Lazy<Mutex<HashSet<usize>>> = Lazy::new(|| Mutex::new(HashSet::new()));

pub fn insert_bad_address(va: usize) {
    BAD_ADDRESS.lock().insert(va);
}

pub fn is_bad_address(va: usize) -> bool {
    BAD_ADDRESS.lock().contains(&va)
}

pub fn remove_bad_address(va: usize) {
    BAD_ADDRESS.lock().remove(&va);
}
