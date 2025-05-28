//! Implementation of [`MapArea`] and [`MemorySet`].
use super::{frame_alloc, FrameTracker};
use super::{PTEFlags, PageTable, PageTableEntry};
use super::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
use super::{StepByOne, VPNRange};
use crate::config::{MEMORY_END, MMIO, PAGE_SIZE, TRAMPOLINE};//,USER_STACK_SIZE};
use crate::sync::UPSafeCell;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::asm;
use lazy_static::*;
use riscv::register::satp;

use crate::info::{stext, etext, srodata, erodata, sdata, edata, sbss, ebss, ekernel};

#[cfg(target_arch = "riscv64")]
extern "C" {
    fn stext();
    fn etext();
    fn srodata();
    fn erodata();
    fn sdata();
    fn edata();
    fn sbss_with_stack();
    fn ebss();
    fn ekernel();
    fn strampoline();
}

#[cfg(target_arch = "riscv64")]
// 内核地址空间的构建只在 RV 中才需要，因为在 LA 下映射窗口已经完成了 RV 中恒等映射相同功能的操作
lazy_static! {
    /// The kernel's initial memory mapping(kernel address space)
    pub static ref KERNEL_SPACE: Arc<UPSafeCell<MemorySet>> =
        Arc::new(unsafe { UPSafeCell::new(MemorySet::new_kernel()) });
}

#[cfg(target_arch = "riscv64")]
/// the kernel token
pub fn kernel_token() -> usize {
    KERNEL_SPACE.exclusive_access().token()
}

#[cfg(target_arch = "loongarch64")]
// remove later
lazy_static! {
    /// The kernel's initial memory mapping(kernel address space)
    pub static ref KERNEL_SPACE: Arc<UPSafeCell<MemorySet>> =
        Arc::new(unsafe { UPSafeCell::new(MemorySet::new_bare()) });
}

#[cfg(target_arch = "loongarch64")]
// remove later
pub fn kernel_token() -> usize {
    unimplemented!()
}

/// address space
pub struct MemorySet {
    /// page table
    pub page_table: PageTable,
    /// areas
    pub areas: Vec<MapArea>,
}

impl MemorySet {
    /// Create a new empty `MemorySet`.
    pub fn new_bare() -> Self {
        Self {
            page_table: PageTable::new(),
            areas: Vec::new(),
        }
    }
    /// Get he page table token
    pub fn token(&self) -> usize {
        self.page_table.token()
    }
    #[cfg(target_arch = "riscv64")]
    /// Assume that no conflicts.
    pub fn insert_framed_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) {
        self.push(
            MapArea::new(start_va, end_va, MapType::Framed, permission),
            None,
        );
    }
    pub fn remove_area_with_start_vpn(&mut self, start_vpn: VirtPageNum) {
        if let Some((idx, area)) = self
            .areas
            .iter_mut()
            .enumerate()
            .find(|(_, area)| area.vpn_range.get_start() == start_vpn)
        {
            area.unmap(&mut self.page_table);
            self.areas.remove(idx);
            #[cfg(target_arch = "riscv64")]
            unsafe {
                asm!("sfence.vma");
            }
        }
    }
    #[cfg(target_arch = "loongarch64")]
    /// Assume that no conflicts.
    pub fn insert_area(&mut self, start_va: VirtAddr, end_va: VirtAddr, permission: MapPermission) {
        self.push(MapArea::new(start_va, end_va, permission), None);
    }

    /// Add a new MapArea into this MemorySet.
    /// Assuming that there are no conflicts in the virtual address
    /// space.
    fn push(&mut self, mut map_area: MapArea, data: Option<&[u8]>) {
        map_area.map(&mut self.page_table);
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data);
        }
        self.areas.push(map_area);
    }
    #[cfg(target_arch = "riscv64")]
    /// Mention that trampoline is not collected by areas.
    fn map_trampoline(&mut self) {
        self.page_table.map(
            VirtAddr::from(TRAMPOLINE).into(),
            PhysAddr::from(strampoline as usize).into(),
            PTEFlags::R | PTEFlags::X,
        );
    }

    #[cfg(target_arch = "riscv64")]
    /// Without kernel stacks.
    pub fn new_kernel() -> Self {
        let mut memory_set = Self::new_bare();
        // map trampoline
        memory_set.map_trampoline();
        // map kernel sections
        info!(".text [{:#x}, {:#x})", stext as usize, etext as usize);
        info!(".rodata [{:#x}, {:#x})", srodata as usize, erodata as usize);
        info!(".data [{:#x}, {:#x})", sdata as usize, edata as usize);
        info!(
            ".bss [{:#x}, {:#x})",
            sbss_with_stack as usize, ebss as usize
        );
        info!("mapping .text section");
        memory_set.push(
            MapArea::new(
                (stext as usize).into(),
                (etext as usize).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::X,
            ),
            None,
        );
        info!("mapping .rodata section");
        memory_set.push(
            MapArea::new(
                (srodata as usize).into(),
                (erodata as usize).into(),
                MapType::Identical,
                MapPermission::R,
            ),
            None,
        );
        info!("mapping .data section");
        memory_set.push(
            MapArea::new(
                (sdata as usize).into(),
                (edata as usize).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        info!("mapping .bss section");
        memory_set.push(
            MapArea::new(
                (sbss_with_stack as usize).into(),
                (ebss as usize).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        info!("mapping physical memory");
        memory_set.push(
            MapArea::new(
                (ekernel as usize).into(),
                MEMORY_END.into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        info!("mapping memory-mapped registers");
        for pair in MMIO {
            memory_set.push(
                MapArea::new(
                    (*pair).0.into(),
                    ((*pair).0 + (*pair).1).into(),
                    MapType::Identical,
                    MapPermission::R | MapPermission::W,
                ),
                None,
            );
        }
        memory_set
    }

    /// Include sections in elf and trampoline and TrapContext and user stack,
    /// also returns user_sp_base and entry point.
    pub fn from_elf(elf_data: &[u8]) -> (Self, usize, usize) {
        let mut memory_set = Self::new_bare();
        #[cfg(target_arch = "riscv64")]
        // map trampoline
        memory_set.map_trampoline();
        // map program headers of elf, with U flag
        let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
        let elf_header = elf.header;
        let magic = elf_header.pt1.magic;
        assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");
        let ph_count = elf_header.pt2.ph_count();
        let mut max_end_vpn = VirtPageNum(0);
        for i in 0..ph_count {
            let ph = elf.program_header(i).unwrap();
            if ph.get_type().unwrap() == xmas_elf::program::Type::Load {
                let start_va: VirtAddr = (ph.virtual_addr() as usize).into();
                let end_va: VirtAddr = ((ph.virtual_addr() + ph.mem_size()) as usize).into();
                //debug!("start_va {:x} end_va {:x}", start_va.0, end_va.0);

                #[cfg(target_arch = "riscv64")]
                let mut map_perm = MapPermission::U;
                #[cfg(target_arch = "loongarch64")]
                let mut map_perm = MapPermission::default();
                
                let ph_flags = ph.flags();
                #[cfg(target_arch = "riscv64")]
                {
                    if ph_flags.is_read() {
                        map_perm |= MapPermission::R;
                    }
                    if ph_flags.is_write() {
                        map_perm |= MapPermission::W;
                    }
                    if ph_flags.is_execute() {
                        map_perm |= MapPermission::X;
                    }
                }
                #[cfg(target_arch = "loongarch64")]
                {
                    if !ph_flags.is_read() {
                        map_perm |= MapPermission::NR;
                    }
                    if ph_flags.is_write() {
                        map_perm |= MapPermission::W;
                    }
                    if !ph_flags.is_execute() {
                        map_perm |= MapPermission::NX;
                    }
                }
                debug!(
                    "start_va: {:?}, end_va: {:?}, map_perm: {:?}",
                    start_va, end_va, map_perm
                );
                #[cfg(target_arch = "riscv64")]
                let map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm);
                #[cfg(target_arch = "loongarch64")]
                let map_area = MapArea::new(start_va, end_va, map_perm);
                debug!("map_area: {:?}", map_area);
                
                max_end_vpn = map_area.vpn_range.get_end();
                // A optimization for mapping data, keep aligned
                if start_va.page_offset() == 0 {
                    memory_set.push(
                        map_area,
                        Some(&elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
                    );
                } else {
                    let data_len = start_va.page_offset() + ph.file_size() as usize;
                    let mut data: Vec<u8> = Vec::with_capacity(data_len);
                    data.resize(data_len, 0);
                    data[start_va.page_offset()..].copy_from_slice(&elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]);
                    memory_set.push(
                        map_area,
                        Some(data.as_slice()),
                    );
                }
            }
        }
        // map user stack with U flags
        //debug!("to map user stack,max end vpn : {}",max_end_vpn.0);
        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_stack_base: usize = max_end_va.into(); // user_stack_bottom
        // guard page，用户栈
        user_stack_base += PAGE_SIZE;
        // 返回 address空间,用户栈顶,入口地址
        (
            memory_set,
            user_stack_base,
            elf.header.pt2.entry_point() as usize,
        )
    }
    /// Create a new address space by copy code&data from a exited process's address space.
    pub fn from_existed_user(user_space: &Self) -> Self {
        let mut memory_set = Self::new_bare();
        #[cfg(target_arch = "riscv64")]
        // map trampoline
        memory_set.map_trampoline();
        // copy data sections/trap_context/user_stack
        for area in user_space.areas.iter() {
            let new_area = MapArea::from_another(area);
            memory_set.push(new_area, None);
            // copy data from another space
            for vpn in area.vpn_range {
                let src_ppn = user_space.translate(vpn).unwrap().ppn();
                let dst_ppn = memory_set.translate(vpn).unwrap().ppn();
                dst_ppn
                    .get_bytes_array()
                    .copy_from_slice(src_ppn.get_bytes_array());
            }
        }
        memory_set
    }
    #[cfg(target_arch = "riscv64")]
    /// Change page table by writing satp CSR Register.
    pub fn activate(&self) {
        let satp = self.page_table.token();
        unsafe {
            satp::write(satp);
            asm!("sfence.vma");
        }
    }
    /// Translate a virtual page number to a page table entry
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.page_table.translate(vpn)
    }

    ///Remove all `MapArea`
    pub fn recycle_data_pages(&mut self) {
        //*self = Self::new_bare();
        self.areas.clear();
    }

    /// shrink the area to new_end
    /// Used in TaskUserRes, RV
    pub fn shrink_to(&mut self, start: VirtAddr, new_end: VirtAddr) -> bool {
        if let Some(area) = self
            .areas
            .iter_mut()
            .find(|area| area.vpn_range.get_start() == start.floor())
        {
            area.shrink_to(&mut self.page_table, new_end.ceil());
            true
        } else {
            false
        }
    }

    /// append the area to new_end
    /// Used in TaskUserRes, RV
    pub fn append_to(&mut self, start: VirtAddr, new_end: VirtAddr) -> bool {
        debug!("in memory set to append,start = {},start floor = {}",start.0,start.floor().0);
        if let Some(area) = self
            .areas
            .iter_mut()
            .find(|area| area.vpn_range.get_start() == start.floor())
        {
            //debug!("to append page table");
            area.append_to(&mut self.page_table, new_end.ceil());
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
pub struct MapArea {
    pub vpn_range: VPNRange,
    pub data_frames: BTreeMap<VirtPageNum, FrameTracker>,
    #[cfg(target_arch = "riscv64")] pub map_type: MapType,
    pub map_perm: MapPermission,
}

impl MapArea {
    pub fn new(
        start_va: VirtAddr,
        end_va: VirtAddr,
        #[cfg(target_arch = "riscv64")] map_type: MapType,
        map_perm: MapPermission,
    ) -> Self {
        // TRACE!("MapArea::new: {:#x}-{:# x}", start_va.0, end_va.0);
        let start_vpn: VirtPageNum = start_va.floor();
        let end_vpn: VirtPageNum = end_va.ceil();
        //debug!("in maparea start floor = {}",start_va.floor().0);
        Self {
            vpn_range: VPNRange::new(start_vpn, end_vpn),
            data_frames: BTreeMap::new(),
            #[cfg(target_arch = "riscv64")] map_type,
            map_perm,
        }
    }
    pub fn from_another(another: &Self) -> Self {
        Self {
            vpn_range: VPNRange::new(another.vpn_range.get_start(), another.vpn_range.get_end()),
            data_frames: BTreeMap::new(),
            #[cfg(target_arch = "riscv64")] map_type: another.map_type,
            map_perm: another.map_perm,
        }
    }
    pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        let ppn: PhysPageNum;
        #[cfg(target_arch = "riscv64")]
        match self.map_type {
            MapType::Identical => {
                ppn = PhysPageNum(vpn.0);
            }
            MapType::Framed => {
                let frame = frame_alloc().unwrap();
                ppn = frame.ppn;
                self.data_frames.insert(vpn, frame);
            }
        }
        #[cfg(target_arch = "loongarch64")]
        {
            let frame = frame_alloc().unwrap();
            ppn = frame.ppn;
            self.data_frames.insert(vpn, frame); //虚拟页号与物理页帧的对应关系
        }
        let pte_flags = PTEFlags::from_bits(self.map_perm.bits).unwrap();
        page_table.map(vpn, ppn, pte_flags);
    }
    pub fn unmap_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        #[cfg(target_arch = "riscv64")]
        if self.map_type == MapType::Framed {
            self.data_frames.remove(&vpn);
        }
        #[cfg(target_arch = "loongarch64")]
        {
            self.data_frames.remove(&vpn);
        }
        page_table.unmap(vpn);
    }
    pub fn map(&mut self, page_table: &mut PageTable) {
        for vpn in self.vpn_range {
            self.map_one(page_table, vpn);
        }
    }
    pub fn unmap(&mut self, page_table: &mut PageTable) {
        for vpn in self.vpn_range {
            self.unmap_one(page_table, vpn);
        }
    }
    /// Used in RV64
    pub fn shrink_to(&mut self, page_table: &mut PageTable, new_end: VirtPageNum) {
        for vpn in VPNRange::new(new_end, self.vpn_range.get_end()) {
            self.unmap_one(page_table, vpn)
        }
        self.vpn_range = VPNRange::new(self.vpn_range.get_start(), new_end);
    }
    /// Used in RV64
    pub fn append_to(&mut self, page_table: &mut PageTable, new_end: VirtPageNum) {
        for vpn in VPNRange::new(self.vpn_range.get_end(), new_end) {
            self.map_one(page_table, vpn)
        }
        self.vpn_range = VPNRange::new(self.vpn_range.get_start(), new_end);
    }
    /// data: start-aligned but maybe with shorter length
    /// assume that all frames were cleared before
    pub fn copy_data(&mut self, page_table: &mut PageTable, data: &[u8]) {
        #[cfg(target_arch = "riscv64")]
        assert_eq!(self.map_type, MapType::Framed);
        let mut start: usize = 0;
        let mut current_vpn = self.vpn_range.get_start();
        let len = data.len();
        loop {
            let src = &data[start..len.min(start + PAGE_SIZE)];
            let dst = &mut page_table
                .translate(current_vpn)
                .unwrap()
                .ppn()
                .get_bytes_array()[..src.len()];
            dst.copy_from_slice(src);
            start += PAGE_SIZE;
            if start >= len {
                break;
            }
            current_vpn.step();
        }
    }
}

#[cfg(target_arch = "riscv64")]
#[derive(Copy, Clone, PartialEq, Debug)]
/// map type for memory set: identical or framed
/// Only framed type in LA64
pub enum MapType {
    Identical,
    Framed,
}

#[cfg(target_arch = "riscv64")]
bitflags! {
    /// map permission corresponding to that in pte: `R W X U`
    pub struct MapPermission: u8 {
        ///Readable
        const R = 1 << 1;
        ///Writable
        const W = 1 << 2;
        ///Excutable
        const X = 1 << 3;
        ///Accessible in U mode
        const U = 1 << 4;
    }
}

//  PTEFlags 的一个子集
// 主要含有几个读写标志位和存在位，对于其它控制位
// 在后面的映射中将会固定为同一种
#[cfg(target_arch = "loongarch64")]
bitflags! {
    pub struct MapPermission: usize {
        const NX = 1 << 62;
        const NR = 1 << 61;
        const W = 1 << 8;
        const PLVL = 1 << 2;
        const PLVH = 1 << 3;
        const RPLV = 1 << 63;
    }
}
#[cfg(target_arch = "loongarch64")]
impl Default for MapPermission {
    fn default() -> Self {
        MapPermission::PLVL | MapPermission::PLVH
    }
}

/// remap test in kernel space
/// Used? in RV64
#[allow(unused)]
pub fn remap_test() {
    let mut kernel_space = KERNEL_SPACE.exclusive_access();
    let mid_text: VirtAddr = ((stext as usize + etext as usize) / 2).into();
    let mid_rodata: VirtAddr = ((srodata as usize + erodata as usize) / 2).into();
    let mid_data: VirtAddr = ((sdata as usize + edata as usize) / 2).into();
    assert!(!kernel_space
        .page_table
        .translate(mid_text.floor())
        .unwrap()
        .writable(),);
    assert!(!kernel_space
        .page_table
        .translate(mid_rodata.floor())
        .unwrap()
        .writable(),);
    assert!(!kernel_space
        .page_table
        .translate(mid_data.floor())
        .unwrap()
        .executable(),);
    println!("remap_test passed!");
}

#[cfg(target_arch = "riscv64")]
// RV version, LA is needed
impl MapPermission {
    /// Convert from port to MapPermission
    pub fn from_port(port: usize) -> Self {
        let bits = (port as u8) << 1;
        MapPermission::from_bits(bits).unwrap() 
    }

    /// Add user permission for MapPermission
    pub fn with_user(self) -> Self {
        self | MapPermission::U
    }
}

#[cfg(target_arch = "riscv64")]
// RV version, LA is needed
impl MemorySet {
    /// Check if all pages in the range are mapped.
    fn all_valid(&self, start: VirtAddr, end: VirtAddr) -> bool {
        let start_vpn = start.floor();
        let end_vpn = end.ceil();
        VPNRange::new(start_vpn, end_vpn)
            .into_iter()
            .all(|vpn| 
                self.translate(vpn).map_or(false, |pte| pte.is_valid())
            )
    }

    /// Check if all pages in the range are unmapped.
    fn all_invalid(&self, start: VirtAddr, end: VirtAddr) -> bool {
        let start_vpn = start.floor();
        let end_vpn = end.ceil();
        VPNRange::new(start_vpn, end_vpn)
            .into_iter()
            .all(|vpn| 
                self.translate(vpn).map_or(true, |pte| !pte.is_valid())
            )
    }

    /// Create a new memory area with the given start address, length, and protection flags.
    pub fn mmap(&mut self, start: usize, len: usize, port: usize) -> isize {
        let start_va = VirtAddr::from(start);
        let end_va = VirtAddr::from(start + len);
        let permission = MapPermission::from_port(port).with_user();

        //debug!("mmap: start_va: {:#x}, end_va: {:#x}, permission: {:?}", start, start + len, permission);
        if !self.all_invalid(start_va, end_va) {
            //debug!("mmap: invalid range");
            return -1;
        }
        self.insert_framed_area(start_va, end_va, permission);
        //debug!("mmap succeed");
        assert!(self.all_valid(start_va, end_va));
        0
    }

    /// Unmap a memory area with the given start address and length.
    pub fn munmap(&mut self, start: usize, len: usize) -> isize {
        let start_va = VirtAddr::from(start);
        let end_va = VirtAddr::from(start + len);
        //debug!("munmap: start_va: {:#x}, end_va: {:#x}", start, start + len);
        if !self.all_valid(start_va, end_va) {
            return -1;
        }
        let area = self
            .areas
            .iter_mut()
            .find(|area| area.vpn_range.get_start() == start_va.floor())
            .unwrap();
        area.unmap(&mut self.page_table);
        //self.areas.retain(|area| area.vpn_range.get_start() != start_va.floor());
        assert!(self.all_invalid(start_va, end_va));
        0
    }
}
