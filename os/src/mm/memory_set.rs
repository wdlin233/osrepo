//! Implementation of [`MapArea`] and [`MemorySet`].
use super::{frame_alloc, FrameTracker};
use super::{PTEFlags, PageTable, PageTableEntry};
use super::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
use super::{StepByOne, VPNRange};
use crate::config::{
    MEMORY_END, MMAP_TOP, MMIO, PAGE_SIZE, TRAMPOLINE, USER_HEAP_BOTTOM, USER_HEAP_SIZE,
};
use crate::fs::{root_inode, File, OSInode, OpenFlags, SEEK_CUR, SEEK_SET};
use crate::mm::group::GROUP_SHARE;
#[cfg(target_arch = "riscv64")]
use crate::mm::map_area::MapType;
use crate::mm::map_area::{MapArea, MapAreaType, MapPermission};
use crate::mm::page_fault_handler::{
    cow_page_fault, lazy_page_fault, mmap_read_page_fault, mmap_write_page_fault,
};
//,USER_STACK_SIZE};
#[cfg(target_arch = "loongarch64")]
use crate::hal::{ebss, edata, ekernel, erodata, etext, sbss, sdata, srodata, stext};
#[cfg(target_arch = "riscv64")]
use crate::hal::{
    ebss, edata, ekernel, erodata, etext, sbss_with_stack, sdata, srodata, stext, strampoline,
};
use crate::mm::page_table::flush_tlb;
use crate::mm::{safe_translated_byte_buffer, translated_byte_buffer, UserBuffer};
use crate::sync::UPSafeCell;
use crate::syscall::MmapFlags;
use crate::task::{current_process, Aux, AuxType};
use crate::utils::SysErrNo;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::asm;
use core::error;
use lazy_static::*;
#[cfg(target_arch = "loongarch64")]
use loongarch64::register::estat::*;
#[cfg(target_arch = "riscv64")]
use riscv::register::{
    satp,
    scause::{Exception, Trap},
};

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

pub struct MemorySet {
    /// inner data
    pub inner: UPSafeCell<MemorySetInner>,
}

impl MemorySet {
    pub fn new(memory_set: MemorySetInner) -> Self {
        unsafe {
            Self {
                inner: UPSafeCell::new(memory_set),
            }
        }
    }
    pub fn get_mut(&self) -> &mut MemorySetInner {
        self.inner.get_unchecked_mut()
    }
    pub fn get_ref(&self) -> &MemorySetInner {
        self.inner.get_unchecked_ref()
    }
    // 对MemorySetInner封装
    #[inline(always)]
    pub fn token(&self) -> usize {
        self.inner.get_unchecked_mut().token()
    }
    #[inline(always)]
    pub fn insert_framed_area(
        &self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
        area_type: MapAreaType,
    ) {
        self.inner
            .get_unchecked_mut()
            .insert_framed_area(start_va, end_va, permission, area_type);
    }
    #[inline(always)]
    pub fn remove_area_with_start_vpn(&self, start_vpn: VirtPageNum) {
        self.inner
            .get_unchecked_mut()
            .remove_area_with_start_vpn(start_vpn);
    }
    #[inline(always)]
    pub fn push(&self, map_area: MapArea, data: Option<&[u8]>) {
        self.inner.get_unchecked_mut().push(map_area, data);
    }
    #[cfg(target_arch = "riscv64")]
    #[inline(always)]
    pub fn map_trampoline(&self) {
        self.inner.get_unchecked_mut().map_trampoline();
    }
    #[cfg(target_arch = "riscv64")]
    #[inline(always)]
    pub fn new_kernel() -> Self {
        Self::new(MemorySetInner::new_kernel())
    }
    #[inline(always)]
    pub fn from_elf(elf_data: &[u8], heap_id: usize) -> (Self, usize, usize, Vec<Aux>) {
        let (memory_set, user_heap_bottom, entry_point, auxv) =
            MemorySetInner::from_elf(elf_data, heap_id);
        (Self::new(memory_set), user_heap_bottom, entry_point, auxv)
    }
    #[inline(always)]
    pub fn from_existed_user(user_space: &MemorySet) -> Self {
        Self::new(MemorySetInner::from_existed_user(
            user_space.inner.get_unchecked_mut(),
        ))
    }
    #[cfg(target_arch = "riscv64")]
    #[inline(always)]
    pub fn activate(&self) {
        self.inner.get_unchecked_ref().activate();
    }
    #[inline(always)]
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.inner.get_unchecked_ref().translate(vpn)
    }
    #[inline(always)]
    pub fn recycle_data_pages(&self) {
        self.inner.get_unchecked_mut().recycle_data_pages();
    }
    #[inline(always)]
    pub fn shrink_to(&self, start: VirtAddr, new_end: VirtAddr) -> bool {
        self.inner.get_unchecked_mut().shrink_to(start, new_end)
    }
    #[inline(always)]
    pub fn append_to(&self, start: VirtAddr, new_end: VirtAddr) -> bool {
        self.inner.get_unchecked_mut().append_to(start, new_end)
    }
    #[inline(always)]
    pub fn lazy_page_fault(&self, vpn: VirtPageNum, scause: Trap) -> bool {
        self.inner.get_unchecked_mut().lazy_page_fault(vpn, scause)
    }
    #[inline(always)]
    pub fn all_valid(&self, start: VirtAddr, end: VirtAddr) -> bool {
        self.inner.get_unchecked_mut().all_valid(start, end)
    }
    #[inline(always)]
    pub fn all_invalid(&self, start: VirtAddr, end: VirtAddr) -> bool {
        self.inner.get_unchecked_mut().all_invalid(start, end)
    }
    #[inline(always)]
    pub fn insert_framed_area_with_hint(
        &self,
        hint: usize,
        size: usize,
        map_perm: MapPermission,
        area_type: MapAreaType,
    ) -> (usize, usize) {
        self.get_mut()
            .insert_framed_area_with_hint(hint, size, map_perm, area_type)
    }
    #[inline(always)]
    pub fn mmap(
        &self,
        start: usize,
        len: usize,
        port: MapPermission,
        flags: MmapFlags,
        fd: Option<Arc<OSInode>>,
        off: usize,
    ) -> usize {
        self.inner
            .get_unchecked_mut()
            .mmap(start, len, port, flags, fd, off)
    }
    #[inline(always)]
    pub fn munmap(&self, addr: usize, len: usize) -> isize {
        self.inner.get_unchecked_mut().munmap(addr, len)
    }
    #[inline(always)]
    pub fn cow_page_fault(&self, vpn: VirtPageNum, scause: Trap) -> bool {
        self.inner.get_unchecked_mut().cow_page_fault(vpn, scause)
    }
}

/// address space
pub struct MemorySetInner {
    /// page table
    pub page_table: PageTable,
    /// areas
    pub areas: Vec<MapArea>,
}

impl MemorySetInner {
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

    pub fn insert_framed_area_with_hint(
        &mut self,
        hint: usize,
        size: usize,
        map_perm: MapPermission,
        area_type: MapAreaType,
    ) -> (usize, usize) {
        let start_va = self.find_insert_addr(hint, size);
        let end_va = start_va + size;
        self.insert_framed_area(
            VirtAddr::from(start_va),
            VirtAddr::from(end_va),
            map_perm,
            area_type,
        );
        (start_va, end_va)
    }

    /// Assume that no conflicts.
    pub fn insert_framed_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
        area_type: MapAreaType,
    ) {
        #[cfg(target_arch = "riscv64")]
        self.push(
            MapArea::new(start_va, end_va, MapType::Framed, permission, area_type),
            None,
        );
        #[cfg(target_arch = "loongarch64")]
        self.push(MapArea::new(start_va, end_va, permission, area_type), None);
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

    /// Add a new MapArea into this MemorySet.
    /// Assuming that there are no conflicts in the virtual address
    /// space.
    fn push(&mut self, mut map_area: MapArea, data: Option<&[u8]>) {
        // debug!(
        //     "in mem set inner push, the map area is, start : {}, end :{}",
        //     map_area.vpn_range.get_start().0,
        //     map_area.vpn_range.get_end().0
        // );
        map_area.map(&mut self.page_table);
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data);
        }
        self.areas.push(map_area);
    }
    pub fn push_lazily(&mut self, map_area: MapArea) {
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
        use core::iter::Map;

        use crate::mm::map_area::MapAreaType;

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
                MapAreaType::Elf,
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
                MapAreaType::Elf,
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
                MapAreaType::Elf,
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
                MapAreaType::Elf,
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
                MapAreaType::Physical,
            ),
            None,
        );
        info!("mapping memory-mapped registers");
        for pair in MMIO {
            use crate::mm::map_area::MapAreaType;

            memory_set.push(
                MapArea::new(
                    (*pair).0.into(),
                    ((*pair).0 + (*pair).1).into(),
                    MapType::Identical,
                    MapPermission::R | MapPermission::W,
                    MapAreaType::MMIO,
                ),
                None,
            );
        }
        memory_set
    }

    /// Include sections in elf and trampoline and TrapContext and user stack,
    /// also returns user_sp_base and entry point.
    pub fn from_elf(elf_data: &[u8], heap_id: usize) -> (Self, usize, usize, Vec<Aux>) {
        let mut memory_set = Self::new_bare();
        let mut auxv = Vec::new();
        #[cfg(target_arch = "riscv64")]
        // map trampoline
        memory_set.map_trampoline();
        // map program headers of elf, with U flag
        let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
        let elf_header = elf.header;
        let _magic = elf_header.pt1.magic;
        //assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");
        let ph_count = elf_header.pt2.ph_count();
        let mut max_end_vpn = VirtPageNum(0);

        auxv.push(Aux::new(
            AuxType::PHENT,
            elf.header.pt2.ph_entry_size() as usize,
        )); // ELF64 header 64bytes
        auxv.push(Aux::new(AuxType::PHNUM, ph_count as usize));
        auxv.push(Aux::new(AuxType::PAGESZ, PAGE_SIZE as usize));
        // // 设置动态链接
        // if let Some(interp_entry_point) = memory_set.load_dl_interp_if_needed(&elf) {
        //     auxv.push(Aux::new(AuxType::BASE, DL_INTERP_OFFSET));
        //     entry_point = interp_entry_point;
        // } else {
        auxv.push(Aux::new(AuxType::BASE, 0));
        //}
        auxv.push(Aux::new(AuxType::FLAGS, 0 as usize));
        auxv.push(Aux::new(
            AuxType::ENTRY,
            elf.header.pt2.entry_point() as usize,
        ));
        auxv.push(Aux::new(AuxType::UID, 0 as usize));
        auxv.push(Aux::new(AuxType::EUID, 0 as usize));
        auxv.push(Aux::new(AuxType::GID, 0 as usize));
        auxv.push(Aux::new(AuxType::EGID, 0 as usize));
        auxv.push(Aux::new(AuxType::PLATFORM, 0 as usize));
        auxv.push(Aux::new(AuxType::HWCAP, 0 as usize));
        auxv.push(Aux::new(AuxType::CLKTCK, 100 as usize));
        auxv.push(Aux::new(AuxType::SECURE, 0 as usize));
        auxv.push(Aux::new(AuxType::NOTELF, 0x112d as usize));

        let mut head_va = 0;
        let mut has_found_header_va = false;

        debug!("elf program header count: {}", ph_count);
        for i in 0..ph_count {
            let ph = elf.program_header(i).unwrap();
            if ph.get_type().unwrap() == xmas_elf::program::Type::Load {
                let start_va: VirtAddr = (ph.virtual_addr() as usize).into();
                let end_va: VirtAddr = ((ph.virtual_addr() + ph.mem_size()) as usize).into();
                debug!("start_va {:x} end_va {:x}", start_va.0, end_va.0);
                if !has_found_header_va {
                    head_va = start_va.0;
                    has_found_header_va = true;
                }
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
                let map_area = MapArea::new(
                    start_va,
                    end_va,
                    MapType::Framed,
                    map_perm,
                    MapAreaType::Elf,
                );
                #[cfg(target_arch = "loongarch64")]
                let map_area = MapArea::new(start_va, end_va, map_perm, MapAreaType::Elf);

                max_end_vpn = map_area.vpn_range.get_end();
                debug!("before page offset, max end vpn is : {}", max_end_vpn.0);
                // A optimization for mapping data, keep aligned
                if start_va.page_offset() == 0 {
                    debug!("page offset == 0");
                    memory_set.push(
                        map_area,
                        Some(
                            &elf.input
                                [ph.offset() as usize..(ph.offset() + ph.file_size()) as usize],
                        ),
                    );
                } else {
                    debug!("page offset != 0");
                    //error!("start_va page offset is not zero, start_va: {:?}", start_va);
                    let data_len = start_va.page_offset() + ph.file_size() as usize;
                    let mut data: Vec<u8> = Vec::with_capacity(data_len);
                    data.resize(data_len, 0);
                    data[start_va.page_offset()..].copy_from_slice(
                        &elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize],
                    );
                    debug!("to mem set push");
                    memory_set.push(map_area, Some(data.as_slice()));
                }
            }
        }

        auxv.push(Aux {
            aux_type: AuxType::PHDR,
            value: head_va + elf.header.pt2.ph_offset() as usize,
        });
        // map user stack with U flags
        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_heap_bottom: usize = USER_HEAP_BOTTOM + heap_id * USER_HEAP_SIZE;

        // guard page
        user_heap_bottom += PAGE_SIZE;
        info!(
            "user heap bottom: {:#x}, {}",
            user_heap_bottom, user_heap_bottom
        );
        let user_heap_top: usize = user_heap_bottom;
        #[cfg(target_arch = "riscv64")]
        let prem = MapPermission::R | MapPermission::W | MapPermission::U;
        #[cfg(target_arch = "loongarch64")]
        let perm = MapPermission::W | MapPermission::PLVL;
        memory_set.insert_framed_area(
            user_heap_bottom.into(),
            user_heap_top.into(),
            perm,
            MapAreaType::Brk,
        );
        // 返回 address空间,用户栈顶,入口地址
        (
            memory_set,
            user_heap_bottom,
            elf.header.pt2.entry_point() as usize,
            auxv,
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
        debug!(
            "in memory set to append,start = {},start floor = {}",
            start.0,
            start.floor().0
        );
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
    pub fn lazy_page_fault(&mut self, vpn: VirtPageNum, scause: Trap) -> bool {
        let pte = self.page_table.translate(vpn);
        //debug!("vpn={:#X},enter lazy", vpn.0);
        if pte.is_some() && pte.unwrap().is_valid() {
            return false;
        }
        //println!("vpn={:#X},enter lazy2", vpn.0);
        //mmap
        if let Some(area) = self
            .areas
            .iter_mut()
            .filter(|area| area.area_type == MapAreaType::Mmap)
            .find(|area| {
                let (start, end) = area.vpn_range.range();
                start <= vpn && vpn < end
            })
        {
            // println!("vpn={:#X},enter lazy3", vpn.0);
            #[cfg(target_arch = "riscv64")]
            if scause == Trap::Exception(Exception::LoadPageFault)
                || scause == Trap::Exception(Exception::InstructionPageFault)
            {
                mmap_read_page_fault(vpn.into(), &mut self.page_table, area);
            } else {
                mmap_write_page_fault(vpn.into(), &mut self.page_table, area);
            }
            #[cfg(target_arch = "loongarch64")]
            {
                use loongarch64::register::estat;
                let cause = estat::read().cause();

                // 使用 FetchPageFault 代替 InstructionPageFault
                match cause {
                    Trap::Exception(Exception::LoadPageFault)
                    | Trap::Exception(Exception::FetchPageFault) => {
                        mmap_read_page_fault(vpn.into(), &mut self.page_table, area);
                    }
                    _ => {
                        mmap_write_page_fault(vpn.into(), &mut self.page_table, area);
                    }
                }
            }
            return true;
        }
        //brk or stack
        if let Some(area) = self
            .areas
            .iter_mut()
            .filter(|area| {
                area.area_type == MapAreaType::Brk || area.area_type == MapAreaType::Stack
            })
            .find(|area| {
                let (start, end) = area.vpn_range.range();
                start <= vpn && vpn < end
            })
        {
            //println!("vpn={:#X},enter lazy4", vpn.0);
            lazy_page_fault(vpn.into(), &mut self.page_table, area);
            return true;
        }
        false
    }
    // #[inline(always)] for multiThread, use lazy_page_fault simply
    // pub fn lazy_page_fault(&self, vpn: VirtPageNum, scause: Trap) -> bool {
    //     self.inner.get_unchecked_mut().lazy_page_fault(vpn, scause)
    // }
}

/// remap test in kernel space
/// Used? in RV64
#[cfg(target_arch = "riscv64")]
#[allow(unused)]
pub fn remap_test() {
    let space = KERNEL_SPACE.exclusive_access();
    let mut kernel_space = space.inner.exclusive_access();
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
    use crate::println;
    println!("remap_test passed!");
}

// RV passed, compatible with LA
impl MemorySetInner {
    /// Check if all pages in the range are mapped.
    fn all_valid(&self, start: VirtAddr, end: VirtAddr) -> bool {
        let start_vpn = start.floor();
        let end_vpn = end.ceil();
        VPNRange::new(start_vpn, end_vpn)
            .into_iter()
            .all(|vpn| self.translate(vpn).map_or(false, |pte| pte.is_valid()))
    }

    /// Check if all pages in the range are unmapped.
    fn all_invalid(&self, start: VirtAddr, end: VirtAddr) -> bool {
        let start_vpn = start.floor();
        let end_vpn = end.ceil();
        VPNRange::new(start_vpn, end_vpn)
            .into_iter()
            .all(|vpn| self.translate(vpn).map_or(true, |pte| !pte.is_valid()))
    }

    /// Create a new memory area with the given start address, length, and protection flags.
    pub fn mmap(
        &mut self,
        addr: usize,
        len: usize,
        map_perm: MapPermission,
        flags: MmapFlags,
        file: Option<Arc<OSInode>>,
        off: usize,
    ) -> usize {
        debug!("(MemorySetInner, mmap) addr:{:#x}, len:{}", addr, len);
        // 映射到固定地址
        // 如果已经映射的部分和需要固定映射的部分冲突,已经映射的部分将被拆分
        if flags.contains(MmapFlags::MAP_FIXED) {
            let start_vpn = VirtAddr::from(addr).floor();
            let end_vpn = VirtAddr::from(addr + len).ceil();
            let need_split = self.areas.iter().any(|area| {
                let (l, r) = area.vpn_range.range();
                if l <= start_vpn && end_vpn <= r {
                    !(l == start_vpn && r == end_vpn && map_perm == area.map_perm)
                } else {
                    false
                }
            });
            if need_split {
                self.mprotect(start_vpn, end_vpn, map_perm);
                for area in self.areas.iter_mut() {
                    let (start, end) = area.vpn_range.range();
                    if start == start_vpn && end == end_vpn {
                        area.mmap_file.offset = off;
                        area.mmap_file.file = file.clone();
                    }
                }
            } else {
                #[cfg(target_arch = "riscv64")]
                self.push_lazily(MapArea::new_mmap(
                    VirtAddr::from(addr),
                    VirtAddr::from(addr + len),
                    MapType::Framed,
                    map_perm,
                    MapAreaType::Mmap,
                    file.clone(),
                    off,
                    flags,
                ));
                #[cfg(target_arch = "loongarch64")]
                self.push_lazily(MapArea::new_mmap(
                    VirtAddr::from(addr),
                    VirtAddr::from(addr + len),
                    map_perm,
                    MapAreaType::Mmap,
                    file.clone(),
                    off,
                    flags,
                ));
            }
            return addr;
        }
        // 自行选择地址,计算已经使用的MMap地址
        let addr = self.find_insert_addr(MMAP_TOP, len);
        debug!(
            "(MemorySetInner, mmap) start_va:{:#x},end_va:{:#x}",
            VirtAddr::from(addr).0,
            VirtAddr::from(addr + len).0
        );
        let area_type = if flags.contains(MmapFlags::MAP_STACK) {
            MapAreaType::Stack
        } else {
            MapAreaType::Mmap
        };
        //self.insert_framed_area(VirtAddr::from(addr), VirtAddr::from(addr + len), map_perm, area_type);
        #[cfg(target_arch = "riscv64")]
        self.push_lazily(MapArea::new_mmap(
            VirtAddr::from(addr),
            VirtAddr::from(addr + len),
            MapType::Framed,
            map_perm,
            area_type,
            file,
            off,
            flags,
        ));
        #[cfg(target_arch = "loongarch64")]
        self.push_lazily(MapArea::new_mmap(
            VirtAddr::from(addr),
            VirtAddr::from(addr + len),
            map_perm,
            area_type,
            file,
            off,
            flags,
        ));
        addr
    }

    /// Unmap a memory area with the given start address and length.
    pub fn munmap(&mut self, addr: usize, len: usize) -> isize {
        debug!("in memory set, munmap");
        let start_vpn = VirtPageNum::from(VirtAddr::from(addr));
        let end_vpn = VirtPageNum::from(VirtAddr::from(addr + len));
        debug!(
            "[MemorySet] start_vpn:{:#x},end_vpn:{:#x}",
            start_vpn.0, end_vpn.0
        );
        while let Some((idx, area)) = self
            .areas
            .iter_mut()
            .enumerate()
            .filter(|(_, area)| area.area_type == MapAreaType::Mmap)
            .find(|(_, area)| {
                let (start, end) = area.vpn_range.range();
                start >= start_vpn && end <= end_vpn
            })
        {
            // 检查是否需要写回
            if area.mmap_flags.contains(MmapFlags::MAP_SHARED)
                && area.map_perm.contains(MapPermission::W)
            {
                let file = area.mmap_file.file.clone().unwrap();
                let found_res = root_inode().find(&file.inode.path(), OpenFlags::O_RDWR, 0);
                if found_res.clone().err() != Some(SysErrNo::ENOENT) {
                    // 相邻的页面一次写回
                    let mut wb_range: Vec<(VirtPageNum, VirtPageNum)> = Vec::new();
                    // debug!(
                    //     "when munmap {}, file {} has not been unlinked!",
                    //     idx,
                    //     file.inode.path()
                    // );
                    VPNRange::new(start_vpn, end_vpn)
                        .into_iter()
                        .for_each(|vpn| {
                            if area.data_frames.contains_key(&vpn) {
                                if wb_range.is_empty() {
                                    wb_range.push((vpn, VirtPageNum(vpn.0 + 1)));
                                } else {
                                    let end_range = wb_range.pop().unwrap();
                                    if end_range.1 == vpn {
                                        wb_range.push((end_range.0, VirtPageNum(vpn.0 + 1)));
                                    } else {
                                        wb_range.push(end_range);
                                        wb_range.push((vpn, VirtPageNum(vpn.0 + 1)));
                                    }
                                }
                            }
                        });
                    // 每次写回前要设置偏移量
                    let off = file.lseek(0, SEEK_CUR).unwrap();
                    wb_range.into_iter().for_each(|(start_vpn, end_vpn)| {
                        let start_addr: usize = VirtAddr::from(start_vpn).into();
                        let mapped_len: usize = (end_vpn.0 - start_vpn.0) * PAGE_SIZE;
                        // debug!(
                        //     "when munmap {}, file {} write back start_addr:{:#x},mapped_len:{}",
                        //     idx,
                        //     file.inode.path(),
                        //     start_addr,
                        //     mapped_len
                        // );
                        info!("start_addr:{:#x},mapped_len:{}", start_addr, mapped_len);

                        // let buf = UserBuffer::new_single(data_flow!({
                        //     core::slice::from_raw_parts_mut(start_addr as *mut u8, mapped_len)
                        // }));
                        let token = self.page_table.token();
                        let buffers =
                            translated_byte_buffer(token, start_addr as *const u8, mapped_len);
                        let buf = UserBuffer::new(buffers);

                        file.lseek((start_addr - addr) as isize, SEEK_SET);
                        debug!(
                            "when munmap {}, file {} write back buf:bbb",
                            idx,
                            file.inode.path(),
                        );
                        file.write(buf);
                    });
                    file.lseek(off as isize, SEEK_SET);
                } else {
                    debug!(
                        "when munmap {}, file {} has been unlinked before!",
                        idx,
                        file.inode.path()
                    );
                }
            }
            debug!(
                "[area vpn_range] start:{:#x},end:{:#x}",
                area.vpn_range.get_start().0,
                area.vpn_range.get_end().0
            );
            //取消映射
            for vpn in VPNRange::new(start_vpn, end_vpn) {
                area.unmap_one(&mut self.page_table, vpn);
            }
            let area_end_vpn = area.vpn_range.get_end();
            // debug!(
            //     "[MemorySet] end_vpn:{:#x},area_end_vpn:{:#x}",
            //     end_vpn.0, area_end_vpn.0
            // );
            // 是否回收,mprotect可能将mmap区域拆分成多个
            if area_end_vpn <= end_vpn {
                self.areas.remove(idx);
            } else {
                area.vpn_range = VPNRange::new(end_vpn, area_end_vpn);
            }
            flush_tlb();
        }
        0
    }
    pub fn mprotect(
        &mut self,
        start_vpn: VirtPageNum,
        end_vpn: VirtPageNum,
        map_perm: MapPermission,
    ) {
        //因修改而新增的Area
        debug!(
            "(MemorySetInner, mprotect) start_vpn:{:#x}, end_vpn:{:#x}, map_perm:{:?}",
            start_vpn.0, end_vpn.0, map_perm
        );
        let mut new_areas = Vec::new();
        for area in self.areas.iter_mut() {
            let (start, end) = area.vpn_range.range();
            //debug!("start is {:x}, end is {:x}", start.0, end.0);
            //debug!("start_vpn is {:x}, end_vpn is {:x}", start_vpn.0, end_vpn.0);
            if start >= start_vpn && end <= end_vpn {
                //修改整个area
                area.map_perm = map_perm;
                continue;
            } else if start < start_vpn && end > start_vpn && end <= end_vpn {
                //修改area后半部分
                let mut new_area = MapArea::from_another(area);
                new_area.map_perm = map_perm;
                new_area.vpn_range = VPNRange::new(start_vpn, end);
                area.vpn_range = VPNRange::new(start, start_vpn);
                GROUP_SHARE.lock().add_area(new_area.groupid);
                while !area.data_frames.is_empty() {
                    let page = area.data_frames.pop_last().unwrap();
                    new_area.data_frames.insert(page.0, page.1);
                    if page.0 == start_vpn {
                        break;
                    }
                }
                new_areas.push(new_area);
                continue;
            } else if start >= start_vpn && start < end_vpn && end > end_vpn {
                //修改area前半部分
                let mut new_area = MapArea::from_another(area);
                new_area.map_perm = map_perm;
                new_area.vpn_range = VPNRange::new(start, end_vpn);
                area.vpn_range = VPNRange::new(end_vpn, end);
                GROUP_SHARE.lock().add_area(new_area.groupid);
                while !area.data_frames.is_empty() {
                    let page = area.data_frames.pop_first().unwrap();
                    if page.0 >= end_vpn {
                        area.data_frames.insert(page.0, page.1);
                        break;
                    }
                    new_area.data_frames.insert(page.0, page.1);
                }

                new_areas.push(new_area);
                continue;
            } else if start < start_vpn && end > end_vpn {
                //修改area中间部分
                let mut front_area = MapArea::from_another(area);
                let mut back_area = MapArea::from_another(area);
                area.map_perm = map_perm;
                front_area.vpn_range = VPNRange::new(start, start_vpn);
                back_area.vpn_range = VPNRange::new(end_vpn, end);
                area.vpn_range = VPNRange::new(start_vpn, end_vpn);
                GROUP_SHARE.lock().add_area(front_area.groupid);
                GROUP_SHARE.lock().add_area(back_area.groupid);
                while !area.data_frames.is_empty() {
                    let page = area.data_frames.pop_first().unwrap();
                    if page.0 >= start_vpn {
                        area.data_frames.insert(page.0, page.1);
                        break;
                    }
                    front_area.data_frames.insert(page.0, page.1);
                }
                while !area.data_frames.is_empty() {
                    let page = area.data_frames.pop_last().unwrap();
                    if page.0 < end_vpn {
                        area.data_frames.insert(page.0, page.1);
                        break;
                    }
                    back_area.data_frames.insert(page.0, page.1);
                }

                new_areas.push(front_area);
                new_areas.push(back_area);
            }
            //剩下的情况无相交部分，无需修改
        }
        for area in new_areas {
            for (vpn, _) in area.data_frames.iter() {
                self.page_table
                    .set_map_flags((*vpn).into(), PTEFlags::from_bits(map_perm.bits()).unwrap())
            }
            self.areas.push(area);
        }
        flush_tlb();
    }
    pub fn find_insert_addr(&self, hint: usize, size: usize) -> usize {
        info!(
            "(MemorySetInner, find_insert_addr) hint = {:#x}, size = {}",
            hint, size
        );
        let end_vpn = VirtAddr::from(hint).floor();
        let start_vpn = VirtAddr::from(hint - size).floor();
        let start_va: VirtAddr = start_vpn.into();
        //for test let start_va: VirtAddr = (start_va.0 - PAGE_SIZE).into();
        info!(
            "(MemorySetInner, find_insert_addr) start_vpn = {:#x}, end_vpn = {:#x}, start_va = {:#x}",
            start_vpn.0, end_vpn.0, start_va.0
        );
        for area in self.areas.iter() {
            let (start, end) = area.vpn_range.range();
            if end_vpn > start && start_vpn < end {
                let new_hint = VirtAddr::from(start_vpn).0 - PAGE_SIZE;
                info!(
                    "find_insert_addr: hint = {:#x}, size = {}, new_hint = {:#x}",
                    hint, size, new_hint
                );
                return self.find_insert_addr(new_hint, size);
            }
        }
        VirtAddr::from(start_vpn).0

        // use crate::config::PAGE_SIZE_BITS;
        // // 确保地址按16KB对齐
        // let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        // let aligned_hint = hint & !(PAGE_SIZE - 1);

        // // 从高地址向低地址搜索
        // let mut candidate = aligned_hint - aligned_size;

        // info!(
        //     "find_insert_addr: hint={:#x}, size={}, aligned_size={}, candidate={:#x}",
        //     hint, size, aligned_size, candidate
        // );

        // 'search: loop {
        //     // 检查候选区域是否重叠
        //     let candidate_end = candidate + aligned_size;
        //     for area in self.areas.iter() {
        //         let (area_start, area_end) = area.vpn_range.range();
        //         let area_start_va = area_start.0 << PAGE_SIZE_BITS;
        //         let area_end_va = area_end.0 << PAGE_SIZE_BITS;

        //         if candidate_end > area_start_va && candidate < area_end_va {
        //             // 有重叠，向前移动一个完整区域
        //             candidate = candidate.checked_sub(PAGE_SIZE).unwrap_or(0);
        //             info!("Overlap found, new candidate={:#x}", candidate);
        //             continue 'search;
        //         }
        //     }

        //     // 检查对齐
        //     if candidate & (PAGE_SIZE - 1) != 0 {
        //         warn!("Unaligned candidate: {:#x}, aligning down", candidate);
        //         candidate = candidate & !(PAGE_SIZE - 1);
        //     }

        //     info!("Found valid address: {:#x}", candidate);
        //     return candidate;
        // }
    }
    pub fn cow_page_fault(&mut self, vpn: VirtPageNum, scause: Trap) -> bool {
        info!("cow_page_fault: vpn = {:#x}", vpn.0);
        #[cfg(target_arch = "riscv64")]
        {
            if scause == Trap::Exception(Exception::LoadPageFault)
                || scause == Trap::Exception(Exception::InstructionPageFault)
            {
                return false;
            }
        }
        #[cfg(target_arch = "loongarch64")]
        {
            info!("cow_page_fault: scause = {:?}", scause);
            // match scause {
            //     Trap::Exception(Exception::FetchPageFault)
            //     | Trap::Exception(Exception::LoadPageFault)
            //     // load 和 fetch 都是读操作
            //     => {
            //         info!("cow_page_fault: LoadPageFault or FetchPageFault, return false");
            //         return false;

            //     }
            //     _ => {}
            // }
        }
        //找到触发cow的段
        if let Some(area) = self
            .areas
            .iter_mut()
            .filter(|area| {
                area.area_type == MapAreaType::Elf
                    || area.area_type == MapAreaType::Brk
                    || area.area_type == MapAreaType::Mmap
            })
            .find(|area| {
                let (start, end) = area.vpn_range.range();
                start <= vpn && vpn < end
            })
        {
            if let Some(pte) = self.page_table.translate(vpn) {
                if pte.is_cow() {
                    cow_page_fault(vpn.into(), &mut self.page_table, area);
                }
                return true;
            }
        }
        false
    }
}
