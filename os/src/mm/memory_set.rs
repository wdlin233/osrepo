//! Implementation of [`MapArea`] and [`MemorySet`].
use super::frame_alloc;
use super::MapType;
use crate::config::{
    DL_INTERP_OFFSET, MEMORY_END, MMAP_TOP, MMIO, PAGE_SIZE, USER_HEAP_BOTTOM,
    USER_HEAP_SIZE,
};
use crate::fs::{
    map_dynamic_link_file, open, root_inode, File, OSInode, OpenFlags, NONE_MODE, SEEK_CUR,
    SEEK_SET,
};
use crate::mm::addr_range::VAddrRange;
use crate::mm::frame_allocator::FrameTracker;
use crate::mm::group::GROUP_SHARE;
use crate::mm::map_area::{MapArea, MapAreaType, MapPermission};
use crate::mm::page_fault_handler::{
    cow_page_fault, lazy_page_fault, mmap_read_page_fault, mmap_write_page_fault,
};
use crate::mm::{translated_byte_buffer, translated_refmut, UserBuffer};
use crate::println;
use crate::sync::UPSafeCell;
use crate::syscall::MmapFlags;
use crate::task::{current_task, Aux, AuxType};
use crate::utils::{SysErrNo, SyscallRet};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::error;
use lazy_static::*;
use polyhal::pagetable::PTEFlags;
use polyhal::pagetable::TLB;
use polyhal::MappingFlags;
use polyhal::MappingSize;
use polyhal::PhysAddr;
use polyhal::VirtAddr;
use polyhal::{PageTable, PageTableWrapper};
use polyhal_trap::trap::TrapType;
use xmas_elf::ElfFile;

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
    #[inline(always)]
    pub fn token(&self) -> Arc<PageTableWrapper> {
        self.inner.get_unchecked_mut().token()
    }
    #[inline(always)]
    pub fn token_pt(&self) -> PageTable {
        self.inner.get_unchecked_mut().page_table.0
    }
    #[inline(always)]
    pub fn insert_framed_area(
        &self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_type: MapType,
        permission: MapPermission,
        area_type: MapAreaType,
    ) {
        self.inner
            .get_unchecked_mut()
            .insert_framed_area(start_va, end_va, map_type, permission, area_type);
    }
    #[inline(always)]
    pub fn remove_area_with_start_vpn(&self, start_vpn: VirtAddr) {
        self.inner
            .get_unchecked_mut()
            .remove_area_with_start_vpn(start_vpn);
    }
    #[inline(always)]
    pub fn push(&self, map_area: MapArea, data: Option<&[u8]>) {
        self.inner.get_unchecked_mut().push(map_area, data);
    }
    #[inline(always)]
    pub fn from_elf(elf_data: &[u8]) -> (Self, usize, usize, Vec<Aux>) {
        let (memory_set, user_heap_bottom, entry_point, auxv) = MemorySetInner::from_elf(elf_data);
        (Self::new(memory_set), user_heap_bottom, entry_point, auxv)
    }
    #[inline(always)]
    pub fn activate(&self) {
        self.inner.get_unchecked_ref().activate();
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
    pub fn lazy_page_fault(&self, vpn: VirtAddr, scause: TrapType) -> bool {
        self.inner.get_unchecked_mut().lazy_page_fault(vpn, scause)
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
    pub fn cow_page_fault(&self, vpn: VirtAddr, scause: TrapType) -> bool {
        self.inner.get_unchecked_mut().cow_page_fault(vpn, scause)
    }
    #[inline(always)]
    pub fn mprotect(&mut self, start_vpn: VirtAddr, end_vpn: VirtAddr, map_perm: MapPermission) {
        self.inner
            .get_unchecked_mut()
            .mprotect(start_vpn, end_vpn, map_perm);
    }
    #[inline(always)]
    pub fn insert_framed_area_with_hint(
        &mut self,
        hint: usize,
        size: usize,
        map_perm: MapPermission,
        area_type: MapAreaType,
    ) -> (usize, usize) {
        self.inner
            .get_unchecked_mut()
            .insert_framed_area_with_hint(hint, size, map_perm, area_type)
    }
    #[inline(always)]
    pub fn lazy_insert_framed_area_with_hint(
        &mut self,
        hint: usize,
        size: usize,
        map_perm: MapPermission,
        area_type: MapAreaType,
    ) -> (usize, usize) {
        self.inner
            .get_unchecked_mut()
            .lazy_insert_framed_area_with_hint(hint, size, map_perm, area_type)
    }
    #[inline(always)]
    pub fn lazy_clone_area(&self, start_vpn: VirtAddr, another: &MemorySetInner) {
        self.get_mut().lazy_clone_area(start_vpn, another)
    }
    #[inline(always)]
    pub fn clone_area(&self, start_vpn: VirtAddr, another: &MemorySetInner) {
        self.get_mut().clone_area(start_vpn, another)
    }
    #[inline(always)]
    pub fn recycle(&mut self) -> SyscallRet {
        self.inner.get_unchecked_mut().recycle_data_pages()
    }
    #[inline(always)]
    pub fn translate(&self, vpn: VirtAddr) -> Option<(PhysAddr, MappingFlags)> {
        self.inner.get_unchecked_ref().translate(vpn)
    }
    #[inline(always)]
    pub fn shm(
        &self,
        addr: usize,
        size: usize,
        map_perm: MapPermission,
        pages: Vec<Arc<FrameTracker>>,
    ) -> usize {
        self.get_mut().shm(addr, size, map_perm, pages)
    }
}

/// address space
pub struct MemorySetInner {
    /// page table
    pub page_table: Arc<PageTableWrapper>,
    /// areas
    pub areas: Vec<MapArea>,
}

impl MemorySetInner {
    /// Create a new empty `MemorySet`.
    pub fn new_bare() -> Self {
        Self {
            page_table: Arc::new(PageTableWrapper::alloc()),
            areas: Vec::new(),
        }
    }
    /// Get he page table token
    pub fn token(&self) -> Arc<PageTableWrapper> {
        self.page_table.clone()
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
            MapType::Framed,
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
        map_type: MapType,
        permission: MapPermission,
        area_type: MapAreaType,
    ) {
        self.push(
            MapArea::new(start_va, end_va, map_type, permission, area_type),
            None,
        );
    }
    pub fn remove_area_with_start_vpn(&mut self, start_vpn: VirtAddr) {
        if let Some((idx, area)) = self
            .areas
            .iter_mut()
            .enumerate()
            .find(|(_, area)| area.vaddr_range.get_start() == start_vpn)
        {
            area.unmap(&mut self.page_table);
            self.areas.remove(idx);
            TLB::flush_all();
        }
    }

    /// Add a new MapArea into this MemorySet.
    /// Assuming that there are no conflicts in the virtual address
    /// space.
    fn push(&mut self, mut map_area: MapArea, data: Option<&[u8]>) {
        map_area.map(&self.page_table);
        if let Some(data) = data {
            map_area.copy_data(&self.page_table, data, 0);
        }
        self.areas.push(map_area);
    }
    pub fn push_lazily(&mut self, map_area: MapArea) {
        self.areas.push(map_area);
    }

    /// Include sections in elf and trampoline and TrapContext and user stack,
    /// also returns user_sp_base and entry point.
    pub fn from_elf(elf_data: &[u8]) -> (Self, usize, usize, Vec<Aux>) {
        let mut memory_set = Self::new_bare();
        let mut auxv = Vec::new();
        // map program headers of elf, with U flag
        let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
        let elf_header = elf.header;
        let magic = elf_header.pt1.magic;
        assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");
        let ph_count = elf_header.pt2.ph_count();
        let mut entry_point = elf.header.pt2.entry_point() as usize;

        auxv.push(Aux::new(
            AuxType::PHENT,
            elf.header.pt2.ph_entry_size() as usize,
        )); // ELF64 header 64bytes
        auxv.push(Aux::new(AuxType::PHNUM, ph_count as usize));
        auxv.push(Aux::new(AuxType::PAGESZ, PAGE_SIZE as usize));
        // 设置动态链接
        if let Some(interp_entry_point) = memory_set.load_dl_interp_if_needed(&elf) {
            auxv.push(Aux::new(AuxType::BASE, DL_INTERP_OFFSET));
            entry_point = interp_entry_point;
        } else {
            auxv.push(Aux::new(AuxType::BASE, 0));
        }
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

        // Get ph_head addr for auxv
        let (max_end_vpn, head_va) = memory_set.map_elf(&elf, VirtAddr::from(0));
        auxv.push(Aux {
            aux_type: AuxType::PHDR,
            value: head_va.raw() + elf.header.pt2.ph_offset() as usize,
        });
        // map user stack with U flags
        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_heap_bottom: usize = max_end_va.into();

        // guard page
        user_heap_bottom += PAGE_SIZE;
        info!(
            "(MemorySetInner, from_elf) user heap bottom: {:#x}, {:#x}",
            user_heap_bottom, user_heap_bottom
        );
        let user_heap_top: usize = user_heap_bottom;
        memory_set.insert_framed_area(
            user_heap_bottom.into(),
            user_heap_top.into(),
            MapType::Framed,
            MapPermission::R | MapPermission::W | MapPermission::U,
            MapAreaType::Brk,
        );
        // 返回 address空间,用户栈顶,入口地址
        (memory_set, user_heap_bottom, entry_point, auxv)
    }
    fn map_elf(&mut self, elf: &ElfFile, offset: VirtAddr) -> (VirtAddr, VirtAddr) {
        let elf_header = elf.header;
        let ph_count = elf_header.pt2.ph_count();

        let mut max_end_vpn = offset.floor();
        let mut head_va = 0;
        let mut has_found_header_va = false;

        debug!("elf program header count: {}", ph_count);
        for i in 0..ph_count {
            let ph = elf.program_header(i).unwrap();
            if ph.get_type().unwrap() == xmas_elf::program::Type::Load {
                let start_va: VirtAddr = (ph.virtual_addr() as usize + offset.raw()).into();
                let end_va: VirtAddr =
                    ((ph.virtual_addr() + ph.mem_size()) as usize + offset.raw()).into();
                debug!("start_va {} end_va {}", start_va, end_va);
                if !has_found_header_va {
                    head_va = start_va.raw();
                    has_found_header_va = true;
                }
                let mut map_perm = MapPermission::U;
                let ph_flags = ph.flags();
                if ph_flags.is_read() {
                    map_perm |= MapPermission::R;
                }
                if ph_flags.is_write() {
                    map_perm |= MapPermission::W;
                }
                if ph_flags.is_execute() {
                    map_perm |= MapPermission::X;
                }
                info!(
                    "(MemorySetInner, map_elf) ph_flags: {:?}, map_perm: {:?}",
                    ph_flags, map_perm
                );
                let map_area = MapArea::new(
                    start_va,
                    end_va,
                    MapType::Framed,
                    map_perm,
                    MapAreaType::Elf,
                );
                let data_offset = start_va.raw() - start_va.floor().raw();
                max_end_vpn = map_area.vaddr_range.get_end();
                debug!("(map_elf) before page offset, max end vpn is : {}", max_end_vpn);
                // A optimization for mapping data, keep aligned
                self.push_with_offset(
                    map_area,
                    data_offset,
                    Some(&elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
                );
            }
        }
        (max_end_vpn, head_va.into())
    }
    /// Create a new address space by copy code&data from a exited process's address space.
    pub fn from_existed_user(user_space: &Arc<MemorySet>) -> MemorySet {
        let mut memory_set = Self::new_bare();
        // copy data sections/trap_context/user_stack
        for area in user_space.get_mut().areas.iter_mut() {
            if area.area_type == MapAreaType::Stack || area.area_type == MapAreaType::Trap {
                continue;
            }
            let mut new_area = MapArea::from_another(area);
            if area.area_type == MapAreaType::Mmap
                && !area.mmap_flags.contains(MmapFlags::MAP_SHARED)
            {
                GROUP_SHARE.lock().add_area(new_area.groupid);
            }
            if area.area_type == MapAreaType::Mmap || area.area_type == MapAreaType::Brk {
                //已经分配且独占/被写过的部分以及读共享部分按cow处理
                //其余是未分配部分，直接clone即可
                if area.mmap_flags.contains(MmapFlags::MAP_SHARED) {
                    let frames = area.data_frames.values().cloned().collect();
                    memory_set.push_with_given_frames(new_area, frames);
                    continue;
                }
                new_area.data_frames = area.data_frames.clone();
                for (vpn, _) in area.data_frames.iter() {
                    let vpn = *vpn;
                    let (src_ppn, mut pte_flags) =
                        user_space.get_mut().page_table.translate(vpn).unwrap();
                    //清空可写位，设置COW位
                    //下面两步不合起来是因为flags只有8位，全都用掉了
                    //所以Cow位没有放到flags里面
                    let need_cow = pte_flags.contains(MappingFlags::W)
                        || pte_flags.contains(MappingFlags::Cow);
                    pte_flags &= !MappingFlags::W;
                    if need_cow {
                        pte_flags |= MappingFlags::Cow;
                    }
                    user_space.get_mut().page_table.set_flags(vpn, pte_flags);
                    // 设置新的pagetable
                    memory_set
                        .page_table
                        .map_page(vpn, src_ppn, pte_flags, MappingSize::Page4KB);
                }
                memory_set.push_lazily(new_area);
                continue;
            }
            // let mut page_table = &mut user_space.page_table;
            // ELF是cow
            if area.area_type == MapAreaType::Elf {
                for vpn in area.vaddr_range {
                    let (src_ppn, flags) = user_space.get_mut().translate(vpn).unwrap();
                    let mut pte_flags = flags & !MappingFlags::W;
                    //清空可写位，设置COW位
                    //下面两步不合起来是因为flags只有8位，全都用掉了
                    //所以Cow位没有放到flags里面
                    pte_flags |= MappingFlags::Cow;
                    user_space.get_mut().page_table.set_flags(vpn, pte_flags);
                    // 设置新的pagetable
                    memory_set
                        .page_table
                        .map_page(vpn, src_ppn, pte_flags, MappingSize::Page4KB);
                }
                new_area.data_frames = area.data_frames.clone();
                memory_set.push_lazily(new_area);
                continue;
            }
            // 映射相同的Frame
            if area.area_type == MapAreaType::Shm {
                let frames = area.data_frames.values().cloned().collect();
                memory_set.push_with_given_frames(new_area, frames);
                continue;
            }

            //既不是cow也不是mmap还不是shm
            memory_set.push(new_area, None);

            // copy data from another space
            for vpn in area.vaddr_range {
                let src_ppn = user_space.translate(vpn).unwrap().0;
                let dst_ppn = memory_set.translate(vpn).unwrap().0;
                let dst =
                    unsafe { core::slice::from_raw_parts_mut(dst_ppn.raw() as *mut u8, PAGE_SIZE) };
                dst.copy_from_slice(unsafe {
                    core::slice::from_raw_parts(src_ppn.raw() as *const u8, PAGE_SIZE)
                });
            }
        }
        TLB::flush_all();
        MemorySet::new(memory_set)
    }
    /// Change page table by writing satp CSR Register.
    pub fn activate(&self) {
        self.page_table.change();
        TLB::flush_all();
    }
    /// Translate a virtual page number to a page table entry
    /// PageTableEntry 被拆解为 PhysAddr 和 MappingFlags
    fn translate(&self, vpn: VirtAddr) -> Option<(PhysAddr, MappingFlags)> {
        self.page_table
            .translate(vpn)
            .map(|(pa, flags)| (pa.into(), flags))
    }

    ///Remove all `MapArea`
    pub fn recycle_data_pages(&mut self) -> SyscallRet {
        // 先检测是否需要munmap
        for area in self.areas.iter_mut() {
            if area.area_type == MapAreaType::Mmap {
                if area.mmap_flags.contains(MmapFlags::MAP_SHARED)
                    && area.map_perm.contains(MapPermission::W)
                {
                    let addr: VirtAddr = area.vaddr_range.get_start().into();
                    let mapped_len: usize = area
                        .vaddr_range
                        .into_iter()
                        .filter(|vpn| area.data_frames.contains_key(&vpn))
                        .count();
                    let file = area.mmap_file.file.clone().unwrap();
                    let buffers = translated_byte_buffer(addr.raw() as *mut u8, mapped_len);
                    file.write(UserBuffer::new(vec![buffers]))?;
                }
            }
        }
        self.areas.clear();
        self.page_table.release(); // perhaps
        return Ok(0);
    }

    /// shrink the area to new_end
    /// Used in TaskUserRes, RV
    pub fn shrink_to(&mut self, start: VirtAddr, new_end: VirtAddr) -> bool {
        if let Some(area) = self
            .areas
            .iter_mut()
            .find(|area| area.vaddr_range.get_start() == start.floor())
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
            start,
            start.floor()
        );
        if let Some(area) = self
            .areas
            .iter_mut()
            .find(|area| area.vaddr_range.get_start() == start.floor())
        {
            //debug!("to append page table");
            area.append_to(&mut self.page_table, new_end.ceil());
            true
        } else {
            false
        }
    }
    pub fn lazy_page_fault(&mut self, vpn: VirtAddr, scause: TrapType) -> bool {
        let res = self.page_table.translate(vpn);
        //debug!("vpn={:#X},enter lazy", vpn.0);
        if res.is_some() && res.unwrap().1.contains(MappingFlags::P) {
            // pte.is_some() && pte.unwrap().is_valid()
            debug!("(lazy_page_fault) valid, to return");
            return false;
        }
        //println!("vpn={:#X},enter lazy2", vpn.0);
        //mmap
        if let Some(area) = self
            .areas
            .iter_mut()
            .filter(|area| area.area_type == MapAreaType::Mmap)
            .find(|area| {
                let (start, end) = area.vaddr_range.range();
                start <= vpn && vpn < end
            })
        {
            // println!("vpn={:#X},enter lazy3", vpn.0);
            debug!("to handle mmap");
            if matches!(scause, TrapType::LoadPageFault(_addr))
                || matches!(scause, TrapType::InstructionPageFault(_addr))
            {
                mmap_read_page_fault(vpn.into(), &mut self.page_table, area);
            } else {
                mmap_write_page_fault(vpn.into(), &mut self.page_table, area);
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
                let (start, end) = area.vaddr_range.range();
                start <= vpn && vpn < end
            })
        {
            //println!("vpn={:#X},enter lazy4", vpn.0);
            debug!("to handler stack or brk");
            lazy_page_fault(vpn.into(), &mut self.page_table, area);
            return true;
        }
        false
    }
    fn push_with_offset(&mut self, mut map_area: MapArea, offset: usize, data: Option<&[u8]>) {
        map_area.map(&mut self.page_table);
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data, offset);
        }
        self.areas.push(map_area);
    }
    fn load_dl_interp_if_needed(&mut self, elf: &ElfFile) -> Option<usize> {
        let elf_header = elf.header;
        let ph_count = elf_header.pt2.ph_count();

        let mut is_dl = false;
        for i in 0..ph_count {
            let ph = elf.program_header(i).unwrap();
            if ph.get_type().unwrap() == xmas_elf::program::Type::Interp {
                is_dl = true;
                break;
            }
        }

        if is_dl {
            debug!("[load_dl] encounter a dl elf");
            let section = elf.find_section_by_name(".interp").unwrap();
            let mut interp = String::from_utf8(section.raw_data(&elf).to_vec()).unwrap();
            interp = interp.strip_suffix("\0").unwrap_or(&interp).to_string();
            debug!("[load_dl] interp {}", interp);

            let interp = map_dynamic_link_file(&interp);

            // log::info!("interp {}", interp);

            let interp_inode = open(&interp, OpenFlags::O_RDONLY, NONE_MODE)
                .unwrap()
                .file()
                .ok();
            let interp_file = interp_inode.unwrap();
            let interp_elf_data = interp_file.inode.read_all().unwrap();
            let interp_elf = xmas_elf::ElfFile::new(&interp_elf_data).unwrap();
            self.map_elf(&interp_elf, DL_INTERP_OFFSET.into());

            Some(interp_elf.header.pt2.entry_point() as usize + DL_INTERP_OFFSET)
        } else {
            debug!("[load_dl] encounter a static elf");
            None
        }
    }
    fn push_with_given_frames(&mut self, mut map_area: MapArea, frames: Vec<Arc<FrameTracker>>) {
        map_area.map_given_frames(&mut self.page_table, frames);
        self.areas.push(map_area);
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
                let (l, r) = area.vaddr_range.range();
                if l <= start_vpn && end_vpn <= r {
                    !(l == start_vpn && r == end_vpn && map_perm == area.map_perm)
                } else {
                    false
                }
            });
            if need_split {
                self.mprotect(start_vpn, end_vpn, map_perm);
                for area in self.areas.iter_mut() {
                    let (start, end) = area.vaddr_range.range();
                    if start == start_vpn && end == end_vpn {
                        area.mmap_file.offset = off;
                        area.mmap_file.file = file.clone();
                    }
                }
            } else {
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
            }
            return addr;
        }
        // 自行选择地址,计算已经使用的MMap地址
        debug!("MMAP_TOP: {:#x}", MMAP_TOP);
        let addr = self.find_insert_addr(MMAP_TOP, len);
        debug!(
            "(MemorySetInner, mmap) start_va:{:#x},end_va:{:#x}",
            addr,
            addr + len
        );
        let area_type = if flags.contains(MmapFlags::MAP_STACK) {
            MapAreaType::Stack
        } else {
            MapAreaType::Mmap
        };
        //self.insert_framed_area(VirtAddr::from(addr), VirtAddr::from(addr + len), map_perm, area_type);
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
        addr
    }

    /// Unmap a memory area with the given start address and length.
    pub fn munmap(&mut self, addr: usize, len: usize) -> isize {
        debug!("in memory set, munmap");
        let start_vpn = VirtAddr::from(addr).floor();
        let end_vpn = VirtAddr::from(addr + len).floor();
        debug!("[MemorySet] start_vpn:{},end_vpn:{}", start_vpn, end_vpn);
        while let Some((idx, area)) = self
            .areas
            .iter_mut()
            .enumerate()
            .filter(|(_, area)| area.area_type == MapAreaType::Mmap)
            .find(|(_, area)| {
                let (start, end) = area.vaddr_range.range();
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
                    let mut wb_range: Vec<(VirtAddr, VirtAddr)> = Vec::new();
                    // debug!(
                    //     "when munmap {}, file {} has not been unlinked!",
                    //     idx,
                    //     file.inode.path()
                    // );
                    VAddrRange::new(start_vpn, end_vpn)
                        .into_iter()
                        .for_each(|vpn| {
                            if area.data_frames.contains_key(&vpn) {
                                if wb_range.is_empty() {
                                    wb_range.push((vpn, VirtAddr::from(vpn + 1)));
                                } else {
                                    let end_range = wb_range.pop().unwrap();
                                    if end_range.1 == vpn {
                                        wb_range.push((end_range.0, VirtAddr::from(vpn + 1)));
                                    } else {
                                        wb_range.push(end_range);
                                        wb_range.push((vpn, VirtAddr::from(vpn + 1)));
                                    }
                                }
                            }
                        });
                    // 每次写回前要设置偏移量
                    let off = file.lseek(0, SEEK_CUR).unwrap();
                    wb_range.into_iter().for_each(|(start_vpn, end_vpn)| {
                        let start_addr: usize = VirtAddr::from(start_vpn).into();
                        let mapped_len: usize = end_vpn.raw() - start_vpn.raw();
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
                        let buffers = translated_byte_buffer(start_addr as *mut u8, mapped_len);
                        let buf = UserBuffer::new(vec![buffers]);

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
                "[area vaddr_range] start:{},end:{}",
                area.vaddr_range.get_start(),
                area.vaddr_range.get_end()
            );
            //取消映射
            for vpn in VAddrRange::new(start_vpn, end_vpn) {
                area.unmap_one(&mut self.page_table, vpn);
            }
            let area_end_vpn = area.vaddr_range.get_end();
            // debug!(
            //     "[MemorySet] end_vpn:{:#x},area_end_vpn:{:#x}",
            //     end_vpn.0, area_end_vpn.0
            // );
            // 是否回收,mprotect可能将mmap区域拆分成多个
            if area_end_vpn <= end_vpn {
                self.areas.remove(idx);
            } else {
                area.vaddr_range = VAddrRange::new(end_vpn, area_end_vpn);
            }
            TLB::flush_all();
        }
        0
    }
    pub fn mprotect(&mut self, start_vpn: VirtAddr, end_vpn: VirtAddr, map_perm: MapPermission) {
        //因修改而新增的Area
        debug!(
            "(MemorySetInner, mprotect) start_vpn:{}, end_vpn:{}, map_perm:{:?}",
            start_vpn, end_vpn, map_perm
        );
        let mut new_areas = Vec::new();
        for area in self.areas.iter_mut() {
            let (start, end) = area.vaddr_range.range();
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
                new_area.vaddr_range = VAddrRange::new(start_vpn, end);
                area.vaddr_range = VAddrRange::new(start, start_vpn);
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
                new_area.vaddr_range = VAddrRange::new(start, end_vpn);
                area.vaddr_range = VAddrRange::new(end_vpn, end);
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
                front_area.vaddr_range = VAddrRange::new(start, start_vpn);
                back_area.vaddr_range = VAddrRange::new(end_vpn, end);
                area.vaddr_range = VAddrRange::new(start_vpn, end_vpn);
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
                self.page_table.set_flags(*vpn, area.map_perm.into());
            }
            self.areas.push(area);
        }
        TLB::flush_all();
    }
    /// 从高地址开始向下方低地址寻找一个 size 大小的空闲地址
    pub fn find_insert_addr(&self, hint: usize, size: usize) -> usize {
        info!(
            "(MemorySetInner, find_insert_addr) hint = {:#x}, size = {}",
            hint, size
        );
        let end_vpn = VirtAddr::from(hint).floor();
        let start_vpn = VirtAddr::from(hint - size).floor();
        // let start_va: VirtAddr = start_vpn.into();
        // info!(
        //     "(MemorySetInner, find_insert_addr) start_vpn = {:#x}, end_vpn = {:#x}, start_va = {:#x}",
        //     start_vpn.0, end_vpn.0, start_va.0
        // );
        for area in self.areas.iter() {
            let (start, end) = area.vaddr_range.range();
            if end_vpn > start && start_vpn < end {
                // 重叠部分的处理，至少一个共用页
                let new_hint = VirtAddr::from(start_vpn).raw() - PAGE_SIZE; // 页下移，再查找
                                                                            // info!(
                                                                            //     "find_insert_addr: hint = {:#x}, size = {}, new_hint = {:#x}",
                                                                            //     hint, size, new_hint
                                                                            // );
                return self.find_insert_addr(new_hint, size); // 递归查找
            }
        }
        VirtAddr::from(start_vpn).raw()
    }
    pub fn cow_page_fault(&mut self, vpn: VirtAddr, scause: TrapType) -> bool {
        debug!("in cow page fault");
        if matches!(scause, TrapType::LoadPageFault(_addr))
            || matches!(scause, TrapType::InstructionPageFault(_addr))
        {
            // 只处理写时拷贝的情况
            // 如果是读时拷贝，直接返回false
            return false;
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
                let (start, end) = area.vaddr_range.range();
                start <= vpn && vpn < end
            })
        {
            debug!("find cow");
            if area.area_type == MapAreaType::Elf {
                debug!("elf");
            }
            if area.area_type == MapAreaType::Brk {
                debug!("brk");
            }
            if area.area_type == MapAreaType::Mmap {
                debug!("mmap");
            }
            if let Some((_paddr, flags)) = self.page_table.translate(vpn) {
                if flags.contains(MappingFlags::Cow) {
                    debug!("is cow,to deal");
                    cow_page_fault(vpn.into(), &mut self.page_table, area);
                }
                return true;
            }
        }
        false
    }
    /// 惰性插入一段映射段
    pub fn lazy_insert_framed_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_perm: MapPermission,
        area_type: MapAreaType,
    ) {
        self.push_lazily(MapArea::new(
            start_va,
            end_va,
            MapType::Framed,
            map_perm,
            area_type,
        ));
    }
    /// 找到一段可以插入的地址，惰性插入映射，返回虚拟起始和结束地址
    pub fn lazy_insert_framed_area_with_hint(
        &mut self,
        hint: usize,
        size: usize,
        map_perm: MapPermission,
        area_type: MapAreaType,
    ) -> (usize, usize) {
        let start_va = self.find_insert_addr(hint, size);
        let end_va = start_va + size;
        self.lazy_insert_framed_area(
            VirtAddr::from(start_va),
            VirtAddr::from(end_va),
            map_perm,
            area_type,
        );
        (start_va, end_va)
    }
    pub fn clone_area(&mut self, start_vpn: VirtAddr, another: &MemorySetInner) {
        let origin_page_table = self.token();
        let another_page_table = another.token();
        if let Some(area) = another
            .areas
            .iter()
            .find(|area| area.vaddr_range.get_start() == start_vpn)
        {
            for vpn in area.vaddr_range {
                let (src_paddr, _src_flags, dst_paddr, _dst_flags);
                let another_res = another_page_table.translate(vpn);
                (src_paddr, _src_flags) = another_res.unwrap();
                let origin_res = origin_page_table.translate(vpn);
                (dst_paddr, _dst_flags) = origin_res.unwrap();
                let src_paddr: *const u8 = src_paddr.get_ptr::<u8>();
                let dst_paddr: *mut u8 = dst_paddr.get_mut_ptr::<u8>();
                let dst_array = unsafe { core::slice::from_raw_parts_mut(dst_paddr, PAGE_SIZE) };
                dst_array
                    .copy_from_slice(unsafe { core::slice::from_raw_parts(src_paddr, PAGE_SIZE) });
                // let src_ppn = another.translate(vpn).unwrap().ppn();
                // let dst_ppn = self.translate(vpn).unwrap().ppn();
                // dst_ppn
                //     .bytes_array_mut()
                //     .copy_from_slice(src_ppn.bytes_array());
            }
        }
    }
    pub fn lazy_clone_area(&mut self, start_vpn: VirtAddr, another: &MemorySetInner) {
        let origin_page_table = self.token();
        let another_page_table = another.token();

        let another_area = if let Some(area) = another
            .areas
            .iter()
            .find(|area| area.vaddr_range.get_start() == start_vpn)
        {
            area
        } else {
            return;
        };
        let this_area = if let Some(area) = self
            .areas
            .iter_mut()
            .find(|area| area.vaddr_range.get_start() == start_vpn)
        {
            area
        } else {
            return;
        };

        for vpn in another_area.vaddr_range {
            let (src_paddr, _src_flags, dst_paddr, _dst_flags);
            let another_res = another_page_table.translate(vpn);
            if another_res.is_none() || !another_res.unwrap().1.contains(MappingFlags::P) {
                continue;
            }
            (src_paddr, _src_flags) = another_res.unwrap();

            let origin_res = origin_page_table.translate(vpn);
            if origin_res.is_none() || !origin_res.unwrap().1.contains(MappingFlags::P) {
                this_area.map_one(&origin_page_table, vpn);
            }
            (dst_paddr, _dst_flags) = origin_res.unwrap();

            debug!(
                "copying page: {}, src_paddr: {}, dst_paddr: {}",
                vpn, src_paddr, dst_paddr
            );
            // dst_ppn
            //   .bytes_array_mut()
            //   .copy_from_slice(src_ppn.bytes_array());
            let src_paddr: *const u8 = src_paddr.get_ptr::<u8>();
            let dst_paddr: *mut u8 = dst_paddr.get_mut_ptr::<u8>();
            let dst_array = unsafe { core::slice::from_raw_parts_mut(dst_paddr, PAGE_SIZE) };
            dst_array.copy_from_slice(unsafe { core::slice::from_raw_parts(src_paddr, PAGE_SIZE) });
        }
    }
    pub fn shm(
        &mut self,
        addr: usize,
        size: usize,
        map_perm: MapPermission,
        pages: Vec<Arc<FrameTracker>>,
    ) -> usize {
        if addr == 0 {
            let vaddr = self.find_insert_addr(MMAP_TOP, size);
            self.push_with_given_frames(
                MapArea::new(
                    VirtAddr::from(vaddr),
                    VirtAddr::from(vaddr + size),
                    MapType::Framed,
                    map_perm,
                    MapAreaType::Shm,
                ),
                pages,
            );
            return vaddr;
        }
        panic!("[shm_attach] unimplement attach addr");
    }
}
