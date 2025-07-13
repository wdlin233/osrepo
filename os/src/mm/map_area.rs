use crate::{
    config::PAGE_SIZE,
    fs::OSInode,
    mm::{
        addr_range::VAddrRange, address::StepByOne, frame_alloc, group::GROUP_SHARE,
    },
    syscall::MmapFlags,
};
use alloc::{collections::BTreeMap, vec::Vec};
use alloc::sync::Arc;
use polyhal::{MappingFlags, MappingSize, PageTableWrapper, VirtAddr};
 use crate::mm::frame_allocator::FrameTracker;

#[derive(Clone)]
pub struct MapArea {
    pub vaddr_range: VAddrRange,
    pub data_frames: BTreeMap<VirtAddr, Arc<FrameTracker>>,
    pub map_type: MapType,
    pub map_perm: MapPermission,
    pub area_type: MapAreaType,
    pub mmap_file: MmapFile,
    pub mmap_flags: MmapFlags,
    pub groupid: usize,
}

impl Drop for MapArea {
    fn drop(&mut self) {
        GROUP_SHARE.lock().del_area(self.groupid);
    }
}

impl MapArea {
    pub fn new(
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_type: MapType,
        map_perm: MapPermission,
        area_type: MapAreaType,
    ) -> Self {
        //info!("MapArea::new: {:#x} - {:#x}", start_va.0, end_va.0);
        let start_vpn: VirtAddr = start_va.floor();
        let end_vpn: VirtAddr = end_va.ceil();
        debug!(
            "MapArea::new(as virtaddr, aligned) start floor = {}, end ceil = {}",
            start_vpn,
            end_vpn
        );
        Self {
            vaddr_range: VAddrRange::new(start_vpn, end_vpn),
            data_frames: BTreeMap::new(),
            map_type,
            map_perm,
            area_type,
            mmap_file: MmapFile::empty(),
            mmap_flags: MmapFlags::empty(),
            groupid: 0,
        }
    }
    pub fn from_another(another: &Self) -> Self {
        Self {
            vaddr_range: VAddrRange::new(another.vaddr_range.get_start(), another.vaddr_range.get_end()),
            data_frames: BTreeMap::new(),
            map_type: another.map_type,
            map_perm: another.map_perm,
            area_type: another.area_type,
            mmap_file: another.mmap_file.clone(),
            mmap_flags: another.mmap_flags,
            groupid: another.groupid,
        }
    }
    pub fn map_one(&mut self, page_table: &Arc<PageTableWrapper>, vaddr: VirtAddr) {
        let p_tracker = frame_alloc().expect("cant allocate frame");
        page_table.map_page(
            vaddr, // aligned
            p_tracker.paddr,
            self.map_perm.into(),
            MappingSize::Page4KB,
        );
        self.data_frames.insert(vaddr, p_tracker);
    }
    pub fn unmap_one(&mut self, page_table: &Arc<PageTableWrapper>, vaddr: VirtAddr) {
        self.data_frames.remove(&vaddr);
        page_table.unmap_page(vaddr);
    }
    pub fn map(&mut self, page_table: &Arc<PageTableWrapper>) {
        for vaddr in self.vaddr_range {
            self.map_one(page_table, vaddr);
        }
    }
    pub fn unmap(&mut self, page_table: &Arc<PageTableWrapper>) {
        for vaddr in self.vaddr_range {
            self.unmap_one(page_table, vaddr);
        }
    }
    /// Used in RV64
    pub fn shrink_to(&mut self, page_table: &Arc<PageTableWrapper>, new_end: VirtAddr) {
        for vpn in VAddrRange::new(new_end, self.vaddr_range.get_end()) {
            self.unmap_one(page_table, vpn)
        }
        self.vaddr_range = VAddrRange::new(self.vaddr_range.get_start(), new_end);
    }
    /// Used in RV64
    pub fn append_to(&mut self, page_table: &Arc<PageTableWrapper>, new_end: VirtAddr) {
        debug!(
            "(MapArea, append_to) the start is : {} and the new end is : {}",
            self.vaddr_range.get_start(),
            new_end
        );
        for vpn in VAddrRange::new(self.vaddr_range.get_end(), new_end) {
            self.map_one(page_table, vpn)
        }
        self.vaddr_range = VAddrRange::new(self.vaddr_range.get_start(), new_end);
    }
    /// data: start-aligned but maybe with shorter length
    /// assume that all frames were cleared before
    pub fn copy_data(&mut self, page_table: &Arc<PageTableWrapper>, data: &[u8], offset: usize) {
        assert_eq!(self.map_type, MapType::Framed);
        let mut start: usize = 0;
        let mut page_offset = offset;
        let mut current_vpn = self.vaddr_range.get_start();
        let len = data.len();
        loop {
            let src = &data[start..len.min(start + PAGE_SIZE - page_offset)];
            let dst = &mut page_table
                .translate(current_vpn)
                .unwrap()
                .0
                .slice_mut_with_len(src.len());
            dst.copy_from_slice(src);
            start += PAGE_SIZE - page_offset;
            page_offset = 0;
            if start >= len {
                break;
            }
            current_vpn = current_vpn + PAGE_SIZE; // aka step()
        }
    }
    pub fn new_mmap(
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_type: MapType,
        map_perm: MapPermission,
        area_type: MapAreaType,
        file: Option<Arc<OSInode>>,
        offset: usize,
        mmap_flags: MmapFlags,
    ) -> Self {
        debug!(
            "MapArea::new_mmap: {} - {}, offset: {}, flags: {:?}",
            start_va, end_va, offset, mmap_flags
        );
        let start_vpn: VirtAddr = start_va.floor();
        let end_vpn: VirtAddr = end_va.ceil();
        let groupid;
        if mmap_flags.contains(MmapFlags::MAP_SHARED) {
            groupid = 0;
        } else {
            groupid = GROUP_SHARE.lock().alloc_id();
            GROUP_SHARE.lock().add_area(groupid);
        }
        //info!("start_vpn: {:x}", start_vpn.0);
        Self {
            vaddr_range: VAddrRange::new(start_vpn, end_vpn),
            data_frames: BTreeMap::new(),
            map_type: map_type,
            map_perm: map_perm,
            area_type: area_type,
            mmap_file: MmapFile::new(file, offset),
            mmap_flags: mmap_flags,
            groupid: groupid,
        }
    }
    pub fn map_given_frames(&mut self, page_table: &mut Arc<PageTableWrapper>, frames: Vec<Arc<FrameTracker>>) {
        for (vpn, frame) in self.vaddr_range.clone().into_iter().zip(frames.into_iter()) {
            page_table.map_page(vpn, frame.paddr, self.map_perm.into(), MappingSize::Page4KB);
            self.data_frames.insert(vpn, frame);
        }
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
/// map type for memory set: identical or framed
pub enum MapType {
    Identical, // not used now
    Framed,
}

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

impl Into<MappingFlags> for MapPermission {
    fn into(self) -> MappingFlags {
        let mut flags = MappingFlags::empty();
        if self.contains(MapPermission::R) {
            flags |= MappingFlags::R;
        }
        if self.contains(MapPermission::W) {
            flags |= MappingFlags::W;
        }
        if self.contains(MapPermission::X) {
            flags |= MappingFlags::X;
        }
        if self.contains(MapPermission::U) {
            flags |= MappingFlags::U;
        }
        flags
    }
}   

/// Map area type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapAreaType {
    /// Segments from elf file, e.g. text, rodata, data, bss
    Elf,
    /// Stack
    Stack,
    /// Brk
    Brk,
    /// Mmap
    Mmap,
    /// For Trap Context
    Trap,
    /// Shared memory
    Shm,
    /// Physical frames(for kernel)
    Physical,
    /// MMIO(for kernel)
    MMIO,
}

#[derive(Clone)]
pub struct MmapFile {
    pub file: Option<Arc<OSInode>>,
    pub offset: usize,
}

impl MmapFile {
    pub fn empty() -> Self {
        Self {
            file: None,
            offset: 0,
        }
    }

    pub fn new(file: Option<Arc<OSInode>>, offset: usize) -> Self {
        Self { file, offset }
    }
}
