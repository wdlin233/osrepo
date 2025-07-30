use crate::{
    config::PAGE_SIZE,
    fs::OSInode,
    mm::{
        address::StepByOne, frame_alloc, group::GROUP_SHARE, FrameTracker, PTEFlags, PageTable,
        PhysAddr, PhysPageNum, VPNRange, VirtAddr, VirtPageNum,
    },
    syscall::MmapFlags,
};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[derive(Clone)]
pub struct MapArea {
    pub vpn_range: VPNRange,
    pub data_frames: BTreeMap<VirtPageNum, Arc<FrameTracker>>,
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
        let start_vpn: VirtPageNum = start_va.floor();
        let end_vpn: VirtPageNum = end_va.ceil();
        debug!(
            "MapArea::new start floor = {:#x}, end ceil = {:#x}",
            start_va.floor().0,
            end_va.ceil().0
        );
        Self {
            vpn_range: VPNRange::new(start_vpn, end_vpn),
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
            vpn_range: VPNRange::new(another.vpn_range.get_start(), another.vpn_range.get_end()),
            data_frames: BTreeMap::new(),
            map_type: another.map_type,
            map_perm: another.map_perm,
            area_type: another.area_type,
            mmap_file: another.mmap_file.clone(),
            mmap_flags: another.mmap_flags,
            groupid: another.groupid,
        }
    }
    pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        let ppn: PhysPageNum;
        match self.map_type {
            MapType::Identical => {
                ppn = PhysPageNum(vpn.0);
            }
            MapType::Framed => {
                //debug!("in map one, to alloc frame");
                let frame = frame_alloc().unwrap();
                ppn = frame.ppn;
                self.data_frames.insert(vpn, Arc::new(frame));
            }
        }
        let pte_flags = self.map_perm.clone();
        let cow = if self.map_perm.contains(MapPermission::W) || self.area_type == MapAreaType::Elf
        {
            true
        } else {
            false
        };
        page_table.map(vpn, ppn, pte_flags, cow);
    }
    pub fn unmap_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        if self.map_type == MapType::Framed {
            self.data_frames.remove(&vpn);
        }
        page_table.unmap(vpn);
    }
    pub fn map(&mut self, page_table: &mut PageTable) {
        debug!("(MapArea, map) mapping area");
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
        debug!("in map area, append to, the new end is : {}", new_end.0);
        debug!(
            "in map area, append to, the start is : {}",
            self.vpn_range.get_start().0
        );
        for vpn in VPNRange::new(self.vpn_range.get_end(), new_end) {
            self.map_one(page_table, vpn)
        }
        self.vpn_range = VPNRange::new(self.vpn_range.get_start(), new_end);
    }
    /// data: start-aligned but maybe with shorter length
    /// assume that all frames were cleared before
    pub fn copy_data(&mut self, page_table: &mut PageTable, data: &[u8]) {
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
    pub fn flags(&self) -> MapPermission {
        self.map_perm.clone()
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
            "MapArea::new_mmap: {:#x} - {:#x}, offset: {}, flags: {:?}",
            start_va.0, end_va.0, offset, mmap_flags
        );
        let start_vpn: VirtPageNum = start_va.floor();
        let end_vpn: VirtPageNum = end_va.ceil();
        let groupid;
        if mmap_flags.contains(MmapFlags::MAP_SHARED) {
            groupid = 0;
        } else {
            groupid = GROUP_SHARE.lock().alloc_id();
            GROUP_SHARE.lock().add_area(groupid);
        }
        //info!("start_vpn: {:x}", start_vpn.0);
        Self {
            vpn_range: VPNRange::new(start_vpn, end_vpn),
            data_frames: BTreeMap::new(),
            map_type: map_type,
            map_perm: map_perm,
            area_type: area_type,
            mmap_file: MmapFile::new(file, offset),
            mmap_flags: mmap_flags,
            groupid: groupid,
        }
    }

    pub fn map_given_frames(&mut self, page_table: &mut PageTable, frames: Vec<Arc<FrameTracker>>) {
        for (vpn, frame) in self.vpn_range.clone().into_iter().zip(frames.into_iter()) {
            let pte_flags = self.map_perm.clone();
            page_table.map(vpn, frame.ppn, pte_flags, false);
            self.data_frames.insert(vpn, frame);
        }
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
/// map type for memory set: identical or framed
pub enum MapType {
    Identical,
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

impl Default for MapPermission {
    fn default() -> Self {
        return MapPermission::R | MapPermission::U;
    }
}

impl From<MapPermission> for PTEFlags {
    fn from(perm: MapPermission) -> Self {
        #[cfg(target_arch = "riscv64")]
        if perm.is_empty() {
            return PTEFlags::empty();
        } else {
            let mut res = PTEFlags::V;
            if perm.contains(MapPermission::R) {
                res |= PTEFlags::R | PTEFlags::A;
            }
            if perm.contains(MapPermission::W) {
                res |= PTEFlags::W | PTEFlags::D;
            }
            if perm.contains(MapPermission::X) {
                res |= PTEFlags::X;
            }
            if perm.contains(MapPermission::U) {
                res |= PTEFlags::U;
            }
            return res;
        }
        #[cfg(target_arch = "loongarch64")]
        if perm.is_empty() {
            return PTEFlags::empty();
        } else {
            let mut res = PTEFlags::V | PTEFlags::MATL | PTEFlags::P;
            if !perm.contains(MapPermission::R) {
                res |= PTEFlags::NR;
            }
            if perm.contains(MapPermission::W) {
                res |= PTEFlags::W | PTEFlags::D;
            }
            if !perm.contains(MapPermission::X) {
                res |= PTEFlags::NX;
            }
            if perm.contains(MapPermission::U) {
                res |= PTEFlags::PLVL | PTEFlags::PLVH; // as PLV3, user mode
            }
            return res;
        }
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
