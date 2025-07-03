#[cfg(target_arch = "loongarch64")]
use core::iter::Map;

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
            "MapArea::new start floor = {}, end ceil = {}",
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
        // only Framed type in LA64
        let ppn: PhysPageNum;
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
        // #[cfg(target_arch = "loongarch64")]
        // {
        //     let frame = frame_alloc().unwrap();
        //     ppn = frame.ppn;
        //     self.data_frames.insert(vpn, Arc::new(frame)); //虚拟页号与物理页帧的对应关系
        // }
        let pte_flags = PTEFlags::from_bits(self.map_perm.bits).unwrap();
        //debug!("in map area, map one, to page table map");
        page_table.map(vpn, ppn, pte_flags);
    }
    pub fn unmap_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        if self.map_type == MapType::Framed {
            self.data_frames.remove(&vpn);
        }
        // #[cfg(target_arch = "loongarch64")]
        // {
        //     self.data_frames.remove(&vpn);
        // }
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
    pub fn flags(&self) -> PTEFlags {
        PTEFlags::from_bits(self.map_perm.bits).unwrap()
    }
    pub fn new_mmap(
        start_va: VirtAddr,
        end_va: VirtAddr,
        #[cfg(target_arch = "riscv64")] map_type: MapType,
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

///  PTEFlags 的一个子集
/// 主要含有几个读写标志位和存在位，对于其它控制位
/// 在后面的映射中将会固定为同一种
/// 特权等级（PLV），2 比特。该页表项对应的特权等级。
/// 当 RPLV=0 时，该页表项可以被任何特权等级不低于 PLV 的程序访问；
/// 当 RPLV=1 时，该页表项仅可以被特权等级等于 PLV 的程序访问
/// 受限特权等级使能（RPLV），1 比特。页表项是否仅被对应特权等级的程序访问的控制位。
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

impl MapPermission {
    pub fn rwu() -> Self {
        #[cfg(target_arch = "riscv64")]
        return MapPermission::R
            | MapPermission::W
            | MapPermission::U;  
        #[cfg(target_arch = "loongarch64")]
        return MapPermission::W | MapPermission::PLVL | MapPermission::PLVH;
    }
    pub fn rw() -> Self {
        #[cfg(target_arch = "riscv64")]
        return MapPermission::R | MapPermission::W;
        #[cfg(target_arch = "loongarch64")]
        return MapPermission::W;
    }
    pub fn ru() -> Self {
        #[cfg(target_arch = "riscv64")]
        return MapPermission::R | MapPermission::U;
        #[cfg(target_arch = "loongarch64")]
        return MapPermission::PLVL | MapPermission::PLVH; // as PLV3, user mode
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

// RV passed, compatible with LA
impl MapPermission {
    /// Convert from port to MapPermission
    pub fn from_port(port: usize) -> Self {
        #[cfg(target_arch = "riscv64")]
        let bits = (port as u8) << 1;
        #[cfg(target_arch = "loongarch64")]
        let bits = port << 1;
        MapPermission::from_bits(bits).unwrap()
    }

    /// Add user permission for MapPermission
    /// LA, 保留现有权限，添加用户模式所需的 PLV3 组合位
    pub fn with_user(self) -> Self {
        #[cfg(target_arch = "riscv64")]
        return self | MapPermission::U;
        #[cfg(target_arch = "loongarch64")]
        return self | MapPermission::PLVL | MapPermission::PLVH;
    }
}
