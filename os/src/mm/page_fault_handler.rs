use crate::config::PAGE_SIZE_BITS;
use alloc::sync::Arc;
use alloc::vec;
use core::arch::asm;
use polyhal::pagetable::TLB;
use polyhal::{MappingFlags, MappingSize, PageTable, PageTableWrapper, PhysAddr, VirtAddr};

use crate::mm::map_area::CowTrait;
use crate::mm::MapPermission;
use crate::{
    config::PAGE_SIZE,
    fs::{vfs::File, SEEK_CUR, SEEK_SET},
    mm::{group::GROUP_SHARE, map_area::MapArea, translated_byte_buffer, UserBuffer},
};

///堆触发的lazy alocation，必是写
pub fn lazy_page_fault(va: VirtAddr, page_table: &Arc<PageTableWrapper>, vma: &mut MapArea) {
    // 仅映射页面
    vma.map_one(page_table, va.floor());
    TLB::flush_all();
}

///mmap读触发的lazy alocation，查看是否有共享页可直接用，没有再直接分配
pub fn mmap_read_page_fault(va: VirtAddr, page_table: &Arc<PageTableWrapper>, vma: &mut MapArea) {
    let frame = GROUP_SHARE.lock().find(vma.groupid, va.floor());
    if let Some(frame) = frame {
        //有现成的，直接clone,需要是cow的
        let vpn = va.floor();
        let mut pte_flags = vma.flags() | MapPermission::V;
        //可写的才需要cow
        let need_cow = pte_flags.contains(MapPermission::W);
        pte_flags &= !MapPermission::W;
        let paddr = frame.paddr;
        //page_table.set_flags(vpn, pte_flags);
        vma.data_frames.insert(vpn, frame);
        let mut flags: MappingFlags = pte_flags.into();
        if need_cow {
            flags.set_cow();
        }
        page_table.map_page(vpn, paddr, flags, MappingSize::Page4KB);

        TLB::flush_all();
    } else {
        //第一次读，分配页面
        mmap_write_page_fault(va, page_table, vma);
        let vpn = va.floor();
        if vma.groupid != 0 {
            GROUP_SHARE.lock().add_frame(
                vma.groupid,
                vpn,
                vma.data_frames.get(&vpn).unwrap().clone(),
            )
        }
    }
}

///mmap写触发的lazy alocation，直接新分配帧
pub fn mmap_write_page_fault(va: VirtAddr, page_table: &Arc<PageTableWrapper>, vma: &mut MapArea) {
    // 映射页面,拷贝数据
    vma.map_one(page_table, va.floor());
    if vma.mmap_file.file.is_none() {
        TLB::flush_all();
        return;
    }
    let file = vma.mmap_file.file.clone().unwrap();
    let old_offset = file.lseek(0, SEEK_CUR).unwrap();
    let start_addr: VirtAddr = vma.vaddr_range.get_start();
    let va: usize = va.raw();

    /*
    debug!(
        "va={:x},start_addr={:x},vma.offset={:x}",
        va, start_addr.0, vma.mmap_file.offset
    );
    */

    file.lseek(
        (va - start_addr.raw() + vma.mmap_file.offset) as isize,
        SEEK_SET,
    )
    .expect("mmap_write_page_fault should not fail");
    file.read(UserBuffer {
        buffers: vec![translated_byte_buffer(va as *mut u8, PAGE_SIZE)],
    })
    .expect("mmap_write_page_fault should not fail");
    file.lseek(old_offset as isize, SEEK_SET)
        .expect("mmap_write_page_fault should not fail");
    //设置为cow
    let vpn = VirtAddr::from(va).floor();
    let mut pte_flags = vma.flags() | MapPermission::V;
    //可写的才需要cow
    let need_cow = pte_flags.contains(MapPermission::W);
    pte_flags &= !MapPermission::W;
    let mut flags: MappingFlags = pte_flags.into();
    if need_cow {
        flags.set_cow();
    }
    page_table.set_flags(vpn, flags);
    TLB::flush_all();
}

///copy on write
pub fn cow_page_fault(va: VirtAddr, page_table: &Arc<PageTableWrapper>, vma: &mut MapArea) {
    // 只有一个，不用复制
    let vpn = va.floor();
    let frame = vma.data_frames.get(&vpn).unwrap();
    // debug!("handle va {:#x}, count={}", va.0, Arc::strong_count(frame));
    if Arc::strong_count(frame) == 1 {
        let (_paddr, mut flags) = page_table.translate(vpn).unwrap();
        if flags.contains(MappingFlags::Cow) {
            // page_table.reset_cow(vpn);
            flags &= !MappingFlags::Cow;
        }
        if flags.contains(MappingFlags::W) {
            // page_table.set_w(vpn);
            flags &= MappingFlags::W;
        }
        page_table.set_flags(vpn, flags);
        TLB::flush_all();
        return;
    }

    //旧物理页的内容复制到新物理页
    let src_ptr = &mut page_table.translate(vpn).unwrap().0.raw();
    let src = unsafe { core::slice::from_raw_parts_mut(src_ptr as *mut usize, PAGE_SIZE) };
    vma.unmap_one(page_table, vpn);
    vma.map_one(page_table, vpn);
    let dst_ptr = &mut page_table.translate(vpn).unwrap().0.raw();
    let dst = unsafe { core::slice::from_raw_parts_mut(dst_ptr as *mut usize, PAGE_SIZE) };
    dst.copy_from_slice(src);

    let (_paddr, mut flags) = page_table.translate(vpn).unwrap();
    if flags.contains(MappingFlags::Cow) {
        // page_table.reset_cow(vpn);
        flags &= !MappingFlags::Cow;
    }
    if !flags.contains(MappingFlags::W) {
        // page_table.set_w(vpn);
        flags &= MappingFlags::W;
    }
    page_table.set_flags(vpn, flags);
    TLB::flush_all();
}
