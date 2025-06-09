// rcore-hal-component/887b4c
use core::ptr::NonNull;

use super::BlockDevice;
//use super::BlockDevice;
use crate::drivers::block::BLOCK_SZ;
use crate::mm::{
    frame_alloc, frame_dealloc, kernel_token, FrameTracker, PageTable, PhysAddr, PhysPageNum,
    StepByOne, VirtAddr, frame_alloc_contiguous, KERNEL_SPACE,
};
use crate::sync::UPSafeCell;
use alloc::vec::Vec;
use lazy_static::*;
use virtio_drivers::{BufferDirection, Hal};
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};

#[allow(unused)]
const VIRTIO0: usize = 0x10001000;
/// VirtIOBlock device driver strcuture for virtio_blk device
pub struct VirtIOBlock(UPSafeCell<VirtIOBlk<VirtioHal, MmioTransport>>);

lazy_static! {
    /// The global io data queue for virtio_blk device
    static ref QUEUE_FRAMES: UPSafeCell<Vec<FrameTracker>> = unsafe { UPSafeCell::new(Vec::new()) };
}

unsafe impl Send for VirtIOBlock {}
unsafe impl Sync for VirtIOBlock {}

/// Interfaces BlockDevices
use core::any::Any;

// impl BlockDevice for VirtIOBlock {
//     /// Read a block from the virtio_blk device
//     fn read_blocks(&self, block_id: usize, buf: &mut [u8]) {
//         //assert!(buf.len() == 512, "read_block: buf size must be 512, got {}", buf.len());
//         //info!("Reading block {} from VirtIOBlk", block_id);
//         let result = self.0.exclusive_access().read_blocks(block_id, buf);
//         if let Err(e) = &result {
//             error!("VirtIOBlk read_blocks failed: {:?}, block_id={}, capacity={}", e, block_id, self.0.exclusive_access().capacity());
//         }
//         result.expect("Error when reading VirtIOBlk");
//     }
//     ///
//     fn write_blocks(&self, block_id: usize, buf: &[u8]) {
//         self.0
//             .exclusive_access()
//             .write_blocks(block_id, buf)
//             .expect("Error when writing VirtIOBlk");
//     }
// }

impl ext4_rs::BlockDevice for VirtIOBlock {
    fn read_offset(&self, offset: usize) -> Vec<u8> {
        // debug!("read_offset: offset = {:#x}", offset);
        let mut buf = [0u8; 4096];
        self.0
            .exclusive_access()
            .read_blocks(offset / BLOCK_SZ, &mut buf)
            .expect("Error when reading VirtIOBlk");
        // debug!("read_offset = {:#x}, buf = {:x?}", offset, buf);
        buf[offset % BLOCK_SZ..].to_vec()
    }
    fn write_offset(&self, offset: usize, data: &[u8]) {
        debug!("write_offset: offset = {:#x}", offset);
        //     debug!("data len = {:#x}", data.len());
        let mut write_size = 0;
        while write_size < data.len() {
            let block_id = (offset + write_size) / BLOCK_SZ;
            let block_offset = (offset + write_size) % BLOCK_SZ;
            let mut buf = [0u8; BLOCK_SZ];
            let copy_size = core::cmp::min(data.len() - write_size, BLOCK_SZ - block_offset);
            self.0
                .exclusive_access()
                .read_blocks(block_id, &mut buf)
                .expect("Error when reading VirtIOBlk");
            buf[block_offset..block_offset + copy_size]
                .copy_from_slice(&data[write_size..write_size + copy_size]);
            self.0
                .exclusive_access()
                .write_blocks(block_id, &buf)
                .expect("Error when writing VirtIOBlk");
            write_size += copy_size;
        }
    }
}

impl VirtIOBlock {
    #[allow(unused)]
    /// Create a new VirtIOBlock driver with VIRTIO0 base_addr for virtio_blk device
    pub fn new() -> Self {
        unsafe {
            let header = &mut *(VIRTIO0 as *mut VirtIOHeader);
            Self(UPSafeCell::new(
                VirtIOBlk::<VirtioHal, MmioTransport>::new(
                    MmioTransport::new(header.into()).unwrap(),
                )
                .expect("this is not a valid virtio device"),
            ))
        }
    }
}

pub struct VirtioHal;

unsafe impl Hal for VirtioHal {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (virtio_drivers::PhysAddr, NonNull<u8>) {
        //debug!("allocating {} pages for virtio_blk", pages);
        let mut ppn_base = PhysPageNum(0);
        for i in 0..pages {
            let frame = frame_alloc().unwrap();
            //debug!("alloc paddr: {:?}", frame);
            if i == 0 {
                ppn_base = frame.ppn;
            }
            assert_eq!(frame.ppn.0, ppn_base.0 + i);
            QUEUE_FRAMES.exclusive_access().push(frame);
        }
        let pa: PhysAddr = ppn_base.into();
        debug!("allocated paddr: {:?}", pa);
        unsafe {
            (pa.0, NonNull::new_unchecked((pa.0 | 0x80200000) as *mut u8))
        }

        // let (_frmaes, root_ppn) = frame_alloc_contiguous(pages);
        // let pa: PhysAddr = root_ppn.into();
        // unsafe {
        //     (pa.0, NonNull::new_unchecked((pa.0 | 0x80200000) as *mut u8))
        // }
    }

    unsafe fn dma_dealloc(paddr: virtio_drivers::PhysAddr, _vaddr: NonNull<u8>, pages: usize) -> i32 {
        info!("deallocating {} pages for virtio_blk", pages);
        let pa = PhysAddr::from(paddr);
        let mut ppn_base: PhysPageNum = pa.into();
        for _ in 0..pages {
            frame_dealloc(ppn_base);
            // ?or use step()
            ppn_base.0 += 1;
        }
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: usize, _size: usize) -> NonNull<u8> {
        info!("translating paddr {:#x} to virt", paddr);  
        NonNull::new_unchecked((PhysAddr::from(paddr).0 | 0x80200000) as *mut u8)
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: virtio_drivers::BufferDirection) -> virtio_drivers::PhysAddr {
        //info!("Executing share for virtio_blk");
        KERNEL_SPACE
            .exclusive_access()
            .page_table
            .translate_va(VirtAddr::from(buffer.as_ptr() as *const usize as usize))
            .unwrap()
            .0
    }

    unsafe fn unshare(_paddr: virtio_drivers::PhysAddr, _buffer: NonNull<[u8]>, _direction: virtio_drivers::BufferDirection) {
        // Nothing to do, as the host already has access to all memory and we didn't copy the buffer
        // anywhere else.
    }
}