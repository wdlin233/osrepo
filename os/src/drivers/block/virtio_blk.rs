//use super::BlockDevice;
use crate::drivers::block::BLOCK_SZ;
use crate::mm::{
    frame_alloc, frame_dealloc, kernel_token, FrameTracker, PageTable, PhysAddr, PhysPageNum,
    StepByOne, VirtAddr,
};
use crate::sync::UPSafeCell;
use alloc::vec::Vec;
use lazy_static::*;
//use spin::Mutex;
use virtio_drivers::{Hal, VirtIOBlk, VirtIOHeader};

#[allow(unused)]
const VIRTIO0: usize = 0x10001000;
/// VirtIOBlock device driver strcuture for virtio_blk device
pub struct VirtIOBlock(UPSafeCell<VirtIOBlk<'static, VirtioHal>>);
//pub struct VirtIOBlock(Mutex<VirtIOBlk<VirtioHal, MmioTransport>>);

lazy_static! {
    /// The global io data queue for virtio_blk device
    static ref QUEUE_FRAMES: UPSafeCell<Vec<FrameTracker>> = unsafe { UPSafeCell::new(Vec::new()) };
}

unsafe impl Send for VirtIOBlock {}
unsafe impl Sync for VirtIOBlock {}

/// Interfaces BlockDevices
use core::any::Any;

/// Block device interface.
pub trait BlockDevice: Send + Sync + Any {
    /// Read a block from the block device.
    #[allow(dead_code)]
    fn read_block(&self, block_id: usize, buf: &mut [u8]);
    /// Write a block to the block device.
    #[allow(dead_code)]
    fn write_block(&self, block_id: usize, buf: &[u8]);
}


impl BlockDevice for VirtIOBlock {
    /// Read a block from the virtio_blk device
    fn read_block(&self, block_id: usize, buf: &mut [u8]) {
        self.0
            .exclusive_access()
            .read_block(block_id, buf)
            .expect("Error when reading VirtIOBlk");
    }
    ///
    fn write_block(&self, block_id: usize, buf: &[u8]) {
        self.0
            .exclusive_access()
            .write_block(block_id, buf)
            .expect("Error when writing VirtIOBlk");
    }
}

impl ext4_rs::BlockDevice for VirtIOBlock {
    fn read_offset(&self, offset: usize) -> Vec<u8> {
        // debug!("read_offset: offset = {:#x}", offset);
        let mut buf = [0u8; 4096];
        self.0
            .exclusive_access()
            .read_block(offset / BLOCK_SZ, &mut buf)
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
                .read_block(block_id, &mut buf)
                .expect("Error when reading VirtIOBlk");
            buf[block_offset..block_offset + copy_size]
                .copy_from_slice(&data[write_size..write_size + copy_size]);
            self.0
                .exclusive_access()
                .write_block(block_id, &buf)
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
            Self(UPSafeCell::new(
                VirtIOBlk::<VirtioHal>::new(&mut *(VIRTIO0 as *mut VirtIOHeader)).unwrap(),
            ))
        }
    }
}

pub struct VirtioHal;

impl Hal for VirtioHal {
    /// allocate memory for virtio_blk device's io data queue
    fn dma_alloc(pages: usize) -> usize {
        let mut ppn_base = PhysPageNum(0);
        for i in 0..pages {
            let frame = frame_alloc().unwrap();
            if i == 0 {
                ppn_base = frame.ppn;
            }
            assert_eq!(frame.ppn.0, ppn_base.0 + i);
            QUEUE_FRAMES.exclusive_access().push(frame);
        }
        let pa: PhysAddr = ppn_base.into();
        pa.0
    }
    /// free memory for virtio_blk device's io data queue
    fn dma_dealloc(pa: usize, pages: usize) -> i32 {
        let pa = PhysAddr::from(pa);
        let mut ppn_base: PhysPageNum = pa.into();
        for _ in 0..pages {
            frame_dealloc(ppn_base);
            ppn_base.step();
        }
        0
    }
    /// translate physical address to virtual address for virtio_blk device
    fn phys_to_virt(addr: usize) -> usize {
        addr
    }
    /// translate virtual address to physical address for virtio_blk device
    fn virt_to_phys(vaddr: usize) -> usize {
        PageTable::from_token(kernel_token())
            .translate_va(VirtAddr::from(vaddr))
            .unwrap()
            .0
    }
}