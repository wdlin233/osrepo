use spin::Mutex;
use virtio_drivers::{transport, BufferDirection, Hal};
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::Transport;
use core::ptr::NonNull; 

use crate::drivers::{BaseDriver, BlockDriver, DeviceType};

pub struct VirtIoBlkDev<H: Hal, T: Transport> {
    inner: Mutex<VirtIOBlk<H, T>>,
}

unsafe impl<H: Hal, T:Transport> Send for VirtIoBlkDev<H, T> {}
unsafe impl<H: Hal, T:Transport> Sync for VirtIoBlkDev<H, T> {}

impl<H: Hal> VirtIoBlkDev<H, MmioTransport> {
    pub fn new(header: &'static mut VirtIOHeader) -> Self {
        // 转换为 NonNull 并创建 MmioTransport
        let ptr = NonNull::new(header as *mut _).unwrap();
        let transport = unsafe { 
            MmioTransport::new(ptr).expect("failed to create MmioTransport") 
        };
        
        Self {
            inner: Mutex::new(
                VirtIOBlk::<H, MmioTransport>::new(transport)
                    .expect("VirtIOBlk create failed")
            ),
        }
    }
}

impl<H: Hal, T: Transport> BaseDriver for VirtIoBlkDev<H, T> {
    fn device_name(&self) -> &str {
        "virtio-blk"
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }
}

impl<H: Hal, T: Transport> BlockDriver for VirtIoBlkDev<H, T> {
    #[inline]
    fn num_blocks(&self) -> usize {
        self.inner.lock().capacity() as usize
    }

    #[inline]
    fn block_size(&self) -> usize {
        512
    }

    fn read_block(&mut self, block_id: usize, buf: &mut [u8]) {
        self.inner.lock().read_blocks(block_id, buf).unwrap();
    }

    fn write_block(&mut self, block_id: usize, buf: &[u8]) {
        self.inner.lock().write_blocks(block_id, buf).unwrap()
    }

    fn flush(&mut self) {

    }
}
