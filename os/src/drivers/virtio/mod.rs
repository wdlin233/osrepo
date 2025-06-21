mod blk;

pub use blk::*;
use spin::{Lazy, Mutex};
use virtio_drivers::{Hal, BufferDirection};

use crate::{
    mm::{
        frame_alloc, frame_dealloc, FrameTracker, PageTable, PhysAddr, PhysPageNum,
        StepByOne, VirtAddr,
    },
    task::current_token,
};
use alloc::{sync::Arc, vec::Vec};
use core::ptr::NonNull;
use crate::mm::KERNEL_SPACE;

/// 实现 Trait BlockDevice时对内部操作加锁
// pub static ref BLOCK_DEVICE: Arc<dyn BlockDevice> = Arc::new(BlockDeviceImpl::new());
static QUEUE_FRAMES: Lazy<Mutex<Vec<Arc<FrameTracker>>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub struct VirtIoHalImpl;

unsafe impl Hal for VirtIoHalImpl {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (usize, NonNull<u8>) {
        let mut ppn_base = PhysPageNum(0);
        for i in 0..pages {
            let frame = frame_alloc().unwrap();
            if i == 0 {
                ppn_base = frame.ppn;
            }
            assert_eq!(frame.ppn.0, ppn_base.0 + i);
            QUEUE_FRAMES.lock().push(frame.into()); // expected `Arc<FrameTracker>`, found `FrameTracker
        }
        let pa: PhysAddr = ppn_base.into();
        unsafe {
            (pa.0, NonNull::new_unchecked((pa.0 | 0x80200000) as *mut u8))
        }
    }

    unsafe fn dma_dealloc(pa: usize, _vaddr: NonNull<u8>, pages: usize) -> i32 {
        let pa = PhysAddr::from(pa);
        let mut ppn_base: PhysPageNum = pa.into();
        for _ in 0..pages {
            frame_dealloc(ppn_base);
            ppn_base.step();
        }
        0
    }

    // fn phys_to_virt(addr: usize) -> usize {
    //     PhysAddr::from(addr).0 | 0x80200000
    // }

    // fn virt_to_phys(vaddr: usize) -> usize {
    //     PageTable::from_token(current_token())
    //         .translate_va(VirtAddr::from(vaddr))
    //         .unwrap()
    //         .0
    //     // PhysAddr::from(vaddr - KERNEL_ADDR_OFFSET).0
    // }
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
