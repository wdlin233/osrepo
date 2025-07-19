mod blk;

pub use blk::*;
use lazy_static::lazy_static;
use polyhal::{consts::VIRT_ADDR_START, pagetable::PAGE_SIZE, PhysAddr};
use spin::{lazy, Lazy, Mutex};
use virtio_drivers::{Hal, BufferDirection};

use crate::{
    mm::{
        frames_alloc, frame_dealloc,
    }, sync::UPSafeCell,
};
use alloc::{sync::Arc, vec::Vec};
use core::ptr::NonNull;

 use crate::mm::FrameTracker;

lazy_static! {
    static ref QUEUE_FRAMES: UPSafeCell<Vec<Arc<FrameTracker>>> = unsafe {
        UPSafeCell::new(Vec::new())
    };
}

pub struct VirtIoHalImpl;

unsafe impl Hal for VirtIoHalImpl {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (usize, NonNull<u8>) {
        info!("(VirtIoHalImpl) dma_alloc: pages = {}", pages);
        let frames = frames_alloc(pages).unwrap();
        let paddr = frames[0].paddr;
        QUEUE_FRAMES.exclusive_access().extend(frames);
        unsafe {
            (paddr.raw(), NonNull::new_unchecked(paddr.get_mut_ptr::<u8>() as *mut u8))
        }
    }

    unsafe fn dma_dealloc(pa: usize, _vaddr: NonNull<u8>, pages: usize) -> i32 {
        info!("(VirtIoHalImpl) dma_dealloc: pa = {:#x}, pages = {}", pa, pages);
        let mut pa = PhysAddr::new(pa);
        for _ in 0..pages {
            frame_dealloc(pa);
            pa = pa + PAGE_SIZE;
        }
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: usize, _size: usize) -> NonNull<u8> {
        info!("(VirtIoHalImpl) translating paddr {:#x} to virt", paddr);
        return NonNull::new_unchecked((paddr | VIRT_ADDR_START) as *mut u8);
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> usize {
        // info!("(VirtIoHalImpl) Executing share for virtio_blk, buffer size: {:?}", buffer.as_ref());
        return buffer.as_ptr() as *mut u8 as usize - VIRT_ADDR_START;
    }

    unsafe fn unshare(_paddr: usize, _buffer: NonNull<[u8]>, _direction: BufferDirection) {
        // Nothing to do, as the host already has access to all memory and we didn't copy the buffer
        // anywhere else.
    }
}
