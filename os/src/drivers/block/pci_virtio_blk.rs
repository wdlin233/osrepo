// Byte-OS/polyhal/examples/src/pci.rs
use core::ptr::NonNull;

use ext4_rs::BlockDevice;
use crate::drivers::block::IO_BLOCK_SIZE;
use crate::mm::{
    frame_alloc, frame_dealloc, FrameTracker, PageTable, PhysAddr, PhysPageNum,
    StepByOne, VirtAddr,
};
use crate::sync::UPSafeCell;
use alloc::vec::Vec;
use lazy_static::*;
use virtio_drivers::transport::pci::bus::{BarInfo, Cam, Command, DeviceFunction, MemoryBarType, PciRoot};
use virtio_drivers::transport::pci::{PciTransport,virtio_device_type};
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::DeviceType;
use virtio_drivers::{BufferDirection, Hal};

//#[allow(unused)]
//#[cfg(target_arch = "loongarch64")]
const VIRTIO0: usize = 0x2000_0000 | 0x9000000000000000;
const VIRT_PCI_BASE: usize = 0x4000_0000;
const VIRT_PCI_SIZE: usize = 0x0002_0000;


pub struct VirtIOBlock(UPSafeCell<VirtIOBlk<VirtioHal, PciTransport>>);

lazy_static! {
    static ref QUEUE_FRAMES: UPSafeCell<Vec<FrameTracker>> = unsafe {
        UPSafeCell::new(Vec::new())
    };
}

unsafe impl Sync for VirtIOBlock {}
unsafe impl Send for VirtIOBlock {}

impl ext4_rs::BlockDevice for VirtIOBlock {
    fn read_offset(&self, offset: usize) -> Vec<u8> {
        // debug!("read_offset: offset = {:#x}", offset);
        let mut buf = [0u8; 4096];
        self.0
            .exclusive_access()
            .read_blocks(offset / IO_BLOCK_SIZE, &mut buf)
            .expect("Error when reading VirtIOBlk");
        // debug!("read_offset = {:#x}, buf = {:x?}", offset, buf);
        buf[offset % IO_BLOCK_SIZE..].to_vec()
    }
    fn write_offset(&self, offset: usize, data: &[u8]) {
        debug!("write_offset: offset = {:#x}", offset);
        //     debug!("data len = {:#x}", data.len());
        let mut write_size = 0;
        while write_size < data.len() {
            let block_id = (offset + write_size) / IO_BLOCK_SIZE;
            let block_offset = (offset + write_size) % IO_BLOCK_SIZE;
            let mut buf = [0u8; IO_BLOCK_SIZE];
            let copy_size = core::cmp::min(data.len() - write_size, IO_BLOCK_SIZE - block_offset);
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


const fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

pub struct PciRangeAllocator {
    start: usize,
    end: usize,
    current: usize,

}

impl PciRangeAllocator {
    /// Creates a new allocator from a memory range.
    pub const fn new(pci_base:usize,pci_size:usize) -> Self {
        Self {
            start:pci_base,
            end:pci_base+pci_size,
            current:pci_base
        }
    }
    pub fn alloc_pci(&mut self,size: usize) -> Option<usize> {
        if !size.is_power_of_two() {
            return None;
        }
        let ret = align_up(self.current, size);
        if ret + size > self.end {
            return None;
        }
        self.current = ret + size;
        Some(ret)
    }
}


fn enumerate_pci(mmconfig_base: *mut u8) -> Option<PciTransport> {
    info!("mmconfig_base = {:#x}", mmconfig_base as usize);

    let mut pci_root = unsafe { PciRoot::new(mmconfig_base, Cam::Ecam) };
    let mut transport = None;

    debug!("Enumerating PCI devices...");
    for (device_function, info) in pci_root.enumerate_bus(0) {
        if let Some(virtio_type) = virtio_device_type(&info) {
            if virtio_type != DeviceType::Block {continue;}
            // debug!(
            //     "Found virtio device {:?} at {}",
            //     virtio_type,
            //     device_function
            // );
            let mut pci_range_allocator = PciRangeAllocator::new(VIRT_PCI_BASE, VIRT_PCI_SIZE);
            //debug!("Allocating BARs for device {}", device_function);
            let mut bar_index = 0;
            while bar_index < 6 {
                let bar_info = pci_root.bar_info(device_function, bar_index).unwrap();
                if let BarInfo::Memory { address_type, address, size, ..} = bar_info {
                    if address == 0 && size != 0{
                        let alloc_addr = pci_range_allocator.alloc_pci(size as usize).unwrap();
                        match  address_type {
                            MemoryBarType::Width64=>pci_root.set_bar_64(device_function, bar_index, alloc_addr as u64),
                            MemoryBarType::Width32=>pci_root.set_bar_32(device_function, bar_index, alloc_addr as u32),
                            _=>{}
                        }
                    }
                }
                bar_index += 1;
                if bar_info.takes_two_entries(){
                    bar_index += 1;
                }
            }

            // Enable the device to use its BARs.
            pci_root.set_command(
                device_function,
                Command::IO_SPACE | Command::MEMORY_SPACE | Command::BUS_MASTER,
            );
         //   dump_bar_contents(&mut pci_root, device_function, 1);

            transport =
                Some(PciTransport::new::<VirtioHal>(&mut pci_root, device_function).unwrap());
            break;
        }
    }
    return transport;
}

impl VirtIOBlock {
    #[allow(unused)]
    pub fn new() -> Self {
        // debug!("Creating VirtIOBlock driver with VIRTIO0 base_addr for virtio_blk device");
        unsafe {
            let header = VIRTIO0 as *mut u8;
            Self(UPSafeCell::new(
                VirtIOBlk::<VirtioHal, PciTransport>::new(
                    enumerate_pci(header).unwrap()
                ).expect("this is not a valid virtio device"),
                )
            )
        }
    }
}

pub struct VirtioHal;

unsafe impl Hal for VirtioHal {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (usize, NonNull<u8>) {
        //debug!("Allocating {} pages for pci_virtio_blk", pages);
        let mut ppn_base = PhysPageNum(0);
        for i in 0..pages {
            let frame = frame_alloc().unwrap();
            debug!("alloc paddr: {:?}", frame);
            if i == 0 {
                ppn_base = frame.ppn
            };
            assert_eq!(frame.ppn.0, ppn_base.0 + i);
            QUEUE_FRAMES.exclusive_access().push(frame);
        }
        let pa: PhysAddr = ppn_base.into();
        unsafe {
            (pa.0, NonNull::new_unchecked((pa.0 | 0x9000000000000000) as *mut u8))
        }
    }

    unsafe fn dma_dealloc(paddr: usize, _vaddr: NonNull<u8>, pages: usize) -> i32 {
        //debug!("Deallocating {} pages for pci_virtio_blk", pages);
        let pa = PhysAddr::from(paddr);
        let mut ppn_base: PhysPageNum = pa.into();
        for _ in 0..pages {
            frame_dealloc(ppn_base);
            ppn_base.step();
        }
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: usize, _size: usize) -> NonNull<u8> {
        //debug!("Converting physical address {:#x} to virtual address", paddr);
        NonNull::new((paddr | 0x9000000000000000) as *mut u8).unwrap()
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> usize {
        //debug!("Executing share for pci_virtio_blk");
        buffer.as_ptr() as *mut u8 as usize - 0x9000000000000000
    }

    unsafe fn unshare(_paddr: usize, _buffer: NonNull<[u8]>, _direction: BufferDirection) {
        // Nothing to do, as the host already has access to all memory and we didn't copy the buffer
        // anywhere else.
    }
}
