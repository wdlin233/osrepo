// Byte-OS/polyhal/examples/src/pci.rs
use core::ptr::NonNull;

use super::BlockDevice;
use crate::mm::{
    frame_alloc, frame_dealloc, kernel_token, FrameTracker, PageTable, PhysAddr, PhysPageNum,
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
//const VIRTIO0: usize = 0x2000_0000 | 0x9000000000000000;
const VIRTIO0: usize = 0x2000_0000;
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

impl BlockDevice for VirtIOBlock {
    fn read_block(&self, block_id: usize, buf: &mut [u8]) {
        self.0
            .exclusive_access()
            .read_blocks(block_id, buf)
            .expect("Error when reading VirtIOBlk");
    }
    fn write_block(&self, block_id: usize, buf: &[u8]) {
        self.0
            .exclusive_access()
            .write_blocks(block_id, buf)
            .expect("Error when writing VirtIOBlk");
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

    for (device_function, info) in pci_root.enumerate_bus(0) {
        // let (status, command) = pci_root.get_status_command(device_function);
        // info!(
        //     "Found {} at {}, status {:?} command {:?}",
        //     info, device_function, status, command
        // );
        if let Some(virtio_type) = virtio_device_type(&info) {
            if virtio_type != DeviceType::Block {continue;}
            let mut pci_range_allocator = PciRangeAllocator::new(VIRT_PCI_BASE, VIRT_PCI_SIZE);
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
                    bar_index+=1;
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
#[allow(unused)]
fn dump_bar_contents(
    root: &mut PciRoot,
    device_function: DeviceFunction,
    bar_index: u8,
) {
    let bar_info = root.bar_info(device_function, bar_index).unwrap();
    if let BarInfo::Memory { address, size, .. } = bar_info {
        let start = address as *const u8;
        println!("start:{:?}", start);
        unsafe {
            let mut buf = [0u8; 32];
            for i in 0..size / 32 {
                let ptr = start.add(i as usize * 32);
                println!("ptr:{:?}",ptr);
                core::ptr::copy(ptr, buf.as_mut_ptr(), 32);
                if buf.iter().any(|b| *b != 0xff) {
                }
            }
        }
    }
}

impl VirtIOBlock {
    #[allow(unused)]
    pub fn new() -> Self {
        unsafe {
            Self(UPSafeCell::new(
                VirtIOBlk::<VirtioHal, PciTransport>::new(
                    enumerate_pci(VIRTIO0 as *mut u8).unwrap()
                    )
                    .expect("this is not a valid virtio device"),
                )
            )
        }
    }
}

pub struct VirtioHal;

unsafe impl Hal for VirtioHal {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (usize, NonNull<u8>) {
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
        let pa = PhysAddr::from(paddr);
        let mut ppn_base: PhysPageNum = pa.into();
        for _ in 0..pages {
            frame_dealloc(ppn_base);
            ppn_base.step();
        }
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: usize, _size: usize) -> NonNull<u8> {
        NonNull::new((paddr | 0x9000000000000000) as *mut u8).unwrap()
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> usize {
        buffer.as_ptr() as *mut u8 as usize - 0x9000000000000000
    }

    unsafe fn unshare(_paddr: usize, _buffer: NonNull<[u8]>, _direction: BufferDirection) {
        // Nothing to do, as the host already has access to all memory and we didn't copy the buffer
        // anywhere else.
    }
}
