use spin::Mutex;
use virtio_drivers::{transport, BufferDirection, Hal};
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::Transport;
use virtio_drivers::transport::pci::bus::{BarInfo, Cam, Command, DeviceFunction, MemoryBarType, PciRoot};
use virtio_drivers::transport::pci::{PciTransport,virtio_device_type};

use core::ptr::NonNull; 

use crate::drivers::{BaseDriver, BlockDriver, DeviceType};

const VIRT_PCI_BASE: usize = 0x4000_0000;
const VIRT_PCI_SIZE: usize = 0x0002_0000;

pub struct VirtIoBlkDev<H: Hal, T: Transport> {
    inner: Mutex<VirtIOBlk<H, T>>,
}

unsafe impl<H: Hal, T:Transport> Send for VirtIoBlkDev<H, T> {}
unsafe impl<H: Hal, T:Transport> Sync for VirtIoBlkDev<H, T> {}

#[cfg(target_arch = "riscv64")]
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

#[cfg(target_arch = "loongarch64")]
impl<H: Hal> VirtIoBlkDev<H, PciTransport> {
    pub fn new(header: *mut u8) -> Self {
        let transport = enumerate_pci::<H>(header)
                .expect("failed to create PciTransport");

        Self {
            inner: Mutex::new(
                VirtIOBlk::<H, PciTransport>::new(transport)
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
        info!(
            "(VirtIoBlkDev, read_block) block_id: {}, buf len: {}",
            block_id, buf.len()
        );
        self.inner.lock()
            .read_blocks(block_id, buf)
            .expect("Error when reading VirtIOBlk");
    }

    fn write_block(&mut self, block_id: usize, buf: &[u8]) {
        self.inner.lock().write_blocks(block_id, buf).expect("Error when writing VirtIOBlk")
    }

    fn flush(&mut self) {

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
        debug!("alloc_pci: size = {:#x}", size);
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


fn enumerate_pci<H: Hal>(mmconfig_base: *mut u8) -> Option<PciTransport> {
    info!("mmconfig_base = {:#x}", mmconfig_base as usize);

    let mut pci_root = unsafe { PciRoot::new(mmconfig_base, Cam::Ecam) };
    let mut transport = None;

    debug!("Enumerating PCI devices...");
    for (device_function, info) in pci_root.enumerate_bus(0) {
        if let Some(virtio_type) = virtio_device_type(&info) {
            if virtio_type != virtio_drivers::transport::DeviceType::Block {continue;}
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
                Some(PciTransport::new::<H>(&mut pci_root, device_function).unwrap());
            break;
        }
    }
    return transport;
}