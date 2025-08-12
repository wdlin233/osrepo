use spin::Mutex;
use virtio_drivers::device::net::{VirtIONet, RxBuffer, TxBuffer};
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::pci::bus::{
    BarInfo, Cam, Command, DeviceFunction, MemoryBarType, PciRoot,
};
use virtio_drivers::transport::pci::{virtio_device_type, PciTransport};
use virtio_drivers::transport::Transport;
use virtio_drivers::{BufferDirection, Hal};
use alloc::vec::Vec;
use core::ptr::NonNull;

use crate::drivers::{BaseDriver, DeviceType};

const VIRT_PCI_BASE: usize = 0x4000_0000;
const VIRT_PCI_SIZE: usize = 0x0002_0000;
const QUEUE_SIZE: usize = 64;
const NET_BUF_LEN: usize = 1526; // Standard MTU + Ethernet header

pub struct VirtIoNetDev<H: Hal, T: Transport> {
    inner: Mutex<VirtIONet<H, T, QUEUE_SIZE>>,
}

unsafe impl<H: Hal, T: Transport> Send for VirtIoNetDev<H, T> {}
unsafe impl<H: Hal, T: Transport> Sync for VirtIoNetDev<H, T> {}

#[cfg(target_arch = "riscv64")]
impl<H: Hal> VirtIoNetDev<H, MmioTransport> {
    pub fn new(header: &'static mut VirtIOHeader) -> Self {
        let ptr = NonNull::new(header as *mut _).unwrap();
        let transport = unsafe { MmioTransport::new(ptr).expect("failed to create MmioTransport") };

        Self {
            inner: Mutex::new(
                VirtIONet::<H, MmioTransport, QUEUE_SIZE>::new(transport, NET_BUF_LEN)
                    .expect("VirtIONet create failed"),
            ),
        }
    }
}

impl<H: Hal> VirtIoNetDev<H, PciTransport> {
    pub fn new(header: *mut u8) -> Self {
        let transport = enumerate_pci::<H>(header).expect("failed to create PciTransport");

        Self {
            inner: Mutex::new(
                VirtIONet::<H, PciTransport, QUEUE_SIZE>::new(transport, NET_BUF_LEN)
                    .expect("VirtIONet create failed"),
            ),
        }
    }
}

impl<H: Hal, T: Transport> BaseDriver for VirtIoNetDev<H, T> {
    fn device_name(&self) -> &str {
        "virtio-net"
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Net
    }
}

/// Network buffer pointer for received packets
pub struct NetBufPtr {
    inner: RxBuffer,
}

impl NetBufPtr {
    pub fn new(rx_buf: RxBuffer) -> Self {
        Self { inner: rx_buf }
    }

    pub fn packet_len(&self) -> usize {
        self.inner.packet_len()
    }

    pub fn packet(&self) -> &[u8] {
        self.inner.packet()
    }

    pub fn packet_mut(&mut self) -> &mut [u8] {
        self.inner.packet_mut()
    }
}

/// Network buffer pointer for transmit packets
pub struct NetTxBufPtr {
    inner: TxBuffer,
}

impl NetTxBufPtr {
    pub fn new(tx_buf: TxBuffer) -> Self {
        Self { inner: tx_buf }
    }

    pub fn packet_len(&self) -> usize {
        self.inner.packet_len()
    }

    pub fn packet(&self) -> &[u8] {
        self.inner.packet()
    }

    pub fn packet_mut(&mut self) -> &mut [u8] {
        self.inner.packet_mut()
    }
}

/// Network device abstraction for socket layer
pub struct AxNetDevice<H: Hal, T: Transport> {
    dev: VirtIoNetDev<H, T>,
}

impl<H: Hal, T: Transport> AxNetDevice<H, T> {
    pub fn new(dev: VirtIoNetDev<H, T>) -> Self {
        Self { dev }
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.dev.inner.lock().mac_address()
    }

    pub fn can_transmit(&self) -> bool {
        self.dev.inner.lock().can_send()
    }

    pub fn can_receive(&self) -> bool {
        self.dev.inner.lock().can_recv()
    }

    pub fn receive(&mut self) -> Result<NetBufPtr, NetError> {
        match self.dev.inner.lock().receive() {
            Ok(rx_buf) => Ok(NetBufPtr::new(rx_buf)),
            Err(_) => Err(NetError::Again),
        }
    }

    pub fn transmit(&mut self, tx_buf: NetTxBufPtr) -> Result<(), NetError> {
        match self.dev.inner.lock().send(tx_buf.inner) {
            Ok(_) => Ok(()),
            Err(_) => Err(NetError::Again),
        }
    }

    pub fn alloc_tx_buffer(&mut self, len: usize) -> Result<NetTxBufPtr, NetError> {
        let tx_buf = self.dev.inner.lock().new_tx_buffer(len);
        Ok(NetTxBufPtr::new(tx_buf))
    }

    pub fn recycle_rx_buffer(&mut self, rx_buf: NetBufPtr) -> Result<(), NetError> {
        match self.dev.inner.lock().recycle_rx_buffer(rx_buf.inner) {
            Ok(_) => Ok(()),
            Err(_) => Err(NetError::Again),
        }
    }

    pub fn recycle_tx_buffers(&mut self) -> Result<(), NetError> {
        // VirtIONet handles tx buffer recycling internally
        Ok(())
    }
}

#[derive(Debug)]
pub enum NetError {
    Again,
    InvalidInput,
    NotSupported,
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
    pub const fn new(pci_base: usize, pci_size: usize) -> Self {
        Self {
            start: pci_base,
            end: pci_base + pci_size,
            current: pci_base,
        }
    }
    pub fn alloc_pci(&mut self, size: usize) -> Option<usize> {
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
            if virtio_type != virtio_drivers::transport::DeviceType::Network {
                continue;
            }
            
            let mut pci_range_allocator = PciRangeAllocator::new(VIRT_PCI_BASE, VIRT_PCI_SIZE);
            let mut bar_index = 0;
            while bar_index < 6 {
                let bar_info = pci_root.bar_info(device_function, bar_index).unwrap();
                if let BarInfo::Memory {
                    address_type,
                    address,
                    size,
                    ..
                } = bar_info
                {
                    if address == 0 && size != 0 {
                        let alloc_addr = pci_range_allocator.alloc_pci(size as usize).unwrap();
                        match address_type {
                            MemoryBarType::Width64 => {
                                pci_root.set_bar_64(device_function, bar_index, alloc_addr as u64)
                            }
                            MemoryBarType::Width32 => {
                                pci_root.set_bar_32(device_function, bar_index, alloc_addr as u32)
                            }
                            _ => {}
                        }
                    }
                }
                bar_index += 1;
                if bar_info.takes_two_entries() {
                    bar_index += 1;
                }
            }

            // Enable the device to use its BARs.
            pci_root.set_command(
                device_function,
                Command::IO_SPACE | Command::MEMORY_SPACE | Command::BUS_MASTER,
            );

            transport = Some(PciTransport::new::<H>(&mut pci_root, device_function).unwrap());
            break;
        }
    }
    return transport;
}
