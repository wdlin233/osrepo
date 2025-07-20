mod device;
mod disk;
pub use device::*;
pub use disk::*;

// cfg_if::cfg_if! {
//     if #[cfg(feature="board_qemu")]{
//         mod virtio;
//         use virtio_drivers::VirtIOHeader;
//         use virtio::*;
//         use crate::config::mm::KERNEL_ADDR_OFFSET;

//         pub type BlockDeviceImpl = VirtIoBlkDev<VirtIoHalImpl>;

//         impl BlockDeviceImpl {
//             pub fn new_device() -> Self {
//                 const VIRTIO0: usize = 0x10001000 + KERNEL_ADDR_OFFSET;
//                 unsafe { VirtIoBlkDev::new(&mut *(VIRTIO0 as *mut VirtIOHeader)) }
//             }
//         }
//     }else if #[cfg(feature="board_vf2")]{
//         mod sdcard;
//         pub type BlockDeviceImpl = sdcard::Vf2BlkDev;
//     }else if #[cfg(feature="board_ramdisk")]{
//         mod ramdisk;
//         pub type BlockDeviceImpl = ramdisk::MemBlockWrapper;
//     }
// }

mod virtio;
use polyhal::consts::VIRT_ADDR_START;
#[cfg(target_arch = "riscv64")]
use polyhal::PhysAddr;
use virtio::*;
use virtio_drivers::transport::mmio::MmioTransport;
use virtio_drivers::transport::mmio::VirtIOHeader;
use virtio_drivers::transport::pci::PciTransport;

#[cfg(target_arch = "riscv64")]
pub const VIRTIO0: PhysAddr = polyhal::pa!(0x1000_1000);
#[cfg(target_arch = "loongarch64")]
const VIRTIO0: usize = 0x2000_0000;

#[cfg(target_arch = "riscv64")]
pub type BlockDeviceImpl = VirtIoBlkDev<VirtIoHalImpl, MmioTransport>;
#[cfg(target_arch = "loongarch64")]
pub type BlockDeviceImpl = VirtIoBlkDev<VirtIoHalImpl, PciTransport>;

impl BlockDeviceImpl {
    pub fn new_device() -> Self {
        #[cfg(target_arch = "riscv64")]
        unsafe {
            VirtIoBlkDev::<VirtIoHalImpl, MmioTransport>::new(
                &mut *(VIRTIO0.get_mut_ptr() as *mut VirtIOHeader),
            )
        }
        #[cfg(target_arch = "loongarch64")]
        unsafe {
            VirtIoBlkDev::<VirtIoHalImpl, PciTransport>::new(&mut *(VIRTIO0 as *mut u8))
        }
    }
}
