//! virtio_blk device driver
#[cfg(target_arch = "loongarch64")]
mod pci_virtio_blk;
#[cfg(target_arch = "loongarch64")]
pub use pci_virtio_blk::VirtIOBlock;

#[cfg(target_arch = "riscv64")]
mod virtio_blk;
#[cfg(target_arch = "riscv64")]
pub use virtio_blk::VirtIOBlock;

use alloc::sync::Arc;
// use easy_fs::BlockDevice;
use crate::fs::BlockDevice;
use lazy_static::*;
use crate::println;

lazy_static! {
    /// The global block device driver instance: BLOCK_DEVICE with BlockDevice trait
    pub static ref BLOCK_DEVICE: Arc<dyn BlockDevice> = Arc::new(VirtIOBlock::new());
}

/// BLOCK_SZ
pub const BLOCK_SZ: usize = 512;

// #[allow(unused)]
// /// Test the block device
// pub fn block_device_test() {
//     let block_device = BLOCK_DEVICE.clone();
//     let mut write_buffer = [0u8; 512];
//     let mut read_buffer = [0u8; 512];
//     for i in 0..512 {
//         for byte in write_buffer.iter_mut() {
//             *byte = i as u8;
//         }
//         block_device.write_block(i as usize, &write_buffer);
//         block_device.read_block(i as usize, &mut read_buffer);
//         assert_eq!(write_buffer, read_buffer);
//     }
//     println!("block device test passed!");
// }
