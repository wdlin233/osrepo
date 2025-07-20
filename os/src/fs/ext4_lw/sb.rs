#![allow(non_snake_case)]
use log::{error, warn};
use lwext4_rust::{Ext4BlockWrapper, InodeTypes, KernelDevOp};

use crate::{
    drivers::Disk,
    fs::{Inode, Statfs, SuperBlock},
    sync::UPSafeCell,
};

use alloc::sync::Arc;

use super::Ext4Inode;
use crate::println;

pub struct Ext4SuperBlock {
    inner: UPSafeCell<Ext4BlockWrapper<Disk>>,
    root: Arc<dyn Inode>,
}

unsafe impl Send for Ext4SuperBlock {}
unsafe impl Sync for Ext4SuperBlock {}

impl SuperBlock for Ext4SuperBlock {
    fn root_inode(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }
    fn fs_stat(&self) -> Statfs {
        let stat = self.inner.get_unchecked_ref().get_lwext4_mp_stats();
        Statfs {
            f_type: 0xEF53,
            f_bsize: stat.block_size as i64,
            f_blocks: stat.blocks_count as i64,
            f_bfree: stat.free_blocks_count as i64,
            f_bavail: stat.free_blocks_count as i64,
            f_files: stat.inodes_count as i64,
            f_ffree: stat.free_inodes_count as i64,
            f_name_len: 255,
            ..Default::default()
        }
    }
    fn sync(&self) {
        self.inner.get_unchecked_mut().sync();
    }
    fn ls(&self) {
        use crate::println;
        self.inner
            .get_unchecked_ref()
            .lwext4_dir_ls()
            .into_iter()
            .for_each(|s| {
                println!("{}", s);
            });
    }
}

impl Ext4SuperBlock {
    pub fn new(disk: Disk) -> Self {
        debug!("in ext4 super block");
        let inner =
            Ext4BlockWrapper::<Disk>::new(disk).expect("failed to initialize EXT4 filesystem");
        let root = Arc::new(Ext4Inode::new("/", InodeTypes::EXT4_DE_DIR));
        unsafe {
            Self {
                inner: UPSafeCell::new(inner),
                root,
            }
        }
    }
}

impl KernelDevOp for Disk {
    //type DevType = Box<Disk>;
    type DevType = Disk;

    fn read(dev: &mut Disk, mut buf: &mut [u8]) -> Result<usize, i32> {
        debug!("READ block device buf={}", buf.len());
        let mut read_len = 0;
        while !buf.is_empty() {
            match dev.read_one(buf) {
                0 => break,
                n => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    read_len += n;
                }
            }
        }
        //debug!("READ rt len={}", read_len);
        Ok(read_len)
    }
    fn write(dev: &mut Self::DevType, mut buf: &[u8]) -> Result<usize, i32> {
        //debug!("WRITE block device buf={}", buf.len());
        let mut write_len = 0;
        while !buf.is_empty() {
            match dev.write_one(buf) {
                0 => break,
                n => {
                    buf = &buf[n..];
                    write_len += n;
                }
            }
        }
        //debug!("WRITE rt len={}", write_len);
        Ok(write_len)
    }
    fn flush(_dev: &mut Self::DevType) -> Result<usize, i32> {
        Ok(0)
    }
    fn seek(dev: &mut Disk, off: i64, whence: i32) -> Result<i64, i32> {
        let size = dev.size();
        /*
        debug!(
            "SEEK block device size:{}, pos:{}, offset={}, whence={}",
            size,z
            &dev.position(),
            off,
            whence
        );
        */
        let new_pos = match whence as u32 {
            lwext4_rust::bindings::SEEK_SET => Some(off),
            lwext4_rust::bindings::SEEK_CUR => dev
                .position()
                .checked_add_signed(off as isize)
                .map(|v| v as i64),
            lwext4_rust::bindings::SEEK_END => {
                size.checked_add_signed(off as isize).map(|v| v as i64)
            }
            _ => {
                error!("invalid seek() whence: {}", whence);
                Some(off)
            }
        }
        .ok_or(-1)?;

        if new_pos as usize > size {
            warn!("Seek beyond the end of the block device");
        }
        dev.set_position(new_pos as usize);
        // debug!("new_pos={}", new_pos);
        Ok(new_pos)
    }
}
