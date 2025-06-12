use alloc::sync::Arc;

use ext4_rs::{BlockDevice, Ext4};

use super::{
    ROOT_INO,
    inode::{Ext4Inode, Ext4InodeInner},
};
use crate::{
    ext4::{dentry::Dentry, superblock, Ext4SuperBlock, Ext4Disk},
    sync::UPSafeCell
};

/// Ext4 Arc Wrapper
pub struct Ext4FS {
    pub superblock: Arc<Ext4SuperBlock>,
    /// Ext4 Arc Wrapper obj
    pub ext4: Arc<Ext4>,
}

/// Ext4 Arc Wrapper implements
impl Ext4FS {
    /// Ext4 Arc Wrapper -> new(block_dev: Arc<dyn BD>)
    pub fn new(block_dev: Arc<dyn crate::drivers::BlockDevice>) -> Self {
        let ext4 = Arc::new(Ext4::open(Arc::new(Ext4Disk::new(block_dev.clone()))));
        let superblock = Arc::new(Ext4SuperBlock::new(block_dev));
        Self { superblock, ext4 }
    }
    fn get_sblock(self: Arc<Self>) -> Arc<Ext4SuperBlock> {
        self.superblock.clone()
    }
    fn root_inode(self: Arc<Self>) -> Arc<Ext4Dentry> {
        let superblock = self.get_sblock();
        superblock
            .root_dentry()
            .get_inode()
    }
}
