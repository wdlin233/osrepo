use alloc::sync::Arc;

use ext4_rs::{BlockDevice, Ext4};

use super::{
    ROOT_INO,
    inode::{Ext4Inode, Ext4InodeInner},
};
use crate::{
    fs::{
        vfs::{FileSystem, FileSystemType},
        inode::Inode,
    },
    sync::UPSafeCell,
};

/// Ext4 Arc Wrapper
pub struct Ext4FS {
    /// Ext4 Arc Wrapper obj
    pub ext4: Arc<Ext4>,
}

/// Ext4 Arc Wrapper implements
impl Ext4FS {
    /// Ext4 Arc Wrapper -> new(block_dev: Arc<dyn BD>)
    pub fn new(block_dev: Arc<dyn BlockDevice>) -> Self {
        let ext4 = Ext4::open(block_dev);
        Self { ext4 }
    }
}

impl FileSystem for Ext4FS {
    fn fs_type(&self) -> FileSystemType {
        FileSystemType::EXT4
    }
    fn root_inode(self: Arc<Self>) -> Arc<dyn Inode> {
        let inode = Ext4Inode {
            fs:    self.clone(),
            ino:   ROOT_INO,
            inner: unsafe { UPSafeCell::new(Ext4InodeInner { fpos: 0 }) },
        };
        Arc::new(inode)
    }
}
