use ext4_rs::Ext4;
use spin::{once::Once, Once};
use crate::ext4::{dentry::Dentry, Ext4Dentry, Ext4Disk, Ext4Inode, ROOT_INO};
use alloc::sync::Arc;
use crate::fs::StatMode;
use crate::drivers::BlockDevice;
use crate::ext4::fs::Ext4FS;

#[derive(Clone, Debug)]
pub struct Ext4SuperBlock {
    pub device: Arc<dyn BlockDevice>,
    pub root_dentry: Once<Arc<Ext4Dentry>>,
    pub fs: Arc<Ext4FS>,
}

impl Ext4SuperBlock {
    /// Create a new Ext4SuperBlock instance
    pub fn new(device: Arc<dyn BlockDevice>) -> Self {
        Self {
            device: device.clone(),
            root_dentry: Once::new(),
            fs: Arc::new(Ext4FS::new(device.clone())),
        }
    }

    /// Get the block device
    pub fn device(&self) -> Arc<dyn BlockDevice> {
        self.device.clone()
    }

    /// Get the root dentry
    pub fn root_dentry(&self) -> Arc<Ext4Dentry> {
         self.root_dentry.get().cloned()
            .expect("root_dentry must be initialized")
    }

    pub fn set_root_dentry(&mut self, dentry: Arc<Exr4Dentry>) {
        self.root_dentry = dentry;
    }

    pub fn init_root_dentry(&mut self) {
        let root_inode = Arc::new(Ext4Inode::new(ROOT_INO, self.clone().into(), StatMode::DIR));
        let root_dentry = Ext4Dentry::new(
            "/",
            root_inode.clone(),
            None,
        );
        self.set_root_dentry(root_dentry);
    }
}