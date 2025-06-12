use ext4_rs::Ext4;
use spin::{once::Once};
use crate::ext4::superblock;
use crate::ext4::{dentry::Ext4Dentry, Ext4Disk, Ext4Inode, ROOT_INO};
use alloc::sync::Arc;
use crate::fs::StatMode;
use crate::drivers::BlockDevice;

pub struct Ext4SuperBlock {
    pub device: Arc<dyn BlockDevice>,
    pub root_dentry: Once<Arc<Ext4Dentry>>,
    pub ext4: Arc<Ext4>,
}

impl Ext4SuperBlock {
    /// Create a new Ext4SuperBlock instance
    pub fn mount(block_dev: Arc<dyn BlockDevice>) -> Arc<Self> {
        // 1. 创建底层 ext4 结构
        let disk = Arc::new(Ext4Disk::new(block_dev.clone()));
        let ext4 = Arc::new(Ext4::open(disk));
        
        // 2. 创建 superblock (此时 root_dentry 未初始化)
        let sb = Arc::new(Self {
            device: block_dev.clone(),
            root_dentry: Once::new(),
            ext4,
        });
        
        // 3. 使用 superblock 本身来初始化 root_dentry
        let root = init_root_dentry(sb.clone());
        sb.root_dentry.call_once(|| root);
        
        sb
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

    pub fn set_root_dentry(&self, dentry: Arc<Ext4Dentry>) {
        self.root_dentry = dentry.into();
    }
}

pub fn init_root_dentry(superblock: Arc<Ext4SuperBlock>) -> Arc<Ext4Dentry> {
    let root_inode = Arc::new(Ext4Inode::new(ROOT_INO, superblock, StatMode::DIR));
    let root_dentry = Ext4Dentry::new(
        "/",
        root_inode.clone(),
        None,
    );
    superblock.set_root_dentry(root_dentry);
    root_dentry
}