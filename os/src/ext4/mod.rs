pub mod disk;
pub mod block_cache;
pub mod superblock;
pub mod fs;
pub mod inode;
pub mod dentry;

pub use block_cache::get_block_cache;
pub use disk::Ext4Disk;
pub use superblock::Ext4SuperBlock;
pub use fs::Ext4FS;
pub use inode::{Ext4Inode, Ext4InodeInner};
pub use dentry::{Ext4Dentry, DentryType, };

pub const ROOT_INO: usize = 2;