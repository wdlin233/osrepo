use alloc::{string::String, sync::Arc, vec::Vec};
use ext4_rs::Ext4;

use super::fs::Ext4FS;
use crate::{
    fs::{
        dentry::Dentry,
        file::File,
        inode::{Inode, InodeType, Stat},
        vfs::FileSystemType,
    },
    sync::UPSafeCell,
};
use ext4_rs::ext4_defs::FileAttr;

/// Ext4Inode defines here
pub struct Ext4Inode {
    /// Ext4 Wrapper
    pub fs: Arc<Ext4FS>,
    /// inode num
    pub ino: u32,
    /// Ext4 UPSafeCell<Ext4InodeInner>
    pub inner: UPSafeCell<Ext4InodeInner>,
}

/// Ext4InodeInner
pub struct Ext4InodeInner {
    /// pos
    pub fpos: usize,
}

impl Inode for Ext4Inode {
    fn get_inode_num(&self) -> u32 {
        self.ino
    }
    fn fstype(&self) -> FileSystemType {
        FileSystemType::EXT4
    }
    fn clear(&self) {
        todo!()
    }
    fn create(self: Arc<Self>, _name: &str, _mode: u32, _type_: InodeType) -> Option<Arc<Dentry>> {
        todo!()
    }

    fn lookup(self: Arc<Self>, name: &str) -> Option<Arc<Dentry>> {
        debug!("in lookup, name is: {}", name);
        let file = self
            .fs
            .ext4
            .fuse_lookup(self.ino as u64, name)
            .ok()
            .unwrap();
        let inode = Ext4Inode {
            fs: self.fs.clone(),
            ino: file.ino as u32,
            inner: unsafe { UPSafeCell::new(Ext4InodeInner { fpos: 0 }) },
        };
        let dentry = Dentry::new(name, Arc::new(inode));
        Some(Arc::new(dentry))
    }

    fn unlink(self: Arc<Self>, name: &str) -> bool {
        self.fs.ext4.fuse_unlink(self.ino as u64, name).is_ok()
    }

    fn link(self: Arc<Self>, _name: &str, _target: Arc<Dentry>) -> bool {
        //self.fs.ext4.ext4_link(parent, child, name, name_len);
        todo!()
    }

    fn rename(self: Arc<Self>, _old_name: &str, _new_name: &str) -> bool {
        todo!()
    }

    fn mkdir(self: Arc<Self>, _name: &str, _mode: u32) -> bool {
        todo!()
        // self.fs
        //     .ext4
        //     .fuse_mkdir(self.ino as u64, name, mode, 0)
        //     .is_ok()
    }

    fn rmdir(self: Arc<Self>, name: &str) -> bool {
        self.fs.ext4.dir_remove(self.ino, name).is_ok()
    }

    fn ls(&self) -> Vec<String> {
        self.fs.ext4.fuse_ls(self.ino)
    }

    fn read_at(&self, offset: usize, buf: &mut [u8]) -> usize {
        let flags: i32 = 0;
        //debug!("in read, to fuse read");
        let read_size = self
            .fs
            .ext4
            .fuse_read(self.ino as u64, 0, offset as i64, buf, flags, None)
            .ok()
            .unwrap();
        read_size
    }

    fn write_at(&self, _offset: usize, _buf: &[u8]) -> usize {
        todo!()
        // let inode_ref = Ext4InodeRef::get_inode_ref(Arc::downgrade(&self.fs.ext4), self.ino);
        // let mut file = Ext4File::new();
        // file.fpos = offset;
        // file.fsize = inode_ref.inner.inode.inode_get_size();
        // self.fs.ext4.ext4_file_write(&mut file, offset as i64, buf);
        // buf.len()
    }
}

impl File for Ext4Inode {
    fn fstat(&self) -> Option<Stat> {
        todo!()
    }
    fn is_dir(&self) -> bool {
        todo!()
    }
    fn read(&self, buf: &mut [u8]) -> usize {
        // TODO: 暂时不考虑 pos file!(), line!()
        let mut inner = self.inner.exclusive_access();
        let read_size = self.read_at(inner.fpos, buf);
        inner.fpos += read_size;
        read_size
    }
    fn readable(&self) -> bool {
        true
    }
    fn writable(&self) -> bool {
        true
    }
    fn write(&self, buf: &[u8]) -> usize {
        // 暂时不考虑 pos
        let write_size = self.write_at(0, buf);
        write_size
    }
    fn read_all(&self) -> Vec<u8> {
        todo!()
    }
    fn hang_up(&self) -> bool {
        todo!()
    }
}
