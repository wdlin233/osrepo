use alloc::{string::String, sync::Arc, vec::Vec};

use crate::mm::UserBuffer;
use crate::{
    fs::StatMode, 
    sync::UPSafeCell
};

use super::Ext4SuperBlock;
use crate::fs::{Stat, File};
use crate::ext4::dentry::Ext4Dentry;

/// Ext4Inode defines here
pub struct Ext4Inode {
    /// inode num
    pub ino: usize,
    pub superblock: Arc<Ext4SuperBlock>,
    pub mode: StatMode,
    //pub inner: UPSafeCell<Ext4InodeInner>,
}

/// Ext4InodeInner
pub struct Ext4InodeInner {
    /// pos
    pub fpos: usize,
    pub size: usize,
    pub nlink: usize,
    pub times: usize, // 先定义在这
}

impl Ext4Inode {
    pub fn new(ino: usize, superblock: Arc<Ext4SuperBlock>, mode: StatMode) -> Self {
        Self {
            ino,
            superblock,
            mode,
            //inner: unsafe { UPSafeCell::new(Ext4InodeInner { fpos: 0, size: 0, nlink: 0, times: 0 }) },
        }
    }
    fn clear(&self) {
        todo!()
    }
    fn create(self: Arc<Self>, _name: &str, _type_: StatMode) -> Option<Arc<Ext4Dentry>> {
        todo!()
    }    

    fn unlink(self: Arc<Self>, _name: &str) -> bool {
        //self.fs.ext4.ext4_file_remove(self.ino, name).is_ok()
        unimplemented!()
    }

    fn link(self: Arc<Self>, _name: &str, _target: Arc<Ext4Dentry>) -> bool {
        //self.fs.ext4.ext4_link(parent, child, name, name_len);
        todo!()
    }

    fn rename(self: Arc<Self>, _old_name: &str, _new_name: &str) -> bool {
        todo!()
    }

    fn mkdir(self: Arc<Self>, _name: &str) -> bool {
        //self.fs.ext4.ext4_dir_mk(self.ino, name).is_ok()
        unimplemented!()
    }

    fn rmdir(self: Arc<Self>, _name: &str) -> bool {
        //self.fs.ext4.ext4_dir_remove(self.ino, name).is_ok()
        unimplemented!()
    }

    fn ls(&self) -> Vec<String> {
        // self.fs
        //     .ext4
        //     .read_dir_entry(self.ino as u64)
        //     .iter()
        //     .map(|x| x.get_name())
        //     .collect()
        unimplemented!()
    }

    fn read_at(&self, _offset: usize, _buf: UserBuffer) -> usize {
        // let mut file = Ext4File::new();
        // file.inode = self.ino;
        // file.fpos = offset;
        // file.fsize = offset as u64;
        // let mut read_size = 0;
        // let _ = self
        //     .fs
        //     .ext4
        //     .ext4_file_read(&mut file, buf, buf.len(), &mut read_size);
        // read_size
        0
    }

    fn write_at(&self, _offset: usize, _buf: UserBuffer) -> usize {
        // let inode_ref = Ext4InodeRef::get_inode_ref(Arc::downgrade(&self.fs.ext4), self.ino);
        // let mut file = Ext4File::new();
        // file.fpos = offset;
        // file.fsize = inode_ref.inner.inode.inode_get_size();
        // self.fs.ext4.ext4_file_write(&mut file, buf, buf.len());
        // buf.len()
        0
    }
    pub fn get_ino(&self) -> usize {
        self.ino
    }
    pub fn superblock(&self) -> Arc<Ext4SuperBlock> {
        Arc::clone(&self.superblock)
    }
} 

impl File for Ext4Inode {
    fn is_dir(&self) -> bool {
        self.mode == StatMode::DIR
    }
    fn read(&self, _buf: UserBuffer) -> usize {
        // // TODO: 暂时不考虑 pos file!(), line!()
        // let mut inner = self.inner.exclusive_access();
        // let read_size = self.read_at(inner.fpos, buf);
        // inner.fpos += read_size;
        // read_size
        0
    }
    fn readable(&self) -> bool {
        true
    }
    fn writable(&self) -> bool {
        true
    }
    fn write(&self, buf: UserBuffer) -> usize {
        // 暂时不考虑 pos
        let write_size = self.write_at(0, buf);
        write_size
    }
    fn state(&self) -> Option<Stat> {
        unimplemented!()
    }
    // fn read_all(&self) -> Vec<u8> {
    //     todo!()
    // }
    // fn hang_up(&self) -> bool {
    //     todo!()
    // }
}
