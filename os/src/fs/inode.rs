//! `Arc<Inode>` -> `OSInodeInner`: In order to open files concurrently
//! we need to wrap `Inode` into `Arc`,but `Mutex` in `Inode` prevents
//! file systems from being accessed simultaneously
//!
//! `UPSafeCell<OSInodeInner>` -> `OSInode`: for static `ROOT_INODE`,we
//! need to wrap `OSInodeInner` into `UPSafeCell`
use super::{File, Stat, StatMode};
use crate::drivers::BLOCK_DEVICE;
use crate::task::{current_process, current_task};
use crate::{ext4::inode::Ext4Inode};
use crate::mm::UserBuffer;
use crate::sync::UPSafeCell;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::*;
use lazy_static::*;
use crate::println;
use super::defs::OpenFlags;
use alloc::string::String;
use spin::once::Once;
use crate::ext4::{Ext4Dentry, Ext4SuperBlock};
use crate::alloc::string::ToString;
use crate::ext4::superblock::init_root_dentry;

/// inode in memory
/// A wrapper around a filesystem inode
/// to implement File trait atop
pub struct OSInode {
    readable: bool,
    writable: bool,
    inner: UPSafeCell<OSInodeInner>,
}
/// The OS inode inner in 'UPSafeCell'
pub struct OSInodeInner {
    offset: usize,
    inode: Arc<Ext4Inode>,
}

//impl OSInode {
    // /// create a new inode in memory
    // pub fn new(readable: bool, writable: bool, inode: Arc<Ext4Inode>) -> Self {
    //     Self {
    //         readable,
    //         writable,
    //         inner: unsafe { UPSafeCell::new(OSInodeInner { offset: 0, inode }) },
    //     }
    // }
    // /// read all data from the inode
    // pub fn read_all(&self) -> Vec<u8> {
    //     let mut inner = self.inner.exclusive_access();
    //     // debug!("Reading all data from inode with id: {}", inner.inode.inode_id());
    //     // let mut buffer: Vec<u8> = Vec::with_capacity(512);
    //     // buffer.resize(512, 0);
    //     // can be written more efficiently
    //     let mut buffer = [0u8; 512];
    //     let mut v: Vec<u8> = Vec::new();
    //     loop {
    //         let len = inner.inode.read_at(inner.offset, &mut buffer);
    //         if len == 0 {
    //             break;
    //         }
    //         inner.offset += len;
    //         v.extend_from_slice(&buffer[..len]);
    //     }
    //     v
    // }
//}

lazy_static! {
    pub static ref ROOT_DENTRY: Once<Arc<Ext4Dentry>> = Once::new();
}

pub fn init() {
    // 直接创建 Ext4 文件系统实例
    let ext4_fs = Ext4SuperBlock::mount(BLOCK_DEVICE.clone());
    // 挂载根文件系统
    let root_dentry = init_root_dentry(ext4_fs.clone());
    
    // 设置全局根目录
    ROOT_DENTRY.call_once(|| root_dentry);
}

pub fn get_root_dentry() -> Arc<Ext4Dentry> {
    ROOT_DENTRY.get().unwrap().clone()
}

/// List all apps in the root directory
pub fn list_apps() {
    // println!("/**** APPS ****");
    // debug!("Listing apps in root directory:");
    // for app in ROOT_INODE.ls() {
    //     println!("{}", app);
    // }
    // println!("**************/");
}

impl OpenFlags {
    /// Do not check validity for simplicity
    /// Return (readable, writable)
    pub fn read_write(&self) -> (bool, bool) {
        if self.is_empty() {
            (true, false)
        } else if self.contains(Self::O_WRONLY) {
            (false, true)
        } else {
            (true, true)
        }
    }
}

// /// Open a file
// pub fn open_file(name: &str, flags: OpenFlags) -> Option<Arc<dyn File>> {
//     let (readable, writable) = flags.read_write();
//     if flags.contains(OpenFlags::CREATE) {
//         if let Some(inode) = ROOT_INODE.find(name) {
//             // clear size
//             inode.clear();
//             Some(Arc::new(OSInode::new(readable, writable, inode)))
//         } else {
//             // create file
//             ROOT_INODE
//                 .create(name)
//                 .map(|inode| Arc::new(OSInode::new(readable, writable, inode)))
//         }
//     } else {
//         ROOT_INODE.find(name).map(|inode| {
//             if flags.contains(OpenFlags::TRUNC) {
//                 inode.clear();
//             }
//             Arc::new(OSInode::new(readable, writable, inode))
//         })
//     }
// }

// impl File for OSInode {
//     fn readable(&self) -> bool {
//         self.readable
//     }
//     fn writable(&self) -> bool {
//         self.writable
//     }
//     fn read(&self, mut buf: UserBuffer) -> usize {
//         let mut inner = self.inner.exclusive_access();
//         debug!("Reading from inode with id: {}", inner.inode.inode_id());
//         let mut total_read_size = 0usize;
//         for slice in buf.buffers.iter_mut() {
//             let read_size = inner.inode.read_at(inner.offset, *slice);
//             if read_size == 0 {
//                 break;
//             }
//             inner.offset += read_size;
//             total_read_size += read_size;
//         }
//         total_read_size
//     }
//     fn write(&self, buf: UserBuffer) -> usize {
//         let mut inner = self.inner.exclusive_access();
//         debug!("Writing to inode with id: {}", inner.inode.inode_id());
//         let mut total_write_size = 0usize;
//         for slice in buf.buffers.iter() {
//             let write_size = inner.inode.write_at(inner.offset, *slice);
//             assert_eq!(write_size, slice.len());
//             inner.offset += write_size;
//             total_write_size += write_size;
//         }
//         total_write_size
//     }

//     fn state(&self) -> Option<Stat> {
//         let inode = &self.inner.exclusive_access().inode;
//         let mode = if inode.is_dir() {
//             StatMode::DIR
//         } else if inode.is_file() {
//             StatMode::FILE
//         } else {
//             StatMode::NULL
//         };
//         Some(Stat {
//             dev: 0,
//             ino: inode.inode_id() as u64,
//             mode,
//             nlink: inode.links_count() as u32,
//             pad: [0; 7],
//         })
//     }
// }

// /// Unlink a file
// pub fn unlink_at(path: &str) -> isize {
//     let Some(file) = ROOT_INODE.remove(path) else {
//         return -1;
//     };

//     if file.links_count() == 0 {
//         file.dealloc_resource();
//     }
//     0
// }

// /// Link a file
// pub fn link_at(old_name: &str, new_name: &str) -> isize {
//     let Some(file) = ROOT_INODE.find(old_name) else {
//         return -1;
//     };
//     if file.is_dir() {
//         return -1;
//     }
//     let inode = file.inode_id();
//     if ROOT_INODE.add_dirent(new_name, inode).is_none() {
//         return -1;
//     }
//     0
// }


pub fn create_file(path:&str, type_: StatMode) -> Option<Arc<Ext4Dentry>>{
    if let Some(inode) = path_to_dentry(path){
        return Some(inode);
    }
    let mut name = String::new();
    let parent = path_to_father_dentry(path,&mut name)?;
    let dentry = parent.create(name.as_str(),type_).unwrap();
    if type_ == StatMode::DIR {
        let _current = dentry.find_dentry_create(".", StatMode::DIR);
        //let mut res = dentry.link(&current);
        // if let Err(e) = res{
        //     return Err(e);
        // }
        let _to_parent = dentry.find_dentry_create("..", StatMode::DIR);
        //res = parent.link(&to_parent); 
        // if let Err(e) = res{
        //     return Err(e);
        // }
    }
    return Some(dentry);
}
///Open file with flags
pub fn open_file(_path: &str, _flags: OpenFlags) -> Option<Arc<dyn File>>{//还需增加对设备文件的支持
    unimplemented!()
    // let ret;
    // if flags.contains(OpenFlags::O_CREAT) {// create file
    //     let dentry = create_file(path, StatMode::FILE)?;
    //     //dentry.get_inode().unwrap().clear();
    //     unimplemented!();
    //     ret = dentry.open(flags);
    // } else {
    //     let dentry = path_to_dentry(path)?;
    //     if dentry.is_dir() && ((flags.bits()&OpenFlags::O_RDONLY.bits()) != OpenFlags::O_RDONLY.bits()){
    //         return None;
    //         //return Err(SysError::EACCES);
    //     }
    //     if flags.contains(OpenFlags::O_TRUNC) && dentry.is_file(){
    //         dentry.get_inode().unwrap().clear();
    //     }
    //     ret = dentry.open(flags);
    // }  
    // Ok(ret)
}

fn skipelem<'a>(path: &'a str, name: &'a mut String) -> Option<&'a str> {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return None;
    }

    let (elem, rest) = match path.find('/') {
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None => (path, ""),
    };

    *name = elem.to_string();
    Some(rest)
}

fn path_to_dirent_(path: &str, to_father: bool, name: &mut String) -> Option<Arc<Ext4Dentry>> {
    // 确定起始目录
    let mut dentry = if path.starts_with('/') {
        get_root_dentry()
    } else {
        current_process()
            .inner_exclusive_access().cwd.clone()
            //.unwrap_or_else(get_root_dentry)
    };
    let mut current = path;
    let mut current_name = name.clone();
    while let Some(new_path) = skipelem(current, &mut current_name) {
        current = new_path;
        
        match current_name.as_str() {
            "." => continue,
            ".." => {
                //dentry = dentry.get_father().ok_or(SysError::ENOENT)?;
                dentry = dentry.get_father().expect("Failed to get parent directory");
                continue;
            }
            _ => {}
        }
        
        // 如果只需要父目录且这是最后一部分
        if to_father && current.is_empty() {
            return Some(dentry);
        }
        
        dentry = dentry.lookup(&current_name)?;
    }
    
    Some(dentry)
}

/// 从路径获取目录项
pub fn path_to_dentry(path: &str) -> Option<Arc<Ext4Dentry>> {
    let mut name = String::new();
    path_to_dirent_(path, false, &mut name)
}

/// 从路径获取父目录项，并将最后一级名称存入name
pub fn path_to_father_dentry(path: &str, name: &mut String) -> Option<Arc<Ext4Dentry>> {
    path_to_dirent_(path, true, name)
}