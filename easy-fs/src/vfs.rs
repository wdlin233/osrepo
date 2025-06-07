//! index node(inode, namely file control block) layer
//!
//! The data struct and functions for the inode layer that service file-related system calls
//!
//! NOTICE: The difference between [`Inode`] and [`DiskInode`]  can be seen from their names: DiskInode in a relatively fixed location within the disk block, while Inode Is a data structure placed in memory that records file inode information.
use super::{
    block_cache_sync_all, get_block_cache, BlockDevice, DirEntry, DiskInode, DiskInodeType,
    EasyFileSystem, DIRENT_SZ,
};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::{Mutex, MutexGuard};
use log::{debug, trace};

/// Inode struct in memory
pub struct Inode {
    /// The block id of the inode
    block_id: usize,
    /// The offset of the inode in the block
    block_offset: usize,
    /// The file system
    fs: Arc<Mutex<EasyFileSystem>>,
    /// The block device
    block_device: Arc<dyn BlockDevice>,
    inode_id: u32,
}

impl Inode {
    /// Create a new Disk Inode
    ///
    /// We should not acquire efs lock here.
    pub fn new(
        block_id: u32,
        block_offset: usize,
        fs: Arc<Mutex<EasyFileSystem>>,
        block_device: Arc<dyn BlockDevice>,
        inode_id: u32,
    ) -> Self {
        Self {
            block_id: block_id as usize,
            block_offset,
            fs,
            block_device,
            inode_id,
        }
    }
    /// Call a function over a disk inode to read it
    fn read_disk_inode<V>(&self, f: impl FnOnce(&DiskInode) -> V) -> V {
        get_block_cache(self.block_id, Arc::clone(&self.block_device))
            .lock()
            .read(self.block_offset, f)
    }
    /// modify the content of the disk inode on disk with 'f' function
    fn modify_disk_inode<V>(&self, f: impl FnOnce(&mut DiskInode) -> V) -> V {
        get_block_cache(self.block_id, Arc::clone(&self.block_device))
            .lock()
            .modify(self.block_offset, f)
    }
    /// Find inode under a disk inode by name
    fn find_inode_id(&self, name: &str, disk_inode: &DiskInode) -> Option<u32> {
        // assert it is a directory
        assert!(disk_inode.is_dir());
        //trace!("find inode id: {}", self.inode_id);
        let file_count = (disk_inode.size as usize) / DIRENT_SZ;
        //trace!("file count: {}", file_count);
        let mut dirent = DirEntry::empty();
        for i in 0..file_count {
            //debug!("dirent index: {}", i);
            assert_eq!(
                disk_inode.read_at(DIRENT_SZ * i, dirent.as_bytes_mut(), &self.block_device,),
                DIRENT_SZ,
            );
            //debug!("dirent name: {}", dirent.name());
            if dirent.name() == name {
                return Some(dirent.inode_id() as u32);
            }
        }
        None
    }
    /// Find inode under current inode by name
    pub fn find(&self, name: &str) -> Option<Arc<Inode>> {
        let fs = self.fs.lock();
        self.read_disk_inode(|disk_inode| {
            self.find_inode_id(name, disk_inode).map(|inode_id| {
                let (block_id, block_offset) = fs.get_disk_inode_pos(inode_id);
                Arc::new(Self::new(
                    block_id,
                    block_offset,
                    self.fs.clone(),
                    self.block_device.clone(),
                    inode_id,
                ))
            })
        })
    }
    /// Increase the size of a disk inode
    fn increase_size(
        &self,
        new_size: u32,
        disk_inode: &mut DiskInode,
        fs: &mut MutexGuard<EasyFileSystem>,
    ) {
        if new_size < disk_inode.size {
            return;
        }
        let blocks_needed = disk_inode.blocks_num_needed(new_size);
        let mut v: Vec<u32> = Vec::new();
        for _ in 0..blocks_needed {
            v.push(fs.alloc_data());
        }
        disk_inode.increase_size(new_size, v, &self.block_device);
    }
    /// create a file with 'name' in the root directory
    pub fn create(&self, name: &str) -> Option<Arc<Inode>> {
        let mut fs = self.fs.lock();
        let op = |root_inode: &mut DiskInode| {
            // assert it is a directory
            assert!(root_inode.is_dir());
            // has the file been created?
            self.find_inode_id(name, root_inode)
        };
        if self.modify_disk_inode(op).is_some() {
            return None;
        }
        // create a new file
        // alloc a inode with an indirect block
        let new_inode_id = fs.alloc_inode();
        // initialize inode
        let (new_inode_block_id, new_inode_block_offset) = fs.get_disk_inode_pos(new_inode_id);
        get_block_cache(new_inode_block_id as usize, Arc::clone(&self.block_device))
            .lock()
            .modify(new_inode_block_offset, |new_inode: &mut DiskInode| {
                new_inode.initialize(DiskInodeType::File);
            });
        self.modify_disk_inode(|root_inode| {
            // append file in the dirent
            let file_count = (root_inode.size as usize) / DIRENT_SZ;
            let new_size = (file_count + 1) * DIRENT_SZ;
            // increase size
            self.increase_size(new_size as u32, root_inode, &mut fs);
            // write dirent
            let dirent = DirEntry::new(name, new_inode_id);
            root_inode.write_at(
                file_count * DIRENT_SZ,
                dirent.as_bytes(),
                &self.block_device,
            );
        });

        let (block_id, block_offset) = fs.get_disk_inode_pos(new_inode_id);
        block_cache_sync_all();
        // return inode
        Some(Arc::new(Self::new(
            block_id,
            block_offset,
            self.fs.clone(),
            self.block_device.clone(),
            new_inode_id,
        )))
        // release efs lock automatically by compiler
    }
    /// List inodes under current inode
    pub fn ls(&self) -> Vec<String> {
        let _fs = self.fs.lock();
        self.read_disk_inode(|disk_inode| {
            debug!("ls inode: {}", self.inode_id);
            let file_count = (disk_inode.size as usize) / DIRENT_SZ;
            let mut v: Vec<String> = Vec::new();
            for i in 0..file_count {
                // debug!("dirent index: {}", i);
                let mut dirent = DirEntry::empty();
                assert_eq!(
                    disk_inode.read_at(i * DIRENT_SZ, dirent.as_bytes_mut(), &self.block_device,),
                    DIRENT_SZ,
                );
                v.push(String::from(dirent.name()));
            }
            v
        })
    }
    /// Read data from current inode
    pub fn read_at(&self, offset: usize, buf: &mut [u8]) -> usize {
        let _fs = self.fs.lock();
        self.read_disk_inode(|disk_inode| disk_inode.read_at(offset, buf, &self.block_device))
    }
    /// Write data to current inode
    pub fn write_at(&self, offset: usize, buf: &[u8]) -> usize {
        let mut fs = self.fs.lock();
        let size = self.modify_disk_inode(|disk_inode| {
            self.increase_size((offset + buf.len()) as u32, disk_inode, &mut fs);
            disk_inode.write_at(offset, buf, &self.block_device)
        });
        block_cache_sync_all();
        size
    }
    /// Clear the data in current inode
    pub fn clear(&self) {
        let mut fs = self.fs.lock();
        self.modify_disk_inode(|disk_inode| {
            let size = disk_inode.size;
            let data_blocks_dealloc = disk_inode.clear_size(&self.block_device);
            assert!(data_blocks_dealloc.len() == DiskInode::total_blocks(size) as usize);
            for data_block in data_blocks_dealloc.into_iter() {
                fs.dealloc_data(data_block);
            }
        });
        block_cache_sync_all();
    }
}

impl Inode {
    /// Get the inode id
    pub fn inode_id(&self) -> u32 {
        self.inode_id
    }
    /// Get the link count of the DiskInode
    pub fn links_count(&self) -> u32 {
        self.read_disk_inode(|disk_inode| disk_inode.links_count())
    }
    /// Judge if the inode is a directory
    pub fn is_dir(&self) -> bool {
        self.read_disk_inode(|disk_inode| disk_inode.is_dir())
    }
    /// Judge if the inode is a file
    pub fn is_file(&self) -> bool {
        self.read_disk_inode(|disk_inode| disk_inode.is_file())
    }
}

impl Inode {
    fn find_dirent_index(&self, name: &str) -> Option<usize> {
        self.read_disk_inode(|disk_inode| {
            assert!(disk_inode.is_dir());
            let file_count = (disk_inode.size as usize) / DIRENT_SZ;
            let mut dirent = DirEntry::empty();
            for idx in 0..file_count {
                assert_eq!(
                    disk_inode.read_at(DIRENT_SZ * idx, dirent.as_bytes_mut(), &self.block_device,),
                    DIRENT_SZ,
                );
                if dirent.name() == name {
                    return Some(idx);
                }
            }
            None
        })
    }
    /// Delete certain DirEntry from the directory
    fn swap_remove_dirent(&self, index: usize) {
        // assert it is a directory
        self.modify_disk_inode(|disk_inode| {
            assert!(disk_inode.is_dir());
            let file_count = (disk_inode.size as usize) / DIRENT_SZ;
            //trace!("file count: {}", file_count);
            let last_dirent_offset = DIRENT_SZ * (file_count - 1);
            let mut temp_dirent = DirEntry::empty();
            disk_inode.read_at(
                last_dirent_offset,
                temp_dirent.as_bytes_mut(),
                &self.block_device,
            );
            disk_inode.write_at(
                DIRENT_SZ * index, 
                temp_dirent.as_bytes(), 
                &self.block_device
            );
            // dealloc
            disk_inode.decrease_size(DIRENT_SZ as u32);
        });
    }

    /// Remove a file from the directory
    pub fn remove(&self, path: &str) -> Option<Arc<Inode>>{
        //trace!("remove file: {}", path);
        let fs = self.fs.lock();
        let op = |root_inode: &DiskInode| {
            // assert it is a directory
            assert!(root_inode.is_dir());
            // has the file been created?
            self.find_inode_id(path, root_inode)
        };
        if let Some(inode_id) = self.read_disk_inode(op){ // panic here
            // decrease links count for the inode
            let (block_id, block_offset) = fs.get_disk_inode_pos(inode_id);
            get_block_cache(block_id as usize, Arc::clone(&self.block_device))
                .lock()
                .modify(block_offset, |inode: &mut DiskInode| {
                    inode.dec_links();
                });
            block_cache_sync_all();
            // remove the dirent
            if let Some(idx) = self.find_dirent_index(path) {
                self.swap_remove_dirent(idx);
            };
            // return inode
            return Some(Arc::new(Self::new(
                block_id,
                block_offset,
                self.fs.clone(),
                self.block_device.clone(),
                inode_id, // not self.inode_id
            )));
        } else {
            return None;
        }
    }

    /// Deallocate the corresponding resouce from the disk
    pub fn dealloc_resource(&self) {
        //trace!("dealloc resource: {}", self.inode_id);
        let mut fs = self.fs.lock();
        self.modify_disk_inode(|disk_inode| {
            let size = disk_inode.size;
            let data_blocks_dealloc = disk_inode.clear_size(&self.block_device);
            assert!(data_blocks_dealloc.len() == DiskInode::total_blocks(size) as usize);
            for data_block in data_blocks_dealloc.into_iter() {
                fs.dealloc_data(data_block);
            }
        });
        fs.dealloc_inode(self.inode_id);
        block_cache_sync_all();
    }

    /// Add a new DirEntry to the directory
    pub fn add_dirent(&self, new_name: &str, old_inode_id: u32) -> Option<Arc<Inode>> {
        let mut fs = self.fs.lock();
        let op = |root_inode: &DiskInode| {
            // assert it is a directory
            assert!(root_inode.is_dir());
            // has the file been created?
            self.find_inode_id(new_name, root_inode)
        };
        if self.read_disk_inode(op).is_some() {
            return None;
        }
        // add links count for the old inode
        let (old_inode_block_id, old_inode_block_offset) = fs.get_disk_inode_pos(old_inode_id);
        get_block_cache(old_inode_block_id as usize, Arc::clone(&self.block_device))
            .lock()
            .modify(old_inode_block_offset, |old_inode: &mut DiskInode| {
                old_inode.inc_links();
            });
        // create a new DirEntry
        // with new_name and old_inode_id
        self.modify_disk_inode(|root_inode| {
            // increase size for root_inode
            let file_count = (root_inode.size as usize) / DIRENT_SZ;
            let new_size = (file_count + 1) * DIRENT_SZ;
            self.increase_size(new_size as u32, root_inode, &mut fs);
            // write dirent
            let dirent = DirEntry::new(new_name, old_inode_id);
            root_inode.write_at(
                file_count * DIRENT_SZ,
                dirent.as_bytes(),
                &self.block_device,
            );
        });
        block_cache_sync_all();
        // return inode
        let (block_id, block_offset) = fs.get_disk_inode_pos(old_inode_id);
        Some(Arc::new(Self::new(
            block_id,
            block_offset,
            self.fs.clone(),
            self.block_device.clone(),
            old_inode_id,
        )))
        // release efs lock automatically by compiler
    }
}
