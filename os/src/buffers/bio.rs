// //! 用于ext4_rs与easyfs的virtio兼容的块缓存层
// //! 
// use core::num::NonZeroUsize;
// //use crate::board::BlockDeviceImpl;
// use crate::config::{BLOCK_SIZE, IO_BLOCK_SIZE};
// //use crate::fs::ext4::Ext4Device;
// use alloc::sync::Arc;
// use lazy_static::*;
// use spin::Mutex;
// use lru::LruCache;
// use alloc::vec;
// use alloc::vec::Vec;

// use crate::drivers::BLOCK_DEVICE;

// // pub trait BlockDevice: Send + Sync + Any {
// //     fn read_offset(&self, offset: usize) -> Vec<u8>;
// //     fn write_offset(&self, offset: usize, data: &[u8]);
// // }


// /// Trait for block devices
// /// which reads and writes data in the unit of blocks
// use crate::fs::BlockDevice;

// /// Ext4BlockCache
// pub struct Ext4BlockCache {
//     /// underlying block id
//     id: usize,
//     /// cached block data
//     data: Vec<u8>,
//     /// underlying block device
//     dev: Arc<dyn BlockDevice>,
//     /// whether the block is dirty
//     dirty: bool,
// }

// impl Ext4BlockCache {
//     /// new
//     pub fn new(id: usize, dev: Arc<dyn BlockDevice>) -> Self {
//         let mut data = vec![0u8; IO_BLOCK_SIZE];
//         dev.read_block(id, &mut data);
//         Self {
//             data,
//             id,
//             dev,
//             dirty: false,
//         }
//     }
//     /// Get the address of an offset inside the cached block data
//     fn addr_of_offset(&self, off: usize) -> usize {
//         // C 语言描述
//         // uintptr_t addr_of_offset(const struct YourStruct* self, size_t off) {
//         //     return (uintptr_t)&(self->cache[off]);
//         // }
//         &self.data[off] as *const _ as usize
//     }
//     /// 获取ext4磁盘块缓存的可变引用
//     pub fn mut_ref<T>(&mut self, off: usize) -> &mut T
//     where
//         T: Sized,
//     {
//         assert!(off + core::mem::size_of::<T>() <= BLOCK_SIZE);
//         self.dirty = true; //获取可变引用时就认为盘块一定会被修改
//         let addr = self.addr_of_offset(off);
//         unsafe { &mut *(addr as *mut T) }
//     }
//     /// 获取ext4磁盘块缓存的普通引用
//     pub fn get_ref<T>(&self, off: usize) -> &T
//     where
//         T: Sized,
//     {
//         assert!(off + core::mem::size_of::<T>() <= BLOCK_SIZE);
//         let addr = self.addr_of_offset(off);
//         unsafe { &*(addr as *const T) }
//     }

//     ///依照偏移读块缓存
//     pub fn read<T, V>(&self, off: usize, f: impl FnOnce(&T) -> V) -> V {
//         f(self.get_ref(off))
//     } 
 
//     ///依照偏移写块缓存 
//     pub fn write<T, V>(&mut self, off: usize, f: impl FnOnce(&mut T) -> V) -> V {
//         //类型转换性处理
//         f(self.mut_ref(off))
//     }

//     ///写回磁盘
//     pub fn write_sync(&mut self) {
//         if self.dirty {
//             // 脏数据写回磁盘
//             self.dev.write_block(self.id, &self.data);
//             self.dirty = false;
//         }
//     }
// }

// impl Drop for Ext4BlockCache {
//     fn drop(&mut self) {
//         self.write_sync()
//     }
// }

// /// 使用LruCache库的队列wrapper
// pub struct Ext4BlockCacheMgr {
//     queue: LruCache<usize, Arc<Mutex<Ext4BlockCache>>>,
// }

// impl Ext4BlockCacheMgr {
//     /// new()
//     pub fn new() -> Self {
//         // 此处设置Lru缓存的大小 NonZeroUsize::new(?)
//         let capacity = NonZeroUsize::new(8192).unwrap();
//         Self {
//             queue: LruCache::new(capacity),
//         }
//     }
//     /// get_by_id()
//     pub fn get_by_id(
//         &mut self,
//         id: usize,
//         device: Arc<dyn BlockDevice>,
//     ) -> Arc<Mutex<Ext4BlockCache>> {
//         if let Some(block) = self.queue.get(&id) {
//             block.clone()
//         } else {
//             // load block into mem and push in
//             let cache = Arc::new(Mutex::new(Ext4BlockCache::new(
//                 id,
//                 Arc::clone(&device),
//             )));
//             self.queue.push(id, Arc::clone(&cache));
//             cache
//         }
//     }
// }

// lazy_static! {
//     /// The global block cache manager
//     pub static ref EXT4_BLOCK_CACHE_MGR: Mutex<Ext4BlockCacheMgr> =
//         Mutex::new(Ext4BlockCacheMgr::new());
// }

// /// Get the block cache corresponding to the given block id and block device
// pub fn bio_get_block_cache(
//     id: usize,
//     device: Arc<dyn BlockDevice>,
// ) -> Arc<Mutex<Ext4BlockCache>> {     // ----------------------------进度条-----------------------------------
//     EXT4_BLOCK_CACHE_MGR
//         .lock()
//         .get_by_id(id, device)
// }
// /// Sync all block cache to block device
// pub fn bio_write_back_all() {
//     let manager = EXT4_BLOCK_CACHE_MGR.lock();
//     for (_, cache) in manager.queue.iter() {
//         cache.lock().write_sync();
//     }
// }

// // lazy_static!{
// //     pub static ref BLOCK_DEVICE_TEST: Arc<dyn BlockDevice> = Arc::new(BlockDeviceImpl::new());
// // }

// /// bio模块测试
// #[allow(unused)]
// pub fn bio_unit_tests() {
//     // let mut kernel_space = KERNEL_SPACE.exclusive_access();
//     // let mid_text: VirtAddr = ((stext as usize + etext as usize) / 2).into();
//     // let mid_rodata: VirtAddr = ((srodata as usize + erodata as usize) / 2).into();
//     // let mid_data: VirtAddr = ((sdata as usize + edata as usize) / 2).into();
//     // assert!(!kernel_space
//     //     .page_table
//     //     .translate(mid_text.floor())
//     //     .unwrap()
//     //     .writable(),);
//     // assert!(!kernel_space
//     //     .page_table
//     //     .translate(mid_rodata.floor())
//     //     .unwrap()
//     //     .writable(),);
//     // assert!(!kernel_space
//     //     .page_table
//     //     .translate(mid_data.floor())
//     //     .unwrap()
//     //     .executable(),);
    

//     let dev = Some(BLOCK_DEVICE.clone());
//     //let ext4fs = Arc::new(Ext4Device::new(dev.unwrap()));
    
//     // block_device.clone()
//     //let device = BLOCK_DEVICE.clone();
//     let blk_cache = bio_get_block_cache(0, dev.unwrap());
//     blk_cache.lock().read(0, |num: &u32|{
//         println!("u32: {:?}", num);
//         //Ok(())
//         *num
//     });

//     println!("bio_unit_tests passed!");
// }