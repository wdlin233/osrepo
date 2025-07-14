use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use spin::{Lazy, Mutex};

use crate::{
    config::PAGE_SIZE,
    task::{current_process, current_task},
    utils::{SysErrNo, SyscallRet},
};

use super::{frame_alloc, FrameTracker, MapPermission};

bitflags! {
    pub struct ShmFlags: i32 {
        ///
        const SHM_R = 0o400;
        ///
        const SHM_W = 0o200;
        /// Create a new segment. If this flag is not used, then shmget() will find the segment associated with key and check to see if the user has permission to access the segment.
        const IPC_CREAT = 0o1000;
        /// This flag is used with IPC_CREAT to ensure that this call creates the segment.  If the segment already exists, the call fails.
        const IPC_EXCL = 0o2000;

        const SHM_RDONLY = 0o10000;
        // const SHM_RND    = 0o20000;
        // const SHM_REMAP  = 0o40000;
        const SHM_EXEC   = 0o100000;
    }
}

pub struct Shm {
    pages: Vec<Arc<FrameTracker>>,
}

impl Shm {
    pub fn new(num: usize) -> Self {
        Self {
            pages: { (0..num).map(|_| Arc::new(frame_alloc().unwrap())).collect() },
        }
    }
}

pub struct ShmManager {
    next_key: usize,
    map: BTreeMap<usize, Shm>,
}

impl ShmManager {
    pub fn new() -> Self {
        Self {
            next_key: 1,
            map: BTreeMap::new(),
        }
    }
}

pub static SHM_MANAGER: Lazy<Mutex<ShmManager>> = Lazy::new(|| Mutex::new(ShmManager::new()));

/// 创建共享内存段，返回共享内存段标识符
///
/// `size` 为共享内存段的大小
pub fn shm_create(size: usize) -> usize {
    let num = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    let mut manager = SHM_MANAGER.lock();
    let key = manager.next_key;
    manager.map.insert(key, Shm::new(num));
    manager.next_key += 1;
    key
}

/// 判断共享内存段是否存在
pub fn shm_find(key: usize) -> bool {
    let manager = SHM_MANAGER.lock();
    manager.map.get(&key).is_some()
}

/// 将共享内存段映射到用户地址空间上
///
/// ## 参数
/// - `key` 为共享内存段标识符
/// - `addr` 为插入的起始地址，为 0 表示随机插入
pub fn shm_attach(key: usize, addr: usize, map_perm: MapPermission) -> isize {
    let manager = SHM_MANAGER.lock();
    if let Some(shm) = manager.map.get(&key) {
        let process = current_process();
        let inner = process.inner_exclusive_access();
        let size = shm.pages.len() * PAGE_SIZE;
        inner
            .memory_set
            .shm(addr, size, map_perm, shm.pages.clone()) as isize
    } else {
        SysErrNo::EINVAL as isize
    }
}

pub fn shm_drop(key: usize) {
    SHM_MANAGER.lock().map.remove(&key);
}
