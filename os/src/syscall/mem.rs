//! memory related syscall

use log::debug;

use super::{MmapFlags, MmapProt};
use crate::{
    config::PAGE_SIZE,
    fs::{File, OpenFlags},
    mm::{
        insert_bad_address, is_bad_address, remove_bad_address, shm_attach, shm_create, shm_drop,
        shm_find, translated_refmut, MapPermission, ShmFlags, VirtAddr,
    },
    task::{current_process, current_task},
    utils::{page_round_up, SysErrNo, SyscallRet},
};

// get mempolicy
//由于目前只有单核，所以这个暂时只需要返回0
pub fn sys_getmempolicy(
    _mode: *mut i32,
    _nodemask: *mut usize,
    _maxnode: usize,
    _addr: *const u8,
    _flags: usize,
) -> isize {
    // let process = current_process();
    // let inner = process.inner_exclusive_access();
    // let token = inner.get_user_token();
    // drop(inner);
    // drop(process);
    // // 1. 检查指针是否位于用户空间（略）

    // // 2. 单节点 => 永远只有 MPOL_DEFAULT
    // if !mode.is_null() {
    //     *translated_refmut(token, mode) = 0;
    // }

    // // 3. nodemask 仅有一个节点 0
    // if !nodemask.is_null() {
    //     // 用户给的 maxnode 必须 ≥ 1
    //     if maxnode < 1 {
    //         return SysErrNo::EINVAL as isize; // -EINVAL
    //     }
    //     // 把 bit0 设为 1，其余清 0
    //     *translated_refmut(token, nodemask) = 0x1;
    // }
    0
}

//shmget
pub fn sys_shmget(key: i32, size: usize, shmflag: i32) -> isize {
    const IPC_PRIVATE: i32 = 0;
    // 忽略权限位
    let flags = ShmFlags::from_bits(shmflag & !0x1ff).unwrap();
    match key {
        IPC_PRIVATE => shm_create(size) as isize,
        key if key > 0 => {
            if shm_find(key as usize) {
                if flags.contains(ShmFlags::IPC_CREAT | ShmFlags::IPC_EXCL) {
                    SysErrNo::EEXIST as isize
                } else {
                    key as usize as isize
                }
            } else {
                if flags.contains(ShmFlags::IPC_CREAT) {
                    shm_create(size) as isize
                } else {
                    SysErrNo::ENOENT as isize
                }
            }
        }
        _ => SysErrNo::ENOENT as isize,
    }
}

pub fn sys_shmat(shmid: i32, shmaddr: usize, shmflag: i32) -> isize {
    let mut permission = MapPermission::U | MapPermission::R;
    if shmflag == 0 {
        permission |= MapPermission::W | MapPermission::X
    } else {
        let shmflg = ShmFlags::from_bits(shmflag).unwrap();
        if shmflg.contains(ShmFlags::SHM_EXEC) {
            permission |= MapPermission::X;
        }
        if !shmflg.contains(ShmFlags::SHM_RDONLY) {
            permission |= MapPermission::W;
        }
    }

    match shmid {
        key if key < 0 => SysErrNo::EINVAL as isize,
        _ => shm_attach(shmid as usize, shmaddr, permission),
    }
}

pub fn sys_shmctl(shmid: i32, cmd: i32, _buf: usize) -> isize {
    const IPC_RMID: i32 = 0;
    match cmd {
        IPC_RMID => {
            shm_drop(shmid as usize);
            0
        }
        _ => {
            panic!("[sys_shmctl] unsupport cmd");
        }
    }
}

/// mmap syscall ref: https://man7.org/linux/man-pages/man2/mmap.2.html
/// `flags` determins whether updates mapping,
/// `fd` as file descriptor, `off` as offset in file
pub fn sys_mmap(addr: usize, len: usize, port: u32, flags: u32, fd: usize, off: usize) -> isize {
    debug!(
        "[sys_mmap] addr={:#x}, len={:#x}, port={:#x}, flags={:#x}, fd={}, off={:#x}",
        addr, len, port, flags, fd, off
    );
    if flags == 0 {
        return SysErrNo::EINVAL as isize;
    }
    let flags = MmapFlags::from_bits(flags).unwrap();
    if fd == usize::MAX && !flags.contains(MmapFlags::MAP_ANONYMOUS) {
        return SysErrNo::EBADF as isize;
    }
    if len == 0 {
        return SysErrNo::EINVAL as isize;
    }
    let mmap_prot = MmapProt::from_bits(port).unwrap();
    let permission: MapPermission = mmap_prot.into();
    if flags.contains(MmapFlags::MAP_FIXED) && addr == 0 {
        return SysErrNo::EPERM as isize;
    }
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let len = page_round_up(len);
    if fd == usize::MAX {
        debug!("fd = usize max");
        let ret = inner
            .memory_set
            .mmap(addr, len, permission, flags, None, usize::MAX);
        return ret as isize;
    }
    if flags.contains(MmapFlags::MAP_ANONYMOUS) {
        // anonymous mapping
        debug!("anonymous map");
        let ret = inner
            .memory_set
            .mmap(0, 1, MapPermission::empty(), flags, None, usize::MAX);
        insert_bad_address(ret);
        debug!("[sys_mmap] bad address is {:x}", ret);
        return ret as isize;
    }
    debug!("sys mmap, not in anonymous mmap");
    // file mapping
    let inode = inner.fd_table.get(fd);
    let file = match inode.file() {
        Ok(n) => n,
        Err(_) => return SysErrNo::EBADF as isize, //?
    };
    #[cfg(target_arch = "riscv64")]
    if (permission.contains(MapPermission::R) && !file.readable())
        || (permission.contains(MapPermission::W) && !file.writable())
        || (mmap_prot != MmapProt::PROT_NONE && inode.flags.contains(OpenFlags::O_WRONLY))
    {
        //如果需要读/写/执行方式映射，必须要求文件可读
        return SysErrNo::EACCES as isize;
    }
    #[cfg(target_arch = "loongarch64")]
    if (permission.contains(MapPermission::NR) && file.readable())
        || (permission.contains(MapPermission::W) && !file.writable())
        || (mmap_prot != MmapProt::PROT_NONE && inode.flags.contains(OpenFlags::O_WRONLY))
    {
        //如果需要读/写/执行方式映射，必须要求文件可读
        return SysErrNo::EACCES as isize;
    }
    let ret = inner
        .memory_set
        .mmap(addr, len, permission, flags, Some(file), off);
    info!(
        "[sys_mmap] alloc addr={:#x}, return from MemorySetInner mmap",
        ret
    );
    return ret as isize;
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(addr: usize, len: usize) -> isize {
    debug!("[sys_munmap] addr={:#x}, len={:#x}", addr, len);
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let len = page_round_up(len);
    if is_bad_address(addr) {
        remove_bad_address(addr);
    }
    inner.memory_set.munmap(addr, len)
}

// change data segment size
pub fn sys_brk(path: usize) -> isize {
    debug!("in sys brk, the path is : {}", path);
    let process = current_process();
    let fromer_addr: usize = process.change_program_brk(0);
    debug!("in sys brk, the fromer addr is : {}", fromer_addr);
    if path == 0 {
        return fromer_addr as isize;
    }
    let grow_size: isize = (path - fromer_addr) as isize;
    debug!("in sys brk, the grow size is : {}", grow_size);
    process.change_program_brk(grow_size) as isize

    // if let Some(result) = inner.res.as_mut().unwrap().change_program_brk(0) {
    //     if path == 0 {
    //         return result;
    //     }
    //     let grow_size: isize = (brk_addr - fromer_addr) as isize;

    //     debug!("to returning result : {}", result as isize);
    //     result as isize
    // } else {
    //     -1
    // }
}

pub fn sys_mprotect(addr: usize, len: usize, prot: u32) -> isize {
    if addr == 0 {
        return SysErrNo::ENOMEM as isize;
    }

    if (addr % PAGE_SIZE != 0) || (len % PAGE_SIZE != 0) {
        log::warn!("sys_mprotect: not align");
        return SysErrNo::EINVAL as isize;
    }
    let map_perm: MapPermission = MmapProt::from_bits(prot).unwrap().into();

    debug!(
        "[sys_mprotect] addr is {:x}, len is {:#x}, map_perm is {:?}",
        addr, len, map_perm
    );

    let process = current_process();
    let inner = process.inner_exclusive_access();
    let memory_set = inner.memory_set.get_mut();
    let start_vpn = VirtAddr::from(addr).floor();
    let end_vpn = VirtAddr::from(addr + len).ceil();
    //修改各段的mappermission
    memory_set.mprotect(start_vpn, end_vpn, map_perm);
    return 0;
}
