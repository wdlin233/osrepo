//use crate::fs::ext4::ROOT_INO;
use crate::fs::pipe::make_pipe;
use crate::fs::{
    convert_kstat_to_statx, open, remove_inode_idx, stat, File, FileClass, FileDescriptor, Kstat, OpenFlags, Statx, StatxFlags, MAX_PATH_LEN, MNT_TABLE, NONE_MODE, SEEK_CUR, SEEK_SET
}; //::{link, unlink}

use crate::data_flow;
use crate::mm::{
    copy_to_virt, is_bad_address, safe_translated_byte_buffer, translated_byte_buffer,
    translated_refmut, translated_str, PhysAddr, UserBuffer,
};
use crate::syscall::process;
use crate::task::{current_process, current_user_token};
use crate::users::User;
use crate::utils::SyscallRet;
use crate::utils::{get_abs_path, SysErrNo};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

/// write syscall
pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    debug!("in sys write with buf: {:x?}, len: {}", buf, len);
    let process = current_process();
    debug!("current pid is :{}", process.getpid());
    let inner = process.inner_exclusive_access();
    let memory_set = inner.memory_set.clone();
    if (fd as isize) < 0 || fd >= inner.fd_table.len() {
        //return Err(SysErrNo::EBADF);
        debug!("fd len error");
        return -1;
    }
    //debug!("to check buf");
    if (buf as isize) < 0 || is_bad_address(buf as usize) || ((buf as usize) == 0 && len != 0) {
        //return Err(SysErrNo::EFAULT);
        debug!("buf error");
        return -1;
    }
    //debug!("to check len, len :{}", len);
    if (len as isize) < 0 {
        //return Err(SysErrNo::EINVAL);
        debug!("len < 0");
        return -1;
    }
    //debug!("to try get");
    if let Some(file) = &inner.fd_table.try_get(fd) {
        if let Ok(readfile) = file.file() {
            if readfile.inode.is_dir() {
                //return Err(SysErrNo::EISDIR);
                debug!("si dir");
                return -1;
            }
        }
        let file: Arc<dyn File> = file.any();
        if !file.writable() {
            //return Err(SysErrNo::EBADF);
            debug!("not writable");
            return -1;
        }
        drop(inner);
        drop(process);

        // release current task TCB manually to avoid multi-borrow
        debug!("in write,to translated byte buffer");
        let buf = UserBuffer::new(safe_translated_byte_buffer(memory_set, buf, len).unwrap());
        //debug!("to write file");
        let ret = match file.write(buf) {
            Ok(n) => n as isize,
            Err(e) => {
                info!("kernel: sys_write .. file.write error: {:?}", e);
                // return Err(SysErrNo::from(e));
                return -1;
            }
        };
        debug!("in write, to return , ret is :{}", ret);
        return ret;
    } else {
        //Err(SysErrNo::EBADF)
        return -1;
    }
}
/// read syscall
pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    debug!("in sys read");
    // let token = current_user_token();
    let process = current_process();
    debug!("current pid is :{}", process.getpid());
    let mut inner = process.inner_exclusive_access();
    let memory_set = inner.memory_set.clone();
    if fd >= inner.fd_table.len() || (fd as isize) < 0 || (buf as isize) <= 0 {
        return -1;
    }
    if let Some(file) = &inner.fd_table.try_get(fd) {
        debug!("in read try get ok");
        if let Ok(readfile) = file.file() {
            if readfile.inode.is_dir() {
                //return Err(SysErrNo::EISDIR);
                return -1;
            }
        }
        let file: Arc<dyn File> = file.any();
        if !file.readable() {
            //return Err(SysErrNo::EBADF);
            return -1;
        }
        drop(inner);
        drop(process);

        debug!("in read, to translated byte buffer");
        // release current task TCB manually to avoid multi-borrow
        let ret = file
            .read(UserBuffer::new(
                safe_translated_byte_buffer(memory_set, buf, len).unwrap(),
            ))
            .unwrap();
        debug!("in read ,to return, the ret is :{}", ret);
        ret as isize
    } else {
        //Err(SysErrNo::EBADF)
        -1
    }
}
/// open sys
pub fn sys_open(dirfd: isize, path: *const u8, flags: u32, mode: u32) -> isize {
    debug!("in sys open");
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    let path = translated_str(token, path);
    let flags = OpenFlags::from_bits(flags).unwrap();
    let mut abs_path = inner.get_abs_path(dirfd, &path);
    if abs_path == "" {
        return -1;
    }

    if abs_path == "/proc/self/stat" {
        abs_path = format!("/proc/{}/stat", process.getpid());
    }
    let inode = match open(&abs_path, flags, mode) {
        Ok(i) => i,
        Err(_) => {
            return -1;
        }
    };
    let new_fd = inner.fd_table.alloc_fd().unwrap();
    inner
        .fd_table
        .set(new_fd, FileDescriptor::new(flags, inode));

    inner.fs_info.insert(abs_path, new_fd);
    new_fd as isize
    // if let Some(dentry) = open_file(inode, path.as_str(), OpenFlags::from_bits(flags as i32).unwrap()) {
    //     let mut inner = process.inner_exclusive_access();
    //     let fd = inner.alloc_fd();
    //     let file = cast_inode_to_file(dentry.inode());
    //     inner.fd_table.try_get(fd) = file;
    //     fd as isize
    // } else {
    //     -1
    // }
    //unimplemented!()
}
/// close syscall
pub fn sys_close(fd: usize) -> isize {
    debug!("in sys close");
    let process = current_process();
    debug!("in close, pid is :{}", process.getpid());
    let inner = process.inner_exclusive_access();
    if fd >= inner.fd_table.len() || fd < 0 {
        return -1;
    }
    if inner.fd_table.try_get(fd).is_none() {
        return 0;
    }
    inner.fd_table.take(fd);
    inner.fs_info.remove(fd);
    debug!("sys close ok");
    0
}
/// pipe syscall
pub fn sys_pipe(fd: *mut u32, flags: u32) -> isize {
    let process = current_process();
    let mut inner = process.inner_exclusive_access();
    //debug!("[sys_pipe2] fd is {:x},flags is {}", fd as usize, flags);

    let mut pipe_flags = OpenFlags::empty();
    if flags == 0x80000 {
        //设置O_CLOEXEC
        pipe_flags |= OpenFlags::O_CLOEXEC;
    }

    let (read_pipe, write_pipe) = make_pipe();
    let read_fd = match inner.fd_table.alloc_fd() {
        Ok(fd) => fd,
        Err(_) => return -1,
    };
    inner.fd_table.set(
        read_fd,
        FileDescriptor::new(pipe_flags, FileClass::Abs(read_pipe)),
    );
    let write_fd = match inner.fd_table.alloc_fd() {
        Ok(fd) => fd,
        Err(_) => {
            return -1;
        }
    };
    inner.fd_table.set(
        write_fd,
        FileDescriptor::new(pipe_flags, FileClass::Abs(write_pipe)),
    );
    inner.fs_info.insert("pipe".to_string(), read_fd);
    inner.fs_info.insert("pipe".to_string(), write_fd);

    use crate::mm::{PageTable, VirtAddr};
    #[cfg(target_arch = "loongarch64")]
    use loongarch64::register::estat::{Exception, Trap};
    #[cfg(target_arch = "riscv64")]
    use riscv::register::scause::{Exception, Trap};
    let memory_set = &mut inner.memory_set.clone();
    let page_table = PageTable::from_token(memory_set.token());

    // 写入第一个 u32 (read_fd)
    let fd_ptr1 = fd as usize;
    let va1 = VirtAddr::from(fd_ptr1);
    let vpn1 = va1.floor();
    // 确保页面有效且可写
    if !page_table
        .translate(vpn1)
        .map_or(false, |pte| pte.is_valid() && pte.writable())
    {
        memory_set.lazy_page_fault(vpn1, Trap::Exception(Exception::StorePageFault));
    }
    // 获取物理地址并写入
    if let Some(pte) = page_table.translate(vpn1) {
        if pte.is_valid() && pte.writable() {
            let ppn = pte.ppn();
            let phys_addr: PhysAddr = ppn.into();
            #[cfg(target_arch = "riscv64")]
            let kernel_va = phys_addr.0 | 0x8020_0000;
            #[cfg(target_arch = "loongarch64")]
            let kernel_va = phys_addr.0 | 0x9000_0000_0000_0000;

            let read_addr = kernel_va + va1.page_offset();
            unsafe {
                *(read_addr as *mut u32) = read_fd as u32;
            }
        }
    }
    // 写入第二个 u32 (write_fd)
    let fd_ptr2 = unsafe { fd.add(1) } as usize;
    let va2 = VirtAddr::from(fd_ptr2);
    let vpn2 = va2.floor();

    // 确保页面有效且可写
    if !page_table
        .translate(vpn2)
        .map_or(false, |pte| pte.is_valid() && pte.writable())
    {
        memory_set.lazy_page_fault(vpn2, Trap::Exception(Exception::StorePageFault));
    }

    // 获取物理地址并写入
    if let Some(pte) = page_table.translate(vpn2) {
        if pte.is_valid() && pte.writable() {
            let ppn = pte.ppn();
            let phys_addr: PhysAddr = ppn.into();
            #[cfg(target_arch = "riscv64")]
            let kernel_va = phys_addr.0 | 0x8020_0000;
            #[cfg(target_arch = "loongarch64")]
            let kernel_va = phys_addr.0 | 0x9000_0000_0000_0000;

            let write_addr = kernel_va + va2.page_offset();
            unsafe {
                *(write_addr as *mut u32) = write_fd as u32;
            }
        }
    }
    0
}
/// dup syscall
pub fn sys_dup(fd: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_dup",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    let process = current_process();
    let inner = process.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table.try_get(fd).is_none() {
        return -1;
    }
    let new_fd = match inner.fd_table.alloc_fd() {
        Ok(fd) => fd,
        Err(_) => return -1,
    };
    // inner.fd_table.try_get(new_fd) = Some(Arc::new(
    //     inner
    //     .fd_table
    //     .try_get(fd)
    //     .as_ref()
    //     .unwrap()
    // )); old implementation
    let mut file = inner.fd_table.get(fd);
    file.unset_cloexec();
    inner.fd_table.set(new_fd, file);
    inner.fs_info.insert_with_glue(fd, new_fd);
    new_fd as isize
}

pub fn sys_dup3(old: usize, new: usize, flags: u32) -> isize {
    let process = current_process();
    let inner = process.inner_exclusive_access();

    if old >= inner.fd_table.len()
        || (old as isize) < 0
        || (new as isize) < 0
        || new >= inner.fd_table.get_soft_limit()
        || inner.fd_table.try_get(old).is_none()
    {
        return -1;
    }
    if inner.fd_table.len() <= new {
        inner.fd_table.resize(new + 1).unwrap();
    }

    let mut file = inner.fd_table.get(old);
    if flags == 0x800000 || flags == 0x80000 {
        file.set_cloexec();
    } else {
        file.unset_cloexec();
    }
    inner.fd_table.set(new, file);
    new as isize
}

pub fn sys_fstat(fd: usize, st: *mut Kstat) -> isize {
    debug!("in sys fast");
    let process = current_process();
    let inner = process.inner_exclusive_access();
    if fd >= inner.fd_table.len() || inner.fd_table.try_get(fd).is_none() {
        return -1;
    }
    let file = inner.fd_table.get(fd).any();
    let stat = file.fstat();
    drop(inner);
    copy_to_virt(&stat, st);
    0
    // if let Some(file) = &inner.fd_table.try_get(fd) {
    //     let file = file.clone();
    //     // release current task TCB manually to avoid multi-borrow
    //     drop(inner);
    //     let stat = file.fstat().unwrap();
    //     copy_to_virt(&stat, st);
    //     return 0
    // }
    // -1
}

pub fn sys_getcwd(buf: *const u8, size: usize) -> isize {
    let process = current_process();
    let mut inner = process.inner_exclusive_access();
    let cwdlen = inner.fs_info.cwd().len();
    if (buf as isize) < 0 || is_bad_address(buf as usize) || (size as isize) < 0 || size <= cwdlen {
        return -1;
    }
    let mut buffer =
        UserBuffer::new(safe_translated_byte_buffer(inner.memory_set.clone(), buf, size).unwrap());
    buffer.write(inner.fs_info.cwd_as_bytes());
    buf as isize
}

/// YOUR JOB: Implement linkat.
pub fn sys_linkat(_old_name: *const u8, _new_name: *const u8) -> isize {
    unimplemented!()
    // // trace!(
    // //     "kernel:pid[{}] sys_linkat(old_name: 0x{:x?}, new_name: 0x{:x?})",
    // //     current_task().unwrap().process.upgrade().unwrap().getpid(), old_name, new_name
    // // );
    // let token = current_user_token();
    // let old_path = translated_str(token, old_name);
    // let new_path = translated_str(token, new_name);
    // //ROOT_INODE.
    // // let curdir = current_process()
    // //     .inner_exclusive_access()
    // //     .work_dir
    // //     .clone();
    // let curdir = Arc::new(crate::fs::dentry::Dentry::new("/", ROOT_INODE.clone()));

    // let target = curdir.inode().lookup(old_path.as_str()).unwrap();
    // if curdir.inode().link(&new_path, target) {
    //     0
    // } else {
    //     super::sys_result::SysError::ENOENT as isize
    // }
}

/// YOUR JOB: Implement unlinkat.
pub fn sys_unlinkat(dirfd: isize, path: *const u8, _flags: u32) -> isize {
    //unimplemented!()
    // // trace!(
    // //     "kernel:pid[{}] sys_unlinkat(name: 0x{:x?})",
    // //     current_task().unwrap().process.upgrade().unwrap().getpid(), name
    // // );
    debug!("in sys unlink");
    let process = current_process();
    let inner = process.inner_exclusive_access();

    let token = inner.get_user_token();
    let path = translated_str(token, path);
    let abs_path = inner.get_abs_path(dirfd, &path);
    if abs_path == "" {
        return -1;
    }
    debug!("to open,the abs path is :{}", abs_path);
    let osfile = open(&abs_path, OpenFlags::O_ASK_SYMLINK, NONE_MODE)
        .unwrap()
        .file()
        .unwrap();
    if osfile.inode.link_cnt().unwrap() == 1 && inner.fs_info.has_fd(&path) {
        osfile.inode.delay();
        remove_inode_idx(&abs_path);
    } else {
        osfile.inode.unlink(&abs_path).unwrap();
        remove_inode_idx(&abs_path);
    }
    0
    // let curdir = Arc::new(crate::fs::dentry::Dentry::new("/", ROOT_INODE.clone()));

    // if curdir.inode().unlink(&path) {
    //     0
    // } else {
    //     super::sys_result::SysError::ENOENT as isize
    // }
}

/// change work dir
pub fn sys_chdir(path: *const u8) -> isize {
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    if (path as isize) <= 0 || is_bad_address(path as usize) {
        return 0;
    }
    let mut path = translated_str(token, path);
    if path.len() > MAX_PATH_LEN {
        return -1;
    }
    let abs_path = get_abs_path(inner.fs_info.cwd(), &path);
    let osfile = open(&abs_path, OpenFlags::O_RDONLY, NONE_MODE)
        .unwrap()
        .file()
        .unwrap();
    if !osfile.inode.is_dir() {
        return -1;
    }
    if path.starts_with("./") {
        path = path[1..].to_string();
    }
    if inner.fs_info.in_root() {
        inner.fs_info.set_cwd(path);
    } else {
        inner.fs_info.set_cwd(abs_path);
    }
    0
}

/// get dentries
pub fn sys_getdents64(fd: usize, buf: *const u8, len: usize) -> isize {
    let process = current_process();
    let mut inner = process.inner_exclusive_access();
    if fd >= inner.fd_table.len() || inner.fd_table.try_get(fd).is_none() {
        return -1;
    }
    let mut buffer =
        UserBuffer::new(safe_translated_byte_buffer(inner.memory_set.clone(), buf, len).unwrap());
    let file = inner.fd_table.get(fd).file().unwrap();
    let off;
    let check_off = file.lseek(0, SEEK_CUR);
    if let Err(_) = check_off {
        return 0;
    } else {
        off = check_off.unwrap();
    }
    let (de, off) = file.inode.read_dentry(off, len).unwrap();
    buffer.write(de.as_slice());
    let _ = file.lseek(off as isize, SEEK_SET).unwrap();
    return de.len() as isize;
}

/// mkdirat
pub fn sys_mkdirat(dirfd: isize, path: *const u8, mode: u32) -> isize {
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    let path = translated_str(token, path);

    if dirfd != -100 && dirfd as usize >= inner.fd_table.len() {
        return -1;
    }
    let abs_path = inner.get_abs_path(dirfd, &path);
    if let Ok(_) = open(&abs_path, OpenFlags::O_RDWR, NONE_MODE) {
        return -1;
    }
    if let Ok(_) = open(
        &abs_path,
        OpenFlags::O_RDWR | OpenFlags::O_CREATE | OpenFlags::O_DIRECTORY,
        mode,
    ) {
        return 0;
    }
    -1
}

/// nount
pub fn sys_mount(
    special: *const u8,
    dir: *const u8,
    ftype: *const u8,
    flags: u32,
    data: *const u8,
) -> isize {
    let token = current_user_token();
    let (special, dir, ftype) = (
        translated_str(token, special),
        translated_str(token, dir),
        translated_str(token, ftype),
    );
    if !data.is_null() {
        let data = translated_str(token, data);
        let ret = MNT_TABLE.lock().mount(special, dir, ftype, flags, data);
        if ret != -1 {
            0
        } else {
            -1
        }
    } else {
        let ret = MNT_TABLE
            .lock()
            .mount(special, dir, ftype, flags, String::from(""));
        if ret != -1 {
            0
        } else {
            -1
        }
    }
}

/// unmount
pub fn sys_unmount2(special: *const u8, flags: u32) -> isize {
    let token = current_user_token();
    let special = translated_str(token, special);
    let ret = MNT_TABLE.lock().umount(special, flags);
    if ret != -1 {
        0
    } else {
        -1
    }
}

/// https://man7.org/linux/man-pages/man2/statx.2.html
pub fn sys_statx(
    dirfd: isize,
    pathname: *const u8,
    flags: i32,
    mask: u32,
    statxbuf: *mut Statx,
) -> isize {
    debug!("in sys statx");
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    
    if flags & StatxFlags::AT_EMPTY_PATH.bits() as i32 != 0 {
        if dirfd < 0 || dirfd as usize >= inner.fd_table.len() {
            return SysErrNo::EBADF as isize;
        }
        
        if let Some(file_desc) = inner.fd_table.try_get(dirfd as usize) {
            let file = file_desc.any();
            let kstat = file.fstat();
            let statx = convert_kstat_to_statx(&kstat, mask);
            drop(inner);
            copy_to_virt(&statx, statxbuf);
            return 0;
        }
        return SysErrNo::EBADF as isize;
    }
    // 获取路径字符串
    if pathname.is_null() {
        return SysErrNo::EFAULT as isize;
    }
    let path = translated_str(token, pathname);
    
    // 获取绝对路径
    let abs_path = inner.get_abs_path(dirfd, &path);
    if abs_path.is_empty() {
        return SysErrNo::ENOENT as isize;
    }
    
    // 设置打开标志
    let mut open_flags = OpenFlags::O_RDONLY;
    if flags & StatxFlags::AT_SYMLINK_NOFOLLOW.bits() as i32 != 0 {
        open_flags |= OpenFlags::O_NOFOLLOW;
    }
    
    // 打开文件获取元数据
    match open(&abs_path, open_flags, NONE_MODE) {
        Ok(file) => {
            let kstat = file.fstat();
            let statx = convert_kstat_to_statx(&kstat, mask);
            drop(inner);
            copy_to_virt(&statx, statxbuf);
            0
        }
        Err(_) => SysErrNo::ENOENT as isize, // 文件打开失败
    }
}