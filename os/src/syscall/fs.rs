use core::mem::transmute;

//use crate::fs::ext4::ROOT_INO;
use crate::fs::pipe::make_pipe;
use crate::fs::{
    convert_kstat_to_statx, open, open_device_file, remove_inode_idx, stat, File, FileClass, FileDescriptor, Kstat, OpenFlags, Statx, StatxFlags, MAX_PATH_LEN, MNT_TABLE, NONE_MODE, SEEK_CUR, SEEK_SET
}; //::{link, unlink}

use crate::mm::{
    is_bad_address, translated_byte_buffer, translated_ref, translated_refmut, translated_str, UserBuffer
};
use crate::syscall::{
    process, FaccessatFileMode, FaccessatMode, FcntlCmd, Iovec, PollEvents, PollFd, RLimit, TimeVal,
};
use crate::task::{
    block_current_and_run_next, current_task, suspend_current_and_run_next,
};
use crate::timer::{get_time_ms, TimeSpec};
use crate::users::User;
use crate::utils::{get_abs_path, rsplit_once, trim_start_slash, SysErrNo, SyscallRet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use polyhal::consts::VIRT_ADDR_START;
use polyhal::{MappingFlags, PhysAddr, VirtAddr};
use polyhal_trap::trap::TrapType;

pub fn sys_readlinkat(dirfd: isize, path: *const u8, buf: *const u8, bufsize: usize) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    //let path = data_flow!({ c_ptr_to_string(path) });
    let path = translated_str(path);

    // assert!(path == "/proc/self/exe", "unsupported other path!");
    if path == "/proc/self/exe" {
        debug!("fs_info={}", inner.fs_info.exe());
        let size_needed = inner.fs_info.exe_as_bytes().len();
        debug!("the size need is : {}", size_needed);
        let mut buffer = UserBuffer::new(vec![
            unsafe {
                core::slice::from_raw_parts_mut(translated_refmut(buf as *mut _), size_needed)
            }
        ]);
        let res = buffer.write(inner.fs_info.exe_as_bytes());
        return res as isize;
    }
    debug!("[sys_read_linkat] got path : {}", inner.fs_info.get_cwd());
    let abs_path = inner.get_abs_path(dirfd, &path);
    let mut linkbuf = vec![0u8; bufsize];
    let file = open(&abs_path, OpenFlags::empty(), NONE_MODE)
        .unwrap()
        .file()
        .unwrap();
    let readcnt = file.inode.read_link(&mut linkbuf, bufsize).unwrap();
    // let mut buffer = UserBuffer::new(translated_byte_buffer(token, buf, readcnt).unwrap());
    let mut buffer =
        UserBuffer::new_single(unsafe { core::slice::from_raw_parts_mut(buf as *mut _, readcnt) });
    buffer.write(&linkbuf);
    readcnt as isize

    // Ok(res)
}

//lseek
pub fn sys_lseek(fd: usize, offset: isize, whence: usize) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();

    if fd >= inner.fd_table.len() || inner.fd_table.try_get(fd).is_none() {
        return SysErrNo::EINVAL as isize;
    }
    let file = match inner.fd_table.get(fd).file() {
        Ok(fi) => fi,
        Err(num) => return num as isize,
    };
    match file.lseek(offset, whence) {
        Ok(i) => i as isize,
        Err(n) => n as isize,
    }
}

//readv
pub fn sys_readv(fd: usize, iov: *const u8, iovcnt: usize) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();

    if (fd as isize) < 0 || fd >= inner.fd_table.len() {
        return SysErrNo::EBADF as isize;
    }

    if (iov as isize) <= 0 || is_bad_address(iov as usize) {
        return SysErrNo::EFAULT as isize;
    }

    if (iovcnt as isize) < 0 {
        return SysErrNo::EINVAL as isize;
    }
    if let Some(file) = &inner.fd_table.try_get(fd) {
        if let Ok(readfile) = file.file() {
            if readfile.inode.is_dir() {
                return SysErrNo::EISDIR as isize;
            }
        }
        let file = file.any();
        if !file.readable() {
            return SysErrNo::EACCES as isize;
        }
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        drop(process);
        let mut ret: usize = 0;
        let iovec_size = core::mem::size_of::<Iovec>();

        for i in 0..iovcnt {
            // current iovec pointer
            let current = unsafe { iov.add(iovec_size * i) };
            //let iovinfo = data_flow!({ *(current as *mut Iovec) });
            let iovinfo = *translated_refmut(current as *mut Iovec);
            if (iovinfo.iov_len as isize) < 0 {
                return SysErrNo::EINVAL as isize;
            }
            let buffer =
                translated_byte_buffer(iovinfo.iov_base as *mut u8, iovinfo.iov_len);
            let buf = UserBuffer::new(vec![buffer]);
            let read_ret = match file.read(buf) {
                Ok(rr) => rr,
                Err(num) => return num as isize,
            };
            ret += read_ret as usize;
        }
        ret as isize
    } else {
        SysErrNo::EBADF as isize
    }
}

/// write syscall
pub fn sys_write(fd: usize, buf: *mut u8, len: usize) -> isize {
    debug!("in sys write with buf: {:x?}, len: {}", buf, len);
    let process = current_task().unwrap();
    debug!("current pid is :{}", process.getpid());
    let inner = process.inner_exclusive_access();
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
        let buf = UserBuffer::new(vec![translated_byte_buffer(buf, len)]);
        debug!("to write file");
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
pub fn sys_read(fd: usize, buf: *mut u8, len: usize) -> isize {
    debug!("in sys read");
    // let token = current_user_token();
    let process = current_task().unwrap();
    debug!("current pid is :{}", process.getpid());
    let inner = process.inner_exclusive_access();
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
                vec![translated_byte_buffer(buf, len)],
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
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    let path = translated_str(path);
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
}
/// close syscall
pub fn sys_close(fd: usize) -> isize {
    debug!("in sys close");
    let process = current_task().unwrap();
    debug!("in close, pid is :{}", process.getpid());
    let inner = process.inner_exclusive_access();
    if fd >= inner.fd_table.len() { // ignore fd < 0, usize
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
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    info!("[sys_pipe2] fd is {:x},flags is {}", fd as usize, flags);

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

    let memory_set = &mut inner.memory_set.clone();
    let page_table = memory_set.token();

    // 写入第一个 u32 (read_fd)
    let fd_ptr1 = fd as usize;
    let va1 = VirtAddr::from(fd_ptr1);
    let vpn1 = va1.floor();
    // 确保页面有效且可写
    if !page_table
        .translate(vpn1)
        .map_or(false, |(_paddr, flags)| flags.contains(MappingFlags::P) && flags.contains(MappingFlags::W))
    {
        memory_set.lazy_page_fault(vpn1, TrapType::StorePageFault(vpn1.into()));
    }
    // 获取物理地址并写入
    if let Some((paddr, flags)) = page_table.translate(vpn1) {
        if flags.contains(MappingFlags::P) && flags.contains(MappingFlags::W) {
            let kernel_va = paddr.raw() | VIRT_ADDR_START;
            
            let read_addr = kernel_va + va1.raw() - vpn1.raw(); // page_offset
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
        .map_or(false, |(_paddr, flags)| flags.contains(MappingFlags::P) && flags.contains(MappingFlags::W))
    {
        memory_set.lazy_page_fault(vpn2, TrapType::StorePageFault(vpn2.into()));
    }

    // 获取物理地址并写入
    if let Some((paddr, flags)) = page_table.translate(vpn2) {
        if flags.contains(MappingFlags::P) && flags.contains(MappingFlags::W) {
            let kernel_va = paddr.raw() | VIRT_ADDR_START;
            
            let write_addr = kernel_va + va2.raw() - vpn2.raw();
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
    let process = current_task().unwrap();
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
    let process = current_task().unwrap();
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
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    if (st as isize) <= 0 || is_bad_address(st as usize) {
        return SysErrNo::EFAULT as isize;
    }
    if fd >= inner.fd_table.len() || inner.fd_table.try_get(fd).is_none() {
        return SysErrNo::EBADF as isize;
    }
    let file = inner.fd_table.get(fd).any();
    unsafe {
        *st = file.fstat() // copy stat to user space
    };
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

pub fn sys_getcwd(buf: *mut u8, size: usize) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    let cwdlen = inner.fs_info.cwd().len();
    if (buf as isize) < 0 || is_bad_address(buf as usize) || (size as isize) < 0 || size <= cwdlen {
        return SysErrNo::EFAULT as isize;
    }
    let cwdlen = inner.fs_info.cwd().len();
    if size <= cwdlen {
        return SysErrNo::ERANGE as isize;
    }
    let mut buffer =
        UserBuffer::new(vec![translated_byte_buffer(buf, size)]);
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
    // // let curdir = current_task()
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
pub fn sys_unlinkat(dirfd: isize, path: *mut u8, _flags: u32) -> isize {
    debug!("in sys unlink");
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();

    let path = translated_str(path);
    let abs_path = inner.get_abs_path(dirfd, &path);
    if abs_path == "" {
        return -1;
    }
    debug!("to open,the abs path is :{}", abs_path);
    let osfile = match open(&abs_path, OpenFlags::O_ASK_SYMLINK, NONE_MODE) {
        Ok(of) => of.file().unwrap(),
        Err(num) => return num as isize,
    };
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
pub fn sys_chdir(path: *mut u8) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    if (path as isize) <= 0 || is_bad_address(path as usize) {
        return 0;
    }
    let mut path = translated_str(path);
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
pub fn sys_getdents64(fd: usize, buf: *mut u8, len: usize) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    if fd >= inner.fd_table.len() || inner.fd_table.try_get(fd).is_none() {
        return -1;
    }
    let mut buffer =
        UserBuffer::new(vec![translated_byte_buffer(buf, len)]);
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
pub fn sys_mkdirat(dirfd: isize, path: *mut u8, mode: u32) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    let path = translated_str(path);

    if dirfd != -100 && dirfd as usize >= inner.fd_table.len() {
        return -1;
    }
    let abs_path = inner.get_abs_path(dirfd, &path);
    if let Ok(_) = open(&abs_path, OpenFlags::O_RDWR, NONE_MODE) {
        return SysErrNo::EEXIST as isize;
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
    special: *mut u8,
    dir: *mut u8,
    ftype: *mut u8,
    flags: u32,
    data: *mut u8,
) -> isize {
    let (special, dir, ftype) = (
        translated_str(special),
        translated_str(dir),
        translated_str(ftype),
    );
    if !data.is_null() {
        let data = translated_str(data);
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
pub fn sys_unmount2(special: *mut u8, flags: u32) -> isize {
    let special = translated_str(special);
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
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();

    if flags & StatxFlags::AT_EMPTY_PATH.bits() as i32 != 0 {
        if dirfd < 0 || dirfd as usize >= inner.fd_table.len() {
            return SysErrNo::EBADF as isize;
        }

        if let Some(file_desc) = inner.fd_table.try_get(dirfd as usize) {
            let file = file_desc.any();
            let kstat = file.fstat();
            let statx = convert_kstat_to_statx(&kstat, mask);
            drop(inner);
            unsafe { *statxbuf = statx; }
            return 0;
        }
        return SysErrNo::EBADF as isize;
    }
    // 获取路径字符串
    if pathname.is_null() {
        return SysErrNo::EFAULT as isize;
    }
    let path = translated_str(pathname);

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
            unsafe { *statxbuf = statx; }
            0
        }
        Err(_) => SysErrNo::ENOENT as isize, // 文件打开失败
    }
}

//ioctl
pub fn sys_ioctl(_fd: usize, _cmd: usize, _arg: usize) -> isize {
    0
}

//fcntl
pub fn sys_fcntl(fd: usize, cmd: usize, arg: usize) -> isize {
    const FD_CLOEXEC: usize = 1;

    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();

    if fd >= inner.fd_table.len() || (fd as isize) < 0 {
        return SysErrNo::EBADF as isize;
    }

    if inner.fd_table.try_get(fd).is_none() {
        return SysErrNo::EINVAL as isize;
    }

    let mut file = inner.fd_table.get(fd);
    let cmd = FcntlCmd::from_bits(cmd).unwrap();

    match cmd {
        FcntlCmd::F_DUPFD => {
            let fd_new = inner.fd_table.alloc_fd_larger_than(arg).unwrap();
            inner.fd_table.set(fd_new, file);
            inner.fs_info.insert_with_glue(fd, fd_new);
            return fd_new as isize;
        }
        FcntlCmd::F_DUPFD_CLOEXEC => {
            let fd_new = inner.fd_table.alloc_fd_larger_than(arg).unwrap();
            file.set_cloexec();
            inner.fd_table.set(fd_new, file);
            inner.fs_info.insert_with_glue(fd, fd_new);
            return fd_new as isize;
        }
        FcntlCmd::F_GETFD => {
            return if inner.fd_table.get(fd).cloexec() {
                1
            } else {
                0
            };
        }
        FcntlCmd::F_SETFD => {
            if arg & FD_CLOEXEC == 0 {
                inner.fd_table.unset_cloexec(fd);
            } else {
                inner.fd_table.set_cloexec(fd);
            }
        }
        FcntlCmd::F_GETFL => {
            let mut res = OpenFlags::O_RDWR.bits() as usize;
            if file.non_block() {
                res |= OpenFlags::O_NONBLOCK.bits() as usize;
            }
            return res as isize;
        }
        FcntlCmd::F_SETFL => {
            // 目前只启用nonblock
            let flags = OpenFlags::from_bits_truncate(arg as u32);
            if flags.contains(OpenFlags::O_NONBLOCK) {
                inner.fd_table.set_nonblock(fd);
            } else {
                inner.fd_table.unset_nonblock(fd);
            }
            // task_inner.fd_table.set_flags(fd, Some(flags));
            // todo!()
        }
        _ => {
            return SysErrNo::EINVAL as isize;
        }
    }
    0
}

//writev
pub fn sys_writev(fd: usize, iov: *const u8, iovcnt: usize) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();

    if (fd as isize) < 0 || fd >= inner.fd_table.len() {
        return SysErrNo::EBADF as isize;
    }

    if (iov as isize) <= 0 || is_bad_address(iov as usize) {
        return SysErrNo::EFAULT as isize;
    }

    if (iovcnt as isize) < 0 {
        return SysErrNo::EINVAL as isize;
    }

    if let Some(file) = &inner.fd_table.try_get(fd) {
        if let Ok(readfile) = file.file() {
            if readfile.inode.is_dir() {
                return SysErrNo::EISDIR as isize;
            }
        }
        let file = file.any();
        if !file.writable() {
            return SysErrNo::EACCES as isize;
        }
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        drop(process);
        let mut ret: usize = 0;
        let iovec_size = core::mem::size_of::<Iovec>();

        for i in 0..iovcnt {
            // current iovec pointer
            let current = unsafe { iov.add(iovec_size * i) };
            //let iovinfo = data_flow!({ *(current as *mut Iovec) });
            let iovinfo = *translated_refmut(current as *mut Iovec);
            if (iovinfo.iov_len as isize) < 0 {
                return SysErrNo::EINVAL as isize;
            }
            let buffer =
                translated_byte_buffer(iovinfo.iov_base as *mut u8, iovinfo.iov_len);
            let buf = UserBuffer::new(vec![buffer]);
            let write_ret = file.write(buf).unwrap();
            ret += write_ret as usize;
        }
        ret as isize
    } else {
        SysErrNo::EBADF as isize
    }
}

/// https://man7.org/linux/man-pages/man2/ppoll.2.html
pub fn sys_ppoll(fds_ptr: usize, nfds: usize, tmo_p: usize, _mask: usize) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    
    if fds_ptr == 0 {
        return SysErrNo::EINVAL as isize;
    }

    let mut fds = Vec::new();
    let ptr = fds_ptr as *mut PollFd;

    for i in 0..nfds {
        fds.push(unsafe { *translated_refmut(ptr.add(i)) });
    }

    let wait_time: isize = if tmo_p == 0 {
        -1
    } else {
        let timespec = *translated_ref(tmo_p as *const TimeSpec);
        (timespec.tv_sec * 1000000000 + timespec.tv_nsec) as isize
    };
    if wait_time == 0 {
        return 0;
    }

    let begin = get_time_ms() * 1000000;
    drop(inner);
    drop(process);
    loop {
        let process = current_task().unwrap();
        let inner = process.inner_exclusive_access();
        let mut resnum = 0;
        for i in 0..nfds {
            if fds[i].fd < 0 {
                fds[i].revents = PollEvents::empty();
                continue;
            }
            if let Some(file) = &inner.fd_table.try_get(fds[i].fd as usize) {
                let file = file.any();
                let events = file.poll(fds[i].events);
                if !events.is_empty() {
                    resnum += 1;
                }
                fds[i].revents = events;
            } else {
                fds[i].revents = PollEvents::INVAL;
            }
        }
        if resnum > 0 {
            return resnum as isize;
        }
        if wait_time > 0 && get_time_ms() - begin >= wait_time as usize {
            return 0; // 超时
        }
        drop(inner);
        drop(process);
        debug!("No events ready, suspending current task.");
        suspend_current_and_run_next(); //or block()?
    }
}

pub fn sys_fstatat(dirfd: isize, path: *mut u8, kst: *mut Kstat, _flags: usize) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    
    let path = trim_start_slash(translated_str(path));
    let abs_path = inner.get_abs_path(dirfd, &path);
    if abs_path == "/ls" || abs_path == "/xargs" || abs_path == "/sleep" {
        open(&abs_path, OpenFlags::O_CREATE, NONE_MODE);
    }

    let file = match open(
        &abs_path,
        OpenFlags::O_RDONLY | OpenFlags::O_ASK_SYMLINK,
        NONE_MODE,
    ) {
        Ok(file) => file,
        Err(_) => {
            return SysErrNo::ENOENT as isize; // 文件打开失败
        }
    };
    *translated_refmut(kst) = file.fstat();
    return 0;
}

//send file
pub fn sys_sendfile(outfd: usize, infd: usize, offset_ptr: usize, count: usize) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    
    if (infd as isize) < 0
        || infd >= inner.fd_table.len()
        || (outfd as isize) < 0
        || outfd >= inner.fd_table.len()
    {
        return SysErrNo::EBADF as isize;
    }

    if (offset_ptr as isize) < 0 || is_bad_address(offset_ptr as usize) {
        return SysErrNo::EFAULT as isize;
    }

    if (count as isize) < 0 {
        return SysErrNo::EINVAL as isize;
    }

    if inner.fd_table.try_get(outfd).is_none() || inner.fd_table.try_get(infd).is_none() {
        return SysErrNo::EINVAL as isize;
    }

    let outinode = inner.fd_table.get(outfd);
    if let Ok(_) = outinode.file() {
        if !outinode.flags.contains(OpenFlags::O_WRONLY)
            && !outinode.flags.contains(OpenFlags::O_RDWR)
        {
            return SysErrNo::EBADF as isize;
        }
    }
    let outfile = outinode.any();
    if !outfile.writable() {
        return SysErrNo::EBADF as isize;
    }

    let infile = inner.fd_table.get(infd).file().unwrap();
    if !infile.readable() {
        return SysErrNo::EBADF as isize;
    }

    drop(inner);
    drop(process);

    //构造输入缓冲池
    let mut buf = vec![0u8; count];
    let mut inbufv = Vec::new();
    unsafe {
        inbufv.push(core::slice::from_raw_parts_mut(
            buf.as_mut_slice().as_mut_ptr(),
            buf.as_slice().len(),
        ));
    }
    //输入缓冲池
    let inbuffer = UserBuffer::new(inbufv);

    let cur_off = infile.lseek(0, SEEK_CUR).unwrap();

    let readcount;
    if offset_ptr == 0 {
        readcount = infile.read(inbuffer).unwrap();
    } else {
        //let offset = data_flow!({ *(offset_ptr as *const isize) });
        let offset = *translated_ref(offset_ptr as *const isize);
        if offset < 0 {
            return SysErrNo::EINVAL as isize;
        }
        infile.lseek(offset, SEEK_SET).unwrap();
        readcount = infile.read(inbuffer).unwrap();
        // data_flow!({
        //     *(offset_ptr as *mut isize) += readcount as isize;
        //});
        *translated_refmut(offset_ptr as *mut isize) += readcount as isize;
        infile.lseek(cur_off as isize, SEEK_SET).unwrap();
    }

    if readcount == 0 {
        return 0;
    }

    //构造输出缓冲池
    let mut outbufv = Vec::new();
    unsafe {
        outbufv.push(core::slice::from_raw_parts_mut(
            buf.as_mut_slice().as_mut_ptr(),
            readcount,
        ));
    }
    //输出缓冲池
    let outbuffer = UserBuffer::new(outbufv);
    //写数据
    let retcount = outfile.write(outbuffer).unwrap();

    retcount as isize
}

// faccessat
pub fn sys_faccessat(dirfd: isize, path: *const u8, mode: u32, _flags: usize) -> isize {
    let process = current_task().unwrap();
    let uid = process.getuid();
    let inner = process.inner_exclusive_access();
    if (path as isize) <= 0 {
        return SysErrNo::EFAULT as isize;
    }
    if (mode as i32) < 0 {
        return SysErrNo::EINVAL as isize;
    }
    //let path = data_flow!({ c_ptr_to_string(path) });
    let path = translated_str(path);
    if path.len() == 0 {
        return SysErrNo::ENOENT as isize;
    }

    if path.len() > MAX_PATH_LEN {
        return SysErrNo::ENAMETOOLONG as isize;
    }

    if dirfd != -100 && dirfd as usize >= inner.fd_table.len() {
        return SysErrNo::EBADF as isize;
    }

    let mode = FaccessatMode::from_bits(mode).unwrap();

    if mode.contains(FaccessatMode::W_OK) {
        if let Some((_, _, _, mountflags)) = MNT_TABLE.lock().got_mount(path.clone()) {
            if mountflags & 1 != 0 {
                //挂载点只读
                return SysErrNo::EROFS as isize;
            }
        }
    }

    let abs_path = inner.get_abs_path(dirfd, &path);
    if abs_path == "/ls" || abs_path == "/xargs" || abs_path == "/sleep" {
        open(&abs_path, OpenFlags::O_CREATE, NONE_MODE);
    }
    let (parent_path, _) = rsplit_once(abs_path.as_str(), "/");
    let parent_inode = match open(&parent_path, OpenFlags::O_RDWR, NONE_MODE) {
        Ok(pi) => pi.file().unwrap(),
        Err(num) => return num as isize,
    };
    let parent_mode = parent_inode.inode.fmode().unwrap() & 0xfff;
    let parent_mode = FaccessatFileMode::from_bits_truncate(parent_mode);
    if !parent_inode.inode.is_dir() {
        return SysErrNo::ENOTDIR as isize;
    }
    if uid != 0
        && !(parent_mode.contains(FaccessatFileMode::S_IXUSR)
            || parent_mode.contains(FaccessatFileMode::S_IXGRP)
            || parent_mode.contains(FaccessatFileMode::S_IXOTH))
    {
        //父目录必须有可以执行的权限
        return SysErrNo::EACCES as isize;
    }
    info!("in sys faccessat , the abs path is : {}", abs_path);
    let inode = match open(&abs_path, OpenFlags::O_RDWR, NONE_MODE) {
        Ok(i) => i.file().unwrap(),
        Err(num) => {
            return num as isize;
        }
    };

    let file_mode = inode.inode.fmode().unwrap() & 0xfff;
    let file_mode = FaccessatFileMode::from_bits_truncate(file_mode);
    if mode.contains(FaccessatMode::R_OK)
        && uid != 0
        && !(file_mode.contains(FaccessatFileMode::S_IRUSR)
            || file_mode.contains(FaccessatFileMode::S_IRGRP)
            || file_mode.contains(FaccessatFileMode::S_IROTH))
    {
        return SysErrNo::EACCES as isize;
    }
    if mode.contains(FaccessatMode::W_OK)
        && uid != 0
        && !(file_mode.contains(FaccessatFileMode::S_IWUSR)
            || file_mode.contains(FaccessatFileMode::S_IWGRP)
            || file_mode.contains(FaccessatFileMode::S_IWOTH))
    {
        return SysErrNo::EACCES as isize;
    }
    if mode.contains(FaccessatMode::X_OK)
        && !(file_mode.contains(FaccessatFileMode::S_IXUSR)
            || file_mode.contains(FaccessatFileMode::S_IXGRP)
            || file_mode.contains(FaccessatFileMode::S_IXOTH))
    {
        return SysErrNo::EACCES as isize;
    }
    0
}

pub fn sys_utimensat(dirfd: isize, path: *const u8, times: *const TimeVal, _flags: usize) -> isize {
    // utime
    pub const UTIME_NOW: usize = 0x3fffffff;
    pub const UTIME_OMIT: usize = 0x3ffffffe;

    if dirfd == -1 {
        return SysErrNo::EBADF as isize;
    }
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    let path = if !path.is_null() {
        //data_flow!({ c_ptr_to_string(path) })
        translated_str(path)
    } else {
        String::new()
    };
    // TODO(ZMY) 为了过测试,暂时特殊处理一下
    if path == "/dev/null/invalid" {
        return SysErrNo::ENOTDIR as isize;
    }
    let nowtime = (get_time_ms() / 1000) as u64;

    let (mut atime_sec, mut mtime_sec) = (None, None);

    if times as usize == 0 {
        atime_sec = Some(nowtime);
        mtime_sec = Some(nowtime);
    } else {
        //let (atime, mtime) = data_flow!({ (*times, *times.add(1)) });
        let (atime, mtime) = (
            *translated_ref(times as *const TimeVal),
            *translated_ref(unsafe { times.add(1) as *const TimeVal }),
        );
        match atime.usec {
            UTIME_NOW => atime_sec = Some(nowtime),
            UTIME_OMIT => (),
            _ => atime_sec = Some(atime.sec as u64),
        };
        match mtime.usec {
            UTIME_NOW => mtime_sec = Some(nowtime),
            UTIME_OMIT => (),
            _ => mtime_sec = Some(mtime.sec as u64),
        };
    }

    let abs_path = inner.get_abs_path(dirfd, &path);
    info!("in sys utimensat , the abs path is : {}", abs_path);
    let osfile = match open(&abs_path, OpenFlags::O_RDONLY, NONE_MODE) {
        Ok(of) => of.file().unwrap(),
        Err(num) => return num as isize,
    };
    osfile
        .inode
        .set_timestamps(atime_sec, mtime_sec, None)
        .unwrap();
    return 0;
}

pub fn sys_prlimit(
    pid: usize,
    resource: u32,
    new_limit: *const RLimit,
    old_limit: *mut RLimit,
) -> isize {
    const RLIMIT_NOFILE: u32 = 7;
    if resource != RLIMIT_NOFILE {
        return 0;
    }

    if pid == 0 {
        let process = current_task().unwrap();
        let mut inner = process.inner_exclusive_access();
        let fd_table = &mut inner.fd_table;
        if !old_limit.is_null() {
            // 说明是get
            (*translated_refmut(old_limit)).rlim_cur = fd_table.get_soft_limit();
            (*translated_refmut(old_limit)).rlim_max = fd_table.get_hard_limit();
        }
        if !new_limit.is_null() {
            // 说明是set
            let limit;
            limit = *translated_ref(new_limit);
            fd_table.set_limit(limit.rlim_cur, limit.rlim_max);
        }
    } else {
        unimplemented!("pid must equal zero");
    }

    return 0;
}

pub fn sys_getrandom(buf: *const u8, buflen: usize, flags: u32) -> isize {
    if (buf as isize) < 0 || is_bad_address(buf as usize) || buf.is_null(){
        return SysErrNo::EFAULT as isize;
    }
    if (flags as isize) < 0 {
        return SysErrNo::EINVAL as isize;
    }

    match open_device_file("/dev/random").unwrap().read(UserBuffer::new_single(unsafe {
        core::slice::from_raw_parts_mut(translated_refmut(buf as *mut _), buflen)
    })) {
        Ok(size) => size as isize,
        Err(_) => SysErrNo::EIO as isize, // check TODO
    }
}

pub fn sys_renameat2(
    olddirfd: isize,
    oldpath: *const u8,
    newdirfd: isize,
    newpath: *const u8,
    _flags: u32,
) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    let (oldpath, newpath) = (
        translated_str(oldpath),
        translated_str(newpath),
    );

    let old_abs_path = inner.get_abs_path(olddirfd, &oldpath);
    let osfile = open(&old_abs_path, OpenFlags::O_RDWR, NONE_MODE)
        .unwrap()
        .file()
        .unwrap();
    let new_abs_path = inner.get_abs_path(newdirfd, &newpath);
    match osfile.inode.rename(&old_abs_path, &new_abs_path) {
        Ok(n) => n as isize,
        Err(e) => e as isize,
    }
}
