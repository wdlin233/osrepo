//use crate::fs::ext4::ROOT_INO;
use crate::fs::{File, OpenFlags }; //::{link, unlink}
use crate::fs::pipe::make_pipe;

use crate::mm::{
    copy_to_virt, is_bad_address, translated_byte_buffer, translated_refmut, translated_str, UserBuffer,
    safe_translated_byte_buffer,
};
use crate::task::{current_process, current_user_token};
use crate::utils::SyscallRet;
use alloc::sync::Arc;
use crate::utils::SysErrNo;

/// write syscall
pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_write",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    let token = current_user_token();
    let process = current_process();
    let mut inner = process.inner_exclusive_access();

    if (fd as isize) < 0 || fd >= inner.fd_table.len() {
        //return Err(SysErrNo::EBADF);
        return -1
    }
    if (buf as isize) < 0 || is_bad_address(buf as usize) || ((buf as usize) == 0 && len != 0) {
        //return Err(SysErrNo::EFAULT);
        return -1
    }
    if (len as isize) < 0 {
        //return Err(SysErrNo::EINVAL);
        return -1
    }

    if let Some(file) = &inner.fd_table.try_get(fd) {
        if let Ok(readfile) = file.file() {
            if readfile.inode.is_dir() {
                //return Err(SysErrNo::EISDIR);
                return -1
            }
        }
        let file: Arc<dyn File> = file.any();
        if !file.writable() {
            //return Err(SysErrNo::EBADF);
            return -1
        }
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        info!(
            "kernel:pid[{}] sys_write .. file.write",
            process.getpid()
        );
        let ret = match file.write(UserBuffer::new(
            safe_translated_byte_buffer(&mut inner.memory_set, buf, len).unwrap(),
        )) {
            Ok(n) => n as isize,
            Err(e) => {
                info!("kernel: sys_write .. file.write error: {:?}", e);
                // return Err(SysErrNo::from(e));
                return -1
            }
        };
        info!(
            "kernel:pid ok"
        );
        drop(inner);
        drop(process);
        return ret    
    } else {
        //Err(SysErrNo::EBADF)
        return -1
    }
}
/// read syscall
pub fn sys_read(_fd: usize, _buf: *const u8, _len: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_read",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    unimplemented!()
    // let token = current_user_token();
    // let process = current_process();
    // let inner = process.inner_exclusive_access();
    // if fd >= inner.fd_table.len() {
    //     return -1;
    // }
    // if let Some(file) = &inner.fd_table.try_get(fd) {
    //     let file = file.clone();
    //     if !file.readable() {
    //         return -1;
    //     }
    //     // release current task TCB manually to avoid multi-borrow
    //     drop(inner);
    //     //trace!("kernel: sys_read .. file.read");
    //     file.read(UserBuffer::new(translated_byte_buffer(token, buf, len)).as_bytes_mut()) as isize
    // } else {
    //     -1
    // }
}
/// open sys
pub fn sys_open(_path: *const u8, _flags: u32) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_open",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    // let process = current_process();
    // let token = current_user_token();
    // let path = translated_str(token, path);
    // let inode = ROOT_INODE.clone();
    // if let Some(dentry) = open_file(inode, path.as_str(), OpenFlags::from_bits(flags as i32).unwrap()) {
    //     let mut inner = process.inner_exclusive_access();
    //     let fd = inner.alloc_fd();
    //     let file = cast_inode_to_file(dentry.inode());
    //     inner.fd_table.try_get(fd) = file;
    //     fd as isize
    // } else {
    //     -1
    // }
    unimplemented!()
}
/// close syscall
pub fn sys_close(fd: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_close",
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
    inner.fd_table.try_get(fd).take();
    0
}
/// pipe syscall
pub fn sys_pipe(_pipe: *mut usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_pipe",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    // let process = current_process();
    // let token = current_user_token();
    // let mut inner = process.inner_exclusive_access();
    // let (pipe_read, pipe_write) = make_pipe();
    // let read_fd = inner.alloc_fd();
    // inner.fd_table.try_get(read_fd) = Some(pipe_read);
    // let write_fd = inner.alloc_fd();
    unimplemented!(); // 参考 dup 的实现或许可行，这里先过
    //inner.fd_table.try_get(write_fd) = Some(pipe_write);
    //*translated_refmut(token, pipe) = read_fd;
    //*translated_refmut(token, unsafe { pipe.add(1) }) = write_fd;
    //0
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
/// YOUR JOB: Implement fstat.
pub fn sys_fstat(_fd: usize, _st: usize) -> isize {
    unimplemented!()
    // // debug!(
    // //     "kernel:pid[{}] sys_fstat(fd: {}, st: 0x{:x?})",
    // //     current_task().unwrap().process.upgrade().unwrap().getpid(), fd, st
    // // );
    // let process = current_process();
    // let inner = process.inner_exclusive_access();
    // if fd >= inner.fd_table.len() {
    //     return -1;
    // }
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
pub fn sys_unlinkat(_name: *const u8) -> isize {
    unimplemented!()
    // // trace!(
    // //     "kernel:pid[{}] sys_unlinkat(name: 0x{:x?})",
    // //     current_task().unwrap().process.upgrade().unwrap().getpid(), name
    // // );
    // let token = current_user_token();
    // let path = translated_str(token, name);

    // let curdir = Arc::new(crate::fs::dentry::Dentry::new("/", ROOT_INODE.clone()));

    // if curdir.inode().unlink(&path) {
    //     0
    // } else {
    //     super::sys_result::SysError::ENOENT as isize
    // }
}
