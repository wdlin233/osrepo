use alloc::{format, string::ToString};

use crate::{
    fs::{make_socket, make_socketpair, FileClass, FileDescriptor, OpenFlags},
    mm::translated_refmut,
    task::current_task,
    utils::{SysErrNo, SyscallRet},
};
use log::debug;

/// 参考 https://man7.org/linux/man-pages/man2/socket.2.html
pub fn sys_socket(_domain: u32, _type: u32, _protocol: u32) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    let new_fd = inner.fd_table.alloc_fd().unwrap();
    let close_on_exec = (_type & 0o2000000) == 0o2000000;
    let non_block = (_type & 0o4000) == 0o4000;
    let mut flags = OpenFlags::empty();
    if close_on_exec {
        flags |= OpenFlags::O_CLOEXEC;
    }
    if non_block {
        flags |= OpenFlags::O_NONBLOCK;
    }
    inner.fd_table.set(
        new_fd,
        FileDescriptor::new(flags, FileClass::Abs(make_socket())),
    );
    inner
        .fs_info
        .insert(format!("socket{}", new_fd).to_string(), new_fd);
    new_fd as isize
}

/// 参考 https://man7.org/linux/man-pages/man2/bind.2.html
pub fn sys_bind(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    0
}

/// 参考 https://man7.org/linux/man-pages/man2/getsockname.2.html
pub fn sys_getsockname(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    0
}

/// 参考 https://man7.org/linux/man-pages/man2/getpeername.2.html
pub fn sys_getpeername(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    SysErrNo::Default as isize
}

/// 参考 https://man7.org/linux/man-pages/man2/setsockopt.2.html
pub fn sys_setsockopt(
    _sockfd: usize,
    _level: u32,
    _optname: u32,
    _optcal: *const u8,
    _optlen: u32,
) -> isize {
    0
}

/// 参考 https://man7.org/linux/man-pages/man2/sendto.2.html
pub fn sys_sendto(
    _sockfd: usize,
    _buf: *const u8,
    _len: usize,
    _flags: u32,
    _dest_addr: *const u8,
    _addrlen: u32,
) -> isize {
    1
}

/// 参考 https://man7.org/linux/man-pages/man2/recvfrom.2.html
pub fn sys_recvfrom(
    _sockfd: usize,
    buf: *mut u8,
    _len: usize,
    _flags: u32,
    _src_addr: *const u8,
    _addrlen: u32,
) -> isize {
    *translated_refmut(buf) = b'x';
    *translated_refmut(unsafe { buf.add(1) }) = b'0';
    1
}

/// 参考 https://man7.org/linux/man-pages/man2/listen.2.html
pub fn sys_listen(_sockfd: usize, _backlog: u32) -> isize {
    0
}

/// 参考 https://man7.org/linux/man-pages/man2/connect.2.html
pub fn sys_connect(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    0
}

/// 参考 https://man7.org/linux/man-pages/man2/accept.2.html
pub fn sys_accept(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    0
}

pub fn sys_accept4(_sockfd: usize, _addr: *const u8, _addrlen: u32, _flags: u32) -> isize {
    0
}

/// 参考 https://man7.org/linux/man-pages/man2/sendmsg.2.html
pub fn sys_sendmsg(_sockfd: usize, _addr: *const u8, _flags: u32) -> isize {
    0
}

pub fn sys_socketpair(_domain: u32, stype: u32, _protocol: u32, sv: *mut u32) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    let (socket1, socket2) = make_socketpair();
    let close_on_exec = (stype & 0o2000000) == 0o2000000;
    let non_block = (stype & 0o4000) == 0o4000;
    let mut flags = OpenFlags::empty();
    if close_on_exec {
        flags |= OpenFlags::O_CLOEXEC;
    }
    if non_block {
        flags |= OpenFlags::O_NONBLOCK;
    }

    let new_fd1 = inner.fd_table.alloc_fd().unwrap();
    inner
        .fd_table
        .set(new_fd1, FileDescriptor::new(flags, FileClass::Abs(socket1)));
    inner
        .fs_info
        .insert(format!("socket{}", new_fd1).to_string(), new_fd1);

    let new_fd2 = inner.fd_table.alloc_fd().unwrap();
    inner
        .fd_table
        .set(new_fd2, FileDescriptor::new(flags, FileClass::Abs(socket2)));
    inner
        .fs_info
        .insert(format!("socket{}", new_fd2).to_string(), new_fd2);

    *translated_refmut(sv) = new_fd1 as u32;
    *translated_refmut(unsafe { sv.add(1) }) = new_fd2 as u32;
    0
}
