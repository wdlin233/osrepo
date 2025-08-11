use alloc::{format, string::ToString, sync::Arc};

use crate::{
    fs::{File, FileClass, FileDescriptor, OpenFlags},
    mm::{translated_byte_buffer, translated_ref, translated_refmut, UserBuffer},
    net::{SocketDomain, SocketProtocol, SocketType},
    task::current_process,
    utils::{SysErrNo, SyscallRet},
};

use spin::rwlock::RwLock;

use log::debug;

pub fn sys_socket(domain: u32, type_: u32, protocol_: u32) -> isize {
    debug!(
        "sys socket,domain: {}, type : {}, protocol : {}",
        domain, type_, protocol_
    );
    //flags
    const SO_NONBLOCK: u32 = 0x800;
    const SOCK_CLOEXEC: u32 = 0x80000;
    const O_NONBLOCK: u32 = SO_NONBLOCK;
    const O_CLOEXEC: u32 = SOCK_CLOEXEC;
    let Some(socket_domain) = SocketDomain::try_get(domain) else {
        return SysErrNo::EAFNOSUPPORT as isize;
    };
    let Some(socket_type) = SocketType::try_get(type_) else {
        return SysErrNo::EPROTOTYPE as isize;
    };
    let Ok(socket_protocol) = SocketProtocol::try_get(protocol_) else {
        return SysErrNo::EPROTONOSUPPORT as isize;
    };
    let mut flags = 0;
    if (type_ & SO_NONBLOCK) != 0 {
        flags |= O_NONBLOCK;
    }
    if (type_ & SOCK_CLOEXEC) != 0 {
        flags |= O_CLOEXEC;
    }

    let process = current_process();
    let inner = process.inner_exclusive_access();
    let fd = inner.fd_table.alloc_fd().unwrap();

    let mut connection = Connection::new(socket, socket_domain, socket_type, socket_protocol);

    inner.fd_table.set(fd, socket_file);
    fd as isize
}

pub fn sys_bind(socket: usize, address: usize, address_len: u32) -> isize {
    unimplemented!()
}

pub fn sys_listen(socket: usize, backlog: u32) -> isize {
    unimplemented!()
}

pub fn sys_accept(socket: usize, _address: *const u8, _address_len: u32) -> isize {
    unimplemented!()
}

pub fn sys_accept4(_sockfd: usize, _addr: *const u8, _addrlen: u32, _flags: u32) -> isize {
    unimplemented!()
}

pub fn sys_connect(socket: usize, address: *const u8, address_len: u32) -> isize {
    unimplemented!()
}
pub fn sys_sendto(
    socket: usize,
    message: *const u8,
    length: usize,
    flags: i32,
    dest_addr: *const u8,
    dest_len: u32,
) -> isize {
    unimplemented!()
}

pub fn sys_sendmsg(socket: usize, message: *const u8, flags: u32) -> isize {
    unimplemented!()
}

pub fn sys_recvfrom(
    socket: usize,
    buffer: *mut u8,
    length: usize,
    flags: u32,
    address: *mut u8,
    address_len: *mut u32,
) -> isize {
    unimplemented!()
}

pub fn sys_getsockname(sockfd: usize, addr: usize, addrlen_ptr: usize) -> isize {
    unimplemented!()
}

pub fn sys_getpeername(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    unimplemented!()
}

pub fn sys_socketpair(domain: u32, stype: u32, protocol: u32, sv: *mut u32) -> isize {
    unimplemented!()
}

pub fn sys_setsockopt(
    socket: usize,
    level: usize,
    option_name: usize,
    option_value: usize,
    option_len: u32,
) -> isize {
    unimplemented!()
}

pub fn sys_getsocketopt(
    socket: usize,
    level: usize,
    option_name: usize,
    option_value: *mut u8, // 用户空间缓冲区的虚拟地址
    option_len: *mut u32,  // 用户空间指向optlen的指针的虚拟地址
) -> isize {
    unimplemented!()
}

// 套接字选项层级常量
pub const SOL_SOCKET: usize = 1;

// 套接字选项常量
pub const SO_REUSEADDR: u32 = 2;
pub const SO_ERROR: u32 = 4;
pub const SO_BROADCAST: u32 = 6;

pub const SO_KEEPALIVE: u32 = 9;
pub const SO_OOBINLINE: u32 = 10;
pub const SO_LINGER: u32 = 13;

pub const SO_RCVTIMEO: usize = 20; // 接收超时
pub const SO_SNDTIMEO: usize = 21; // 发送超时
pub const SO_DOMAIN: usize = 39; // 套接字域（AF_INET / AF_INET6 …）
pub const SO_PROTOCOL: usize = 38; // 套接字协议（IPPROTO_TCP / IPPROTO_UDP …）
pub const SO_TYPE: usize = 3; // 套接字类型（SOCK_STREAM / SOCK_DGRAM …）
pub const SO_SNDBUF: usize = 7; // 发送缓冲区大小
pub const SO_RCVBUF: usize = 8; // 接收缓冲区大小

// TCP 选项常量
pub const TCP_NODELAY: u32 = 1;
pub const TCP_MAXSEG: u32 = 2;
pub const TCP_KEEPIDLE: u32 = 4;
pub const TCP_KEEPINTVL: u32 = 5;
pub const TCP_KEEPCNT: u32 = 6;

// 套接字类型常量
pub const SOCK_STREAM: u32 = 1;

// 添加IP选项常量定义（通常来自Linux netinet/in.h）
pub const IP_TOS: u32 = 1; // IP服务类型
pub const IP_TTL: u32 = 2; // IP生存时间
pub const IP_RECVTTL: u32 = 12; // 接收TTL字段
