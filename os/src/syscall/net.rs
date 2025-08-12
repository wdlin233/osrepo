use alloc::{format, string::ToString};
use alloc::{sync::Arc, vec, vec::Vec};
use core::ffi::{c_char, c_int, c_void};
use core::mem::size_of;
use core::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use spin::Mutex;

use crate::{
    fs::{File, FileClass, FileDescriptor, OpenFlags},
    mm::{translated_byte_buffer, translated_ref, translated_refmut, UserBuffer},
    net::{socket::PollState, Socket, TcpSocket, UdpSocket},
    task::current_process,
    utils::{SysErrNo, SyscallRet},
};

use log::debug;

const AF_INET: u32 = 2;

pub fn sys_socket(domain: u32, socktype: u32, protocol: u32) -> isize {
    debug!("sys_socket <= {} {} {}", domain, socktype, protocol);
    let (domain, socktype, protocol) = (domain as u32, socktype as u32, protocol as u32);

    match (domain, socktype, protocol) {
        (AF_INET, SOCK_STREAM, IPPROTO_TCP) | (AF_INET, SOCK_STREAM, 0) => {
            let sock = Socket::Tcp(Mutex::new(TcpSocket::new()));
            let flags = 0;
            let process = current_process();
            let inner = process.inner_exclusive_access();
            let fd = inner.fd_table.alloc_fd().unwrap();
            inner.fd_table.set(
                fd,
                FileDescriptor::new(flags, FileClass::Sock(Arc::new(sock))),
            );
            fd as isize
        }
        (AF_INET, SOCK_DGRAM, IPPROTO_UDP) | (AF_INET, SOCK_DGRAM, 0) => {
            let sock = Socket::Udp(Mutex::new(UdpSocket::new()));
            let process = current_process();
            let inner = process.inner_exclusive_access();
            let fd = inner.fd_table.alloc_fd().unwrap();
            inner.fd_table.set(
                fd,
                FileDescriptor::new(flags, FileClass::Sock(Arc::new(sock))),
            );
            fd as isize
        }
        _ => SysErrNo::EINVAL as isize,
    }
}

pub fn sys_getsockname(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    unimplemented!()
}

pub fn sys_getpeername(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    unimplemented!()
}

pub fn sys_sendto(
    _sockfd: usize,
    _buf: *const u8,
    _len: usize,
    _flags: u32,
    _dest_addr: *const u8,
    _addrlen: u32,
) -> isize {
    unimplemented!()
}

pub fn sys_accept(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    unimplemented!()
}

pub fn sys_accept4(_sockfd: usize, _addr: *const u8, _addrlen: u32, _flags: u32) -> isize {
    unimplemented!()
}

pub fn sys_sendmsg(_sockfd: usize, _addr: *const u8, _flags: u32) -> isize {
    unimplemented!()
}
pub fn sys_recvfrom(
    _sockfd: usize,
    buf: *mut u8,
    _len: usize,
    _flags: u32,
    _src_addr: *const u8,
    _addrlen: u32,
) -> isize {
    unimplemented!()
}

pub fn sys_listen(sockfd: usize, backlog: u32) -> isize {
    unimplemented!()
}

pub fn sys_socketpair(domain: u32, stype: u32, protocol: u32, sv: *mut u32) -> isize {
    unimplemented!()
}

pub fn sys_connect(sockfd: usize, addr: *const u8, addrlen: u32) -> isize {
    unimplemented!()
}

pub fn sys_setsockopt(
    sockfd: usize,
    level: u32,
    optname: u32,
    optval: usize,
    optlen: u32,
) -> isize {
    unimplemented!()
}

pub fn sys_bind(sockfd: usize, addr: usize, addrlen: u32) -> isize {
    unimplemented!()
}
pub fn sys_getsocketopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,     // 用户空间缓冲区的虚拟地址
    optlen_ptr: usize, // 用户空间指向optlen的指针的虚拟地址
) -> isize {
    unimplemented!()
}

// 套接字选项层级常量
pub const SOL_SOCKET: u32 = 1;
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;
pub const IPPROTO_IP: u32 = 0;

// 套接字选项常量
pub const SO_REUSEADDR: u32 = 2;
pub const SO_TYPE: u32 = 3;
pub const SO_ERROR: u32 = 4;
pub const SO_BROADCAST: u32 = 6;
pub const SO_SNDBUF: u32 = 7;
pub const SO_RCVBUF: u32 = 8;
pub const SO_KEEPALIVE: u32 = 9;
pub const SO_OOBINLINE: u32 = 10;
pub const SO_LINGER: u32 = 13;
pub const SO_RCVTIMEO: u32 = 20;
pub const SO_SNDTIMEO: u32 = 21;

// TCP 选项常量
pub const TCP_NODELAY: u32 = 1;
pub const TCP_MAXSEG: u32 = 2;
pub const TCP_KEEPIDLE: u32 = 4;
pub const TCP_KEEPINTVL: u32 = 5;
pub const TCP_KEEPCNT: u32 = 6;

// 套接字类型常量
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;

// 添加IP选项常量定义（通常来自Linux netinet/in.h）
pub const IP_TOS: u32 = 1; // IP服务类型
pub const IP_TTL: u32 = 2; // IP生存时间
pub const IP_RECVTTL: u32 = 12; // 接收TTL字段
