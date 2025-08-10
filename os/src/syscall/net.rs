use core::u32;

use alloc::{format, string::ToString, sync::Arc};

use crate::{
    fs::{
        make_socket, make_socketpair, udp_connect, File, FileClass, FileDescriptor, OpenFlags,
        SockAddrIn, SocketAddrIn, TcpSocket, UdpSocket, AF_INET,
    },
    mm::{translated_byte_buffer, translated_ref, translated_refmut, UserBuffer},
    net::{
        self, connection::Connection, SocketAddress, SocketDomain, SocketFd, SocketMsghdr,
        SocketProtocol, SocketType, Timeval,
    },
    task::current_process,
    utils::{SysErrNo, SyscallRet},
};
use alloc::{boxed::Box, collections::btree_map::BTreeMap, sync::Arc};
use core::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
    sync::atomic::{AtomicI32, Ordering},
    time::Duration,
};
use smoltcp::wire::{IpAddress, IpEndpoint};
use spin::rwlock::RwLock;

use log::debug;

pub fn sys_socket(domain: u32, type_: u32, protocol_: u32) -> isize {
    const SO_NONBLOCK: usize = 2048;
    const SOCK_CLOEXEC: usize = 0o2000000;
    const O_NONBLOCK: usize = SO_NONBLOCK;
    const O_CLOEXEC: usize = SOCK_CLOEXEC;
    let Ok(socket_domain) = SocketDomain::try_from(domain) else {
        // The implementation does not support the specified address family.
        return SysErrNo::EAFNOSUPPORT as isize;
    };

    let Ok(socket_type) = SocketType::try_from(type_) else {
        // The socket type is not supported by the address family, or the socket type is not supported by the implementation.
        return SysErrNo::EPROTOTYPE as isize;
    };

    let Ok(socket_protocol) = SocketProtocol::try_from(protocol_) else {
        // Posix ERRORS : The value of protocol is non-zero and either the protocol is not supported by the address family or the protocol is not supported by the implementation.
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

    let socket = inner.fd_table.alloc_fd().unwrap() as SocketFd;
    let mut connection = Connection::new(socket, socket_domain, socket_type, socket_protocol);

    connection.set_is_nonblocking((type_ & SO_NONBLOCK) != 0);

    debug!("sys socket, to connection create");
    match connection.create() {
        Ok(_) => inner.fd_table.set(socket as usize, FileDescriptor),
        Err(_) => {
            return -1;
        }
    }
    if let Err(e) = sock_attach_to_fd(socket, Arc::new(connection)) {
        log::error!("sock_attach_to_fd socket fd={} error: {}", socket, e);
        -1
    } else {
        socket
    }
}

pub fn sys_bind(sockfd: usize, addr: usize, addrlen: u32) -> isize {
    log::debug!("fd={}: Binding", socket);

    let Ok(connection) = get_sock_by_fd(socket) else {
        log::error!("fd={}: not a valid file descriptor.", socket);
        return -libc::EBADF;
    };

    if connection.is_bound() {
        log::warn!("The socket is already bound to an address");
        return -libc::EINVAL;
    }

    let Some(socket_addr) = (unsafe { SocketAddress::from_ptr(address, address_len) }) else {
        log::error!("fd={}: Invalid Address", socket);
        return -libc::EBADF;
    };

    let Some(local_endpoint) = socket_addr.create_ip_endpoint() else {
        log::error!("fd={}: Parse endpoint fail", socket);
        return -libc::EADDRNOTAVAIL;
    };

    connection
        .bind(local_endpoint)
        .map(|_| 0)
        .map_err(|e| log::debug!("bind fail {:#?}", e))
        .unwrap_or(-1)
}

pub fn sys_listen(sockfd: usize, backlog: u32) -> isize {
    log::debug!("fd={}: Listening (backlog={})", socket, backlog);

    let Ok(connection) = get_sock_by_fd(socket) else {
        log::error!("fd={}: not a valid file descriptor.", socket);
        return -libc::EBADF;
    };

    if connection.socket_type() == SocketType::SockDgram
        || connection.socket_type() == SocketType::SockRaw
    {
        log::warn!("fd={}: socket protocol does not support listen()", socket);
        return -libc::EOPNOTSUPP;
    }

    if !connection.is_bound() {
        log::warn!("fd={}: socket is unbound", socket);
        return -libc::EDESTADDRREQ;
    }
    connection.listen().map(|_| 0).unwrap_or(-1)
}

pub fn sys_accept(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    log::debug!("fd={}: Accepting connection", socket);

    if let Err(e) = get_sock_by_fd(socket) {
        log::warn!("fd={}: not a valid file descriptor", socket);
        -libc::EBADF
    } else {
        // return socket fd when exit, do not support backlog
        socket
    }
}

pub fn sys_accept4(_sockfd: usize, _addr: *const u8, _addrlen: u32, _flags: u32) -> isize {
    unimplemented!()
}

pub fn sys_connect(sockfd: usize, addr: *const u8, addrlen: u32) -> isize {
    log::debug!("fd={}: Connecting", socket);

    let Ok(connection) = get_sock_by_fd(socket) else {
        log::error!("fd={}: not a valid file descriptor.", socket);
        return -libc::EBADF;
    };

    let Some(socket_addr) = (unsafe { SocketAddress::from_ptr(address, address_len) }) else {
        log::error!("fd={}: Invalid Address", socket);
        return -libc::EBADF;
    };

    let Some(remote_endpoint) = socket_addr.create_ip_endpoint() else {
        log::error!("fd={}: Parse endpoint fail", socket);
        return -libc::EADDRNOTAVAIL;
    };

    connection.connect(remote_endpoint).map(|_| 0).unwrap_or(-1)
}
pub fn sys_sendto(
    _sockfd: usize,
    _buf: *const u8,
    _len: usize,
    _flags: u32,
    _dest_addr: *const u8,
    _addrlen: u32,
) -> isize {
    log::debug!("fd={}: Sending to (flags={})", socket, flags);

    let Ok(connection) = get_sock_by_fd(socket) else {
        log::error!("fd={}: not a valid file descriptor.", socket);
        return -libc::EBADF as c_ssize_t;
    };

    if connection.socket_type() == SocketType::SockStream
        || connection.socket_type() == SocketType::SockRaw
    {
        log::warn!("fd={}: socket protocol does not support sendto()", socket);
        return -libc::EOPNOTSUPP as c_ssize_t;
    }

    if message.is_null() || length == 0 {
        return -1;
    }

    let Some(socket_addr) = (unsafe { SocketAddress::from_ptr(dest_addr, dest_len) }) else {
        log::error!("fd={}: Invalid Address", socket);
        return -libc::EBADF as c_ssize_t;
    };

    let Some(remote_endpoint) = socket_addr.create_ip_endpoint() else {
        log::error!("fd={}: Parse endpoint fail", socket);
        return -libc::EADDRNOTAVAIL as c_ssize_t;
    };

    let buf = unsafe { core::slice::from_raw_parts(message as *const u8, length) };

    connection
        .sendto(buf, flags, remote_endpoint)
        .map(|send_sizes| send_sizes.try_into().unwrap_or(-1))
        .unwrap_or(-1)
}

pub fn sys_sendmsg(_sockfd: usize, _addr: *const u8, _flags: u32) -> isize {
    log::debug!("fd={}: sendmsg to (flags={})", socket, flags);

    let Ok(connection) = get_sock_by_fd(socket) else {
        log::error!("fd={}: not a valid file descriptor.", socket);
        return -libc::EBADF as c_ssize_t;
    };

    // sendmsg only support icmp/icmpv6 now
    if connection.socket_type() == SocketType::SockStream
        || connection.socket_type() == SocketType::SockDgram
        || !(connection.socket_protocol() == SocketProtocol::Icmp
            || connection.socket_protocol() == SocketProtocol::Icmpv6)
    {
        log::warn!("fd={}: socket protocol does not support sendmsg()", socket);
        return -libc::EOPNOTSUPP as c_ssize_t;
    }

    let Some(msghdr) = (unsafe { SocketMsghdr::from_ptr(message) }) else {
        log::error!("Parse Msghdr fail");
        return 0;
    };

    let Some(remote_endpoint) = msghdr.endpoint() else {
        log::error!("Parse endpoint fail");
        return 0;
    };

    // Get packet len
    let packet_len = msghdr.packet_len();

    let identifer = msghdr.parse_icmp_identifier();

    let iov_buffer_ptr = msghdr.msg_iov as usize;
    let iov_buffer_len = msghdr.msg_iovlen;

    // Copy buffer into packet
    let send_payload = Box::new(move |packet: &mut [u8]| -> usize {
        SocketMsghdr::gather_to_buffer(
            iov_buffer_ptr as *const libc::iovec,
            iov_buffer_len as usize,
            packet,
        )
    });

    connection
        .sendmsg(remote_endpoint, identifer, packet_len, send_payload)
        .map(|send_sizes| send_sizes.try_into().unwrap_or(-1))
        .unwrap_or(-1)
}

pub fn sys_recvfrom(
    _sockfd: usize,
    buf: *mut u8,
    _len: usize,
    _flags: u32,
    _src_addr: *const u8,
    _addrlen: u32,
) -> isize {
    log::debug!("fd={}: recvfrom to (flags={})", socket, flags);

    let Ok(connection) = get_sock_by_fd(socket) else {
        log::error!("fd={}: not a valid file descriptor.", socket);
        return -libc::EBADF as c_ssize_t;
    };

    if connection.socket_type() == SocketType::SockStream
        || connection.socket_type() == SocketType::SockRaw
    {
        log::warn!("fd={}: socket protocol does not support recvfrom()", socket);
        return -libc::EOPNOTSUPP as c_ssize_t;
    }

    if buffer.is_null() || length == 0 {
        return -1;
    }
    let buffer = buffer as *mut u8;
    #[allow(unused_mut)]
    let mut buffer = unsafe { core::slice::from_raw_parts_mut(buffer, length) };

    let recv_addr = if address.is_null() || address_len.is_null() {
        None
    } else {
        Some((unsafe { &mut *address }, unsafe { &mut *address_len }))
    };

    let recv_payload = Box::new(move |recv_buffer: &[u8], endpoint: IpEndpoint| -> usize {
        log::debug!("Received packet from {:?}", endpoint);

        if let Some((mut address_ref, mut address_len_ref)) = recv_addr {
            net::write_to_sockaddr(
                endpoint,
                address_ref as *mut libc::sockaddr,
                address_len_ref as *mut libc::socklen_t,
            );
        }

        let recv_len = core::cmp::min(recv_buffer.len(), length as usize);
        buffer[..recv_len].copy_from_slice(&recv_buffer[..recv_len]);
        recv_len
    });

    connection
        .recvfrom(recv_payload)
        .map(|recv_sized| recv_sized.try_into().unwrap_or(-1))
        .unwrap_or(-1)
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
    sockfd: usize,
    level: u32,
    optname: u32,
    optval: usize,
    optlen: u32,
) -> isize {
    log::debug!("fd={}: setsockopt ", socket);

    let Ok(connection) = get_sock_by_fd(socket) else {
        log::error!("fd={}: not a valid file descriptor.", socket);
        return -libc::EBADF;
    };

    // option_name suppose to contain only one option
    if level == libc::SOL_SOCKET {
        if (option_name & libc::SO_RCVTIMEO) != 0 {
            return match unsafe { Timeval::from_ptr(option_value, option_len) } {
                Some(timeval) => {
                    connection.set_recv_timeout(Duration::from(timeval));
                    0
                }
                None => -1,
            };
        }

        if (option_name & libc::SO_SNDTIMEO) != 0 {
            return match unsafe { Timeval::from_ptr(option_value, option_len) } {
                Some(timeval) => {
                    connection.set_send_timeout(Duration::from(timeval));
                    0
                }
                None => -1,
            };
        }

        // The specified option is invalid at the specified socket level.
        -libc::EINVAL
    } else {
        // Do not support level other than SOL_SOCKET, like TCP...
        // The option is not supported by the protocol.
        -libc::ENOPROTOOPT
    }
}

pub fn sys_getsocketopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,     // 用户空间缓冲区的虚拟地址
    optlen_ptr: usize, // 用户空间指向optlen的指针的虚拟地址
) -> isize {
    log::debug!("fd={}: getsockopt ", socket);

    let Ok(connection) = get_sock_by_fd(socket) else {
        log::error!("fd={}: not a valid file descriptor", socket);
        return -libc::EBADF;
    };

    if option_value.is_null() || option_len.is_null() {
        return -libc::EINVAL;
    }
    if level == libc::SOL_SOCKET {
        if (option_name & libc::SO_RCVTIMEO) != 0 {
            let timeval = Timeval::from(connection.get_recv_timeout());
            unsafe {
                core::ptr::copy_nonoverlapping(&timeval, option_value as *mut Timeval, ONE_ELEMENT);
                *option_len = size_of::<Timeval>() as u32;
            }
            return 0;
        }

        if (option_name & libc::SO_SNDTIMEO) != 0 {
            let timeval = Timeval::from(connection.get_send_timeout());
            unsafe {
                core::ptr::copy_nonoverlapping(&timeval, option_value as *mut Timeval, ONE_ELEMENT);
                *option_len = size_of::<Timeval>() as u32;
            }
            return 0;
        }

        if (option_name & libc::SO_DOMAIN) != 0 {
            return connection
                .socket_domain()
                .write_to_ptr(option_value, option_len)
                .map(|()| 0)
                .unwrap_or(-1);
        }

        if (option_name & libc::SO_PROTOCOL) != 0 {
            return connection
                .socket_protocol()
                .into_ptr(option_value, option_len)
                .map(|()| 0)
                .unwrap_or(-1);
        }

        if (option_name & libc::SO_TYPE) != 0 {
            return connection
                .socket_type()
                .write_to_ptr(option_value, option_len)
                .map(|()| 0)
                .unwrap_or(-1);
        }

        // TODO
        if (option_name & libc::SO_SNDBUF) != 0 {
            return -1;
        }

        // TODO
        if (option_name & libc::SO_RCVBUF) != 0 {
            return -1;
        }

        // The specified option is invalid at the specified socket level.
        -libc::EINVAL
    } else {
        // Do not support level other than SOL_SOCKET, like TCP...
        // The option is not supported by the protocol.
        -libc::ENOPROTOOPT
    }
}

// 套接字选项层级常量
pub const SOL_SOCKET: u32 = 1;
pub const IPPROTO_TCP: u32 = 6;
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

// 添加IP选项常量定义（通常来自Linux netinet/in.h）
pub const IP_TOS: u32 = 1; // IP服务类型
pub const IP_TTL: u32 = 2; // IP生存时间
pub const IP_RECVTTL: u32 = 12; // 接收TTL字段
