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
    net::socket_impl::SockaddrIn,
    task::current_process,
    utils::{SysErrNo, SyscallRet},
};

use log::debug;

const AF_INET: u32 = 2;

pub fn sys_socket(domain: u32, socktype: u32, protocol: u32) -> isize {
    debug!("sys_socket <= {} {} {}", domain, socktype, protocol);
    let (domain, socktype, protocol) = (domain as u32, socktype as u32, protocol as u32);
    let flags = OpenFlags::empty(); // Define flags here for both branches

    match (domain, socktype, protocol) {
        (AF_INET, SOCK_STREAM, IPPROTO_TCP) | (AF_INET, SOCK_STREAM, 0) => {
            let sock = Socket::Tcp(Mutex::new(TcpSocket::new()));
            let process = current_process();
            let inner = process.inner_exclusive_access();
            let fd = match inner.fd_table.alloc_fd() {
                Ok(fd) => fd,
                Err(_) => return SysErrNo::EMFILE as isize,
            };
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
            let fd = match inner.fd_table.alloc_fd() {
                Ok(fd) => fd,
                Err(_) => return SysErrNo::EMFILE as isize, 
            };
            inner.fd_table.set(
                fd,
                FileDescriptor::new(flags, FileClass::Sock(Arc::new(sock))),
            );
            fd as isize
        }
        _ => SysErrNo::EINVAL as isize,
    }
}

pub fn sys_getsockname(sockfd: usize, addr: *mut u8, addrlen: *mut u32) -> isize {
    debug!("sys_getsockname <= sockfd: {}, addr: {:?}, addrlen: {:?}", sockfd, addr, addrlen);
    
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    
    if sockfd >= inner.fd_table.len() || inner.fd_table.try_get(sockfd).is_none() {
        return SysErrNo::EBADF as isize;
    }
    
    let socket = match inner.fd_table.get(sockfd).file.sock() {
        Ok(socket_arc) => socket_arc,
        Err(_) => return SysErrNo::ENOTSOCK as isize,
    };
    
    let local_addr = match socket.local_addr() {
        Ok(addr) => addr,
        Err(_) => return SysErrNo::EINVAL as isize,
    };
    
    let sockaddr_in = match local_addr {
        SocketAddr::V4(addr) => SockaddrIn {
            sin_family: AF_INET as u16,
            sin_port: addr.port().to_be(),
            sin_addr: crate::net::socket_impl::Inaddr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            },
            sin_zero: [0; 8],
        },
        SocketAddr::V6(_) => return SysErrNo::EAFNOSUPPORT as isize,
    };
    
    let sockaddr_len = size_of::<SockaddrIn>() as u32;
    
    if addr.is_null() || addrlen.is_null() {
        return SysErrNo::EFAULT as isize;
    }
    
    let addrlen_ref = translated_refmut(token, addrlen);
    let provided_len = *addrlen_ref;
    if provided_len < sockaddr_len {
        return SysErrNo::EINVAL as isize;
    }
    
    let addr_ref = translated_refmut(token, addr as *mut SockaddrIn);
    *addr_ref = sockaddr_in;
    *addrlen_ref = sockaddr_len;
    
    debug!("sys_getsockname addr: {:?}, len: {}", local_addr, sockaddr_len);
    0
}

pub fn sys_getpeername(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    unimplemented!()
}

pub fn sys_sendto(
    sockfd: usize,
    buf: *const u8,
    len: usize,
    flags: u32,
    dest_addr: *const u8,
    addrlen: u32,
) -> isize {
    debug!("sys_sendto <= sockfd: {}, buf: {:?}, len: {}, flags: {}, dest_addr: {:?}, addrlen: {}", 
           sockfd, buf, len, flags, dest_addr, addrlen);
    
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    
    if sockfd >= inner.fd_table.len() || inner.fd_table.try_get(sockfd).is_none() {
        return SysErrNo::EBADF as isize;
    }
    
    let socket_arc = match inner.fd_table.get(sockfd).file.sock() {
        Ok(socket_arc) => socket_arc,
        Err(_) => return SysErrNo::ENOTSOCK as isize,
    };
    
    if buf.is_null() || len == 0 {
        return SysErrNo::EFAULT as isize;
    }
    
    let dest_socket_addr = if !dest_addr.is_null() && addrlen > 0 {
        if addrlen < size_of::<SockaddrIn>() as u32 {
            return SysErrNo::EINVAL as isize;
        }
        
        // Safely read sockaddr_in structure by using safe copy
        if dest_addr as usize + size_of::<SockaddrIn>() < dest_addr as usize {
            return SysErrNo::EFAULT as isize;
        }
        
        let sockaddr_bytes = match translated_byte_buffer(token, dest_addr, size_of::<SockaddrIn>()) {
            buffer if !buffer.is_empty() => {
                let mut data = [0u8; size_of::<SockaddrIn>()];
                let mut offset = 0;
                for slice in buffer {
                    let copy_len = (data.len() - offset).min(slice.len());
                    data[offset..offset + copy_len].copy_from_slice(&slice[..copy_len]);
                    offset += copy_len;
                    if offset >= data.len() {
                        break;
                    }
                }
                if offset < data.len() {
                    return SysErrNo::EFAULT as isize;
                }
                data
            }
            _ => return SysErrNo::EFAULT as isize,
        };
        
        let sockaddr_in = unsafe { *(sockaddr_bytes.as_ptr() as *const SockaddrIn) };
        
        if sockaddr_in.sin_family as u32 != AF_INET {
            return SysErrNo::EAFNOSUPPORT as isize;
        }
        
        // Convert from network byte order
        let port = u16::from_be(sockaddr_in.sin_port);
        let ip = Ipv4Addr::from(u32::from_be(sockaddr_in.sin_addr.s_addr));
        
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else {
        None
    };
    
    let user_buf = translated_byte_buffer(token, buf, len);
    let mut data = Vec::new();
    for slice in user_buf {
        data.extend_from_slice(slice);
    }
    
    debug!("sys_sendto: sending {} bytes to {:?}", data.len(), dest_socket_addr);
    
    drop(inner);
    
    match dest_socket_addr {
        Some(addr) => {
            // For UDP sockets, ensure they are bound before sending
            if let Err(e) = socket_arc.local_addr() {
                debug!("sys_sendto: socket not bound, attempting to bind to any address");
                let any_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
                if let Err(bind_err) = socket_arc.bind(any_addr) {
                    debug!("sys_sendto: failed to auto-bind socket: {:?}", bind_err);
                    return -(SysErrNo::EADDRNOTAVAIL as isize);
                }
            }
            
            // Use sendto with specific destination address
            match socket_arc.sendto(&data, addr) {
                Ok(sent_bytes) => {
                    debug!("sys_sendto: sent {} bytes to {}", sent_bytes, addr);
                    sent_bytes as isize
                }
                Err(e) => {
                    debug!("sys_sendto: sendto failed with error {:?}", e);
                    match e {
                        crate::net::AxError::WouldBlock => -(SysErrNo::EAGAIN as isize),
                        crate::net::AxError::NotConnected => -(SysErrNo::ENOTCONN as isize),
                        crate::net::AxError::ConnectionReset => -(SysErrNo::ECONNRESET as isize),
                        crate::net::AxError::NoMemory => -(SysErrNo::ENOMEM as isize),
                        crate::net::AxError::InvalidInput => -(SysErrNo::EINVAL as isize),
                        _ => -(SysErrNo::EIO as isize),
                    }
                }
            }
        }
        None => {
            // Use regular write (for connected sockets)
            match socket_arc.write(&data) {
                Ok(sent_bytes) => {
                    debug!("sys_sendto: sent {} bytes via write", sent_bytes);
                    sent_bytes as isize
                }
                Err(e) => {
                    debug!("sys_sendto: write failed with error {:?}", e);
                    match e {
                        crate::net::AxError::WouldBlock => -(SysErrNo::EAGAIN as isize),
                        crate::net::AxError::NotConnected => -(SysErrNo::ENOTCONN as isize),
                        crate::net::AxError::ConnectionReset => -(SysErrNo::ECONNRESET as isize),
                        crate::net::AxError::NoMemory => -(SysErrNo::ENOMEM as isize),
                        crate::net::AxError::InvalidInput => -(SysErrNo::EINVAL as isize),
                        _ => -(SysErrNo::EIO as isize),
                    }
                }
            }
        }
    }
}

pub fn sys_accept(sockfd: usize, addr: *mut u8, addrlen: *mut u32) -> isize {
    debug!("sys_accept <= sockfd: {}, addr: {:?}, addrlen: {:?}", sockfd, addr, addrlen);
    
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    
    if sockfd >= inner.fd_table.len() || inner.fd_table.try_get(sockfd).is_none() {
        return SysErrNo::EBADF as isize;
    }
    
    let socket_arc = match inner.fd_table.get(sockfd).file.sock() {
        Ok(socket_arc) => socket_arc,
        Err(_) => return SysErrNo::ENOTSOCK as isize,
    };
    
    let need_peer_addr = !addr.is_null() && !addrlen.is_null();
    let provided_len = if need_peer_addr {
        Some(*translated_refmut(token, addrlen))
    } else {
        None
    };
    
    drop(inner);
    
    match socket_arc.accept() {
        Ok((new_socket, peer_addr)) => {
            debug!("sys_accept: accepted connection from {:?}", peer_addr);
            
            let process = current_process();
            let inner = process.inner_exclusive_access();
            let flags = OpenFlags::empty();
            let new_fd = match inner.fd_table.alloc_fd() {
                Ok(fd) => fd,
                Err(_) => return SysErrNo::EMFILE as isize, 
            };
            inner.fd_table.set(
                new_fd,
                FileDescriptor::new(flags, FileClass::Sock(new_socket)),
            );
            
            // peer address?
            if need_peer_addr {
                let token = inner.get_user_token();
                if let Some(len) = provided_len {
                    if len >= size_of::<SockaddrIn>() as u32 {
                        if let SocketAddr::V4(addr_v4) = peer_addr {
                            let sockaddr_in = SockaddrIn {
                                sin_family: AF_INET as u16,
                                sin_port: addr_v4.port().to_be(),
                                sin_addr: crate::net::socket_impl::Inaddr {
                                    s_addr: u32::from_be_bytes(addr_v4.ip().octets()),
                                },
                                sin_zero: [0; 8],
                            };
                            
                            let addr_ref = translated_refmut(token, addr as *mut SockaddrIn);
                            *addr_ref = sockaddr_in;
                            let addrlen_ref = translated_refmut(token, addrlen);
                            *addrlen_ref = size_of::<SockaddrIn>() as u32;
                        }
                    }
                }
            }
            
            new_fd as isize
        }
        Err(e) => {
            debug!("sys_accept: accept failed with error {:?}", e);
            match e {
                crate::net::AxError::WouldBlock => -(SysErrNo::EAGAIN as isize),
                crate::net::AxError::InvalidInput => -(SysErrNo::EINVAL as isize),
                crate::net::AxError::NotConnected => -(SysErrNo::ENOTCONN as isize),
                _ => -(SysErrNo::EIO as isize),
            }
        }
    }
}

pub fn sys_accept4(_sockfd: usize, _addr: *const u8, _addrlen: u32, _flags: u32) -> isize {
    unimplemented!()
}

pub fn sys_sendmsg(_sockfd: usize, _addr: *const u8, _flags: u32) -> isize {
    unimplemented!()
}
pub fn sys_recvfrom(
    sockfd: usize,
    buf: *mut u8,
    len: usize,
    flags: u32,
    src_addr: *mut u8,
    addrlen: *mut u32,
) -> isize {
    debug!("sys_recvfrom <= sockfd: {}, buf: {:?}, len: {}, flags: {}, src_addr: {:?}, addrlen: {:?}", 
           sockfd, buf, len, flags, src_addr, addrlen);
    
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    
    if sockfd >= inner.fd_table.len() || inner.fd_table.try_get(sockfd).is_none() {
        return SysErrNo::EBADF as isize;
    }
    
    let socket_arc = match inner.fd_table.get(sockfd).file.sock() {
        Ok(socket_arc) => socket_arc,
        Err(_) => return SysErrNo::ENOTSOCK as isize,
    };
    
    if buf.is_null() || len == 0 {
        return SysErrNo::EFAULT as isize;
    }
    
    let user_buf = translated_byte_buffer(token, buf, len);
    let mut receive_buffer = vec![0u8; len];
    
    drop(inner);
    
    match socket_arc.recvfrom(&mut receive_buffer) {
        Ok((received_bytes, src_socket_addr)) => {
            debug!("sys_recvfrom: received {} bytes from {:?}", received_bytes, src_socket_addr);
            
            // user buffer
            let mut offset = 0;
            for slice in user_buf {
                let copy_len = (received_bytes - offset).min(slice.len());
                slice[..copy_len].copy_from_slice(&receive_buffer[offset..offset + copy_len]);
                offset += copy_len;
                if offset >= received_bytes {
                    break;
                }
            }
            
            if !src_addr.is_null() && !addrlen.is_null() && src_socket_addr.is_some() {
                let process = current_process();
                let inner = process.inner_exclusive_access();
                let token = inner.get_user_token();
                
                let addrlen_ref = translated_refmut(token, addrlen);
                let provided_len = *addrlen_ref;
                
                if let Some(addr) = src_socket_addr {
                    if provided_len >= size_of::<SockaddrIn>() as u32 {
                        if let SocketAddr::V4(addr_v4) = addr {
                            let sockaddr_in = SockaddrIn {
                                sin_family: AF_INET as u16,
                                sin_port: addr_v4.port().to_be(),
                                sin_addr: crate::net::socket_impl::Inaddr {
                                    s_addr: u32::from_ne_bytes(addr_v4.ip().octets()),
                                },
                                sin_zero: [0; 8],
                            };
                            
                            let addr_ref = translated_refmut(token, src_addr as *mut SockaddrIn);
                            *addr_ref = sockaddr_in;
                            *addrlen_ref = size_of::<SockaddrIn>() as u32;
                        }
                    }
                }
            }
            
            received_bytes as isize
        }
        Err(e) => {
            debug!("sys_recvfrom: recvfrom failed with error {:?}", e);
            match e {
                crate::net::AxError::WouldBlock => -(SysErrNo::EAGAIN as isize),
                crate::net::AxError::NotConnected => -(SysErrNo::ENOTCONN as isize),
                crate::net::AxError::ConnectionReset => -(SysErrNo::ECONNRESET as isize),
                crate::net::AxError::NoMemory => -(SysErrNo::ENOMEM as isize),
                crate::net::AxError::InvalidInput => -(SysErrNo::EINVAL as isize),
                _ => -(SysErrNo::EIO as isize),
            }
        }
    }
}

pub fn sys_listen(sockfd: usize, backlog: u32) -> isize {
    debug!("sys_listen <= sockfd: {}, backlog: {}", sockfd, backlog);
    
    let process = current_process();
    let inner = process.inner_exclusive_access();
    
    if sockfd >= inner.fd_table.len() || inner.fd_table.try_get(sockfd).is_none() {
        return SysErrNo::EBADF as isize;
    }
    
    let socket_arc = match inner.fd_table.get(sockfd).file.sock() {
        Ok(socket_arc) => socket_arc,
        Err(_) => return SysErrNo::ENOTSOCK as isize,
    };
    
    drop(inner);
    
    match socket_arc.listen(backlog as i32) {
        Ok(_) => {
            debug!("sys_listen: successfully set socket to listen mode with backlog {}", backlog);
            0
        }
        Err(e) => {
            debug!("sys_listen: listen failed with error {:?}", e);
            match e {
                crate::net::AxError::InvalidInput => SysErrNo::EINVAL as isize,
                crate::net::AxError::Unsupported => SysErrNo::EOPNOTSUPP as isize,
                crate::net::AxError::BadState => SysErrNo::EINVAL as isize,
                _ => SysErrNo::EINVAL as isize,
            }
        }
    }
}

pub fn sys_socketpair(_domain: u32, _stype: u32, _protocol: u32, _sv: *mut u32) -> isize {
    unimplemented!()
}

pub fn sys_connect(sockfd: usize, addr: *const u8, addrlen: u32) -> isize {
    debug!("sys_connect <= sockfd: {}, addr: {:?}, addrlen: {}", sockfd, addr, addrlen);
    
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    
    if sockfd >= inner.fd_table.len() || inner.fd_table.try_get(sockfd).is_none() {
        return SysErrNo::EBADF as isize;
    }
    
    let socket_arc = match inner.fd_table.get(sockfd).file.sock() {
        Ok(socket_arc) => socket_arc,
        Err(_) => return SysErrNo::ENOTSOCK as isize,
    };
    
    if addr.is_null() || addrlen < size_of::<SockaddrIn>() as u32 {
        return SysErrNo::EFAULT as isize;
    }
    
    if addr as usize + size_of::<SockaddrIn>() < addr as usize {
        return SysErrNo::EFAULT as isize;
    }
    
    let sockaddr_bytes = match translated_byte_buffer(token, addr, size_of::<SockaddrIn>()) {
        buffer if !buffer.is_empty() => {
            let mut data = [0u8; size_of::<SockaddrIn>()];
            let mut offset = 0;
            for slice in buffer {
                let copy_len = (data.len() - offset).min(slice.len());
                data[offset..offset + copy_len].copy_from_slice(&slice[..copy_len]);
                offset += copy_len;
                if offset >= data.len() {
                    break;
                }
            }
            if offset < data.len() {
                return SysErrNo::EFAULT as isize;
            }
            data
        }
        _ => return SysErrNo::EFAULT as isize,
    };
    
    let sockaddr_in = unsafe { *(sockaddr_bytes.as_ptr() as *const SockaddrIn) };
    
    if sockaddr_in.sin_family as u32 != AF_INET {
        return SysErrNo::EAFNOSUPPORT as isize;
    }
    
    let port = u16::from_be(sockaddr_in.sin_port);
    let ip = Ipv4Addr::from(u32::from_be(sockaddr_in.sin_addr.s_addr));
    let dest_addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    
    debug!("sys_connect: connecting to address {:?}", dest_addr);
    
    drop(inner);
    
    match socket_arc.connect(dest_addr) {
        Ok(_) => {
            debug!("sys_connect: successfully connected to {}", dest_addr);
            0
        }
        Err(e) => {
            debug!("sys_connect: connect failed with error {:?}", e);
            match e {
                crate::net::AxError::WouldBlock => -(SysErrNo::EINPROGRESS as isize),
                crate::net::AxError::AddrInUse => -(SysErrNo::EADDRINUSE as isize),
                crate::net::AxError::BadAddress => -(SysErrNo::EADDRNOTAVAIL as isize),
                crate::net::AxError::ConnectionRefused => -(SysErrNo::ECONNREFUSED as isize),
                crate::net::AxError::ConnectionReset => -(SysErrNo::ECONNRESET as isize),
                crate::net::AxError::InvalidInput => -(SysErrNo::EINVAL as isize),
                crate::net::AxError::NotFound => -(SysErrNo::ENETUNREACH as isize),
                _ => -(SysErrNo::ECONNREFUSED as isize),
            }
        }
    }
}

pub fn sys_setsockopt(
    sockfd: usize,
    level: u32,
    optname: u32,
    optval: usize,
    optlen: u32,
) -> isize {
    debug!("sys_setsockopt <= sockfd: {}, level: {}, optname: {}, optval: {:#x}, optlen: {}", 
           sockfd, level, optname, optval, optlen);
    
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    
    if sockfd >= inner.fd_table.len() || inner.fd_table.try_get(sockfd).is_none() {
        return SysErrNo::EBADF as isize;
    }
    
    let _socket = match inner.fd_table.get(sockfd).file.sock() {
        Ok(socket_arc) => socket_arc,
        Err(_) => return SysErrNo::ENOTSOCK as isize,
    };
    
    if optval == 0 || optlen == 0 {
        return SysErrNo::EFAULT as isize;
    }
    
    // 比较复杂的 level 处理
    match level {
        SOL_SOCKET => {
            match optname {
                SO_REUSEADDR => {
                    // SO_REUSEADDR expects an int (4 bytes)
                    if optlen < 4 {
                        return SysErrNo::EINVAL as isize;
                    }
                    
                    let value = unsafe { *translated_ref(token, optval as *const u32) };
                    let enable = value != 0;
                    
                    debug!("sys_setsockopt: SO_REUSEADDR = {}", enable);

                    // temp impl                
                    0
                }
                SO_BROADCAST => {
                    // SO_BROADCAST expects an int (4 bytes)
                    if optlen < 4 {
                        return SysErrNo::EINVAL as isize;
                    }
                    
                    let value = unsafe { *translated_ref(token, optval as *const u32) };
                    let enable = value != 0;
                    
                    debug!("sys_setsockopt: SO_BROADCAST = {}", enable);
                    
                    // For now, just return success
                    0
                }
                SO_KEEPALIVE => {
                    // SO_KEEPALIVE expects an int (4 bytes)
                    if optlen < 4 {
                        return SysErrNo::EINVAL as isize;
                    }
                    
                    let value = unsafe { *translated_ref(token, optval as *const u32) };
                    let enable = value != 0;
                    
                    debug!("sys_setsockopt: SO_KEEPALIVE = {}", enable);
                    
                    // For now, just return success
                    0
                }
                SO_RCVBUF | SO_SNDBUF => {
                    // Buffer size options expect an int (4 bytes)
                    if optlen < 4 {
                        return SysErrNo::EINVAL as isize;
                    }
                    
                    let value = unsafe { *translated_ref(token, optval as *const u32) };
                    
                    debug!("sys_setsockopt: {} = {}", 
                           if optname == SO_RCVBUF { "SO_RCVBUF" } else { "SO_SNDBUF" }, 
                           value);
                    
                    // For now, just return success
                    0
                }
                SO_RCVTIMEO | SO_SNDTIMEO => {
                    // Timeout options expect a struct timeval (8 bytes on 32-bit, 16 bytes on 64-bit)
                    if optlen < 8 {
                        return SysErrNo::EINVAL as isize;
                    }
                    
                    debug!("sys_setsockopt: {} with optlen {}", 
                           if optname == SO_RCVTIMEO { "SO_RCVTIMEO" } else { "SO_SNDTIMEO" }, 
                           optlen);
                    
                    // For now, just return success
                    0
                }
                _ => {
                    debug!("sys_setsockopt: unsupported SOL_SOCKET option {}", optname);
                    SysErrNo::ENOPROTOOPT as isize
                }
            }
        }
        IPPROTO_TCP => {
            match optname {
                TCP_NODELAY => {
                    // TCP_NODELAY expects an int (4 bytes)
                    if optlen < 4 {
                        return SysErrNo::EINVAL as isize;
                    }
                    
                    let value = unsafe { *translated_ref(token, optval as *const u32) };
                    let enable = value != 0;
                    
                    debug!("sys_setsockopt: TCP_NODELAY = {}", enable);
                    
                    // For now, just return success
                    0
                }
                _ => {
                    debug!("sys_setsockopt: unsupported IPPROTO_TCP option {}", optname);
                    SysErrNo::ENOPROTOOPT as isize
                }
            }
        }
        IPPROTO_IP => {
            match optname {
                IP_TOS | IP_TTL => {
                    // These options expect an int (4 bytes)
                    if optlen < 4 {
                        return SysErrNo::EINVAL as isize;
                    }
                    
                    let value = unsafe { *translated_ref(token, optval as *const u32) };
                    
                    debug!("sys_setsockopt: IP option {} = {}", optname, value);
                    
                    // For now, just return success
                    0
                }
                _ => {
                    debug!("sys_setsockopt: unsupported IPPROTO_IP option {}", optname);
                    SysErrNo::ENOPROTOOPT as isize
                }
            }
        }
        _ => {
            debug!("sys_setsockopt: unsupported level {}", level);
            SysErrNo::ENOPROTOOPT as isize
        }
    }
}

pub fn sys_bind(sockfd: usize, addr: usize, addrlen: u32) -> isize {
    debug!("sys_bind <= sockfd: {}, addr: {:#x}, addrlen: {}", sockfd, addr, addrlen);
    
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    
    if sockfd >= inner.fd_table.len() {
        return SysErrNo::EBADF as isize;
    }
    
    let file = inner.fd_table.get(sockfd);
    match file.file.sock() {
        Ok(socket_arc) => {
            if addrlen < size_of::<SockaddrIn>() as u32 {
                return SysErrNo::EINVAL as isize;
            }
            
            if addr as usize + size_of::<SockaddrIn>() < addr as usize {
                return SysErrNo::EFAULT as isize;
            }
            
            let sockaddr_bytes = match translated_byte_buffer(token, addr as *const u8, size_of::<SockaddrIn>()) {
                buffer if !buffer.is_empty() => {
                    let mut data = [0u8; size_of::<SockaddrIn>()];
                    let mut offset = 0;
                    for slice in buffer {
                        let copy_len = (data.len() - offset).min(slice.len());
                        data[offset..offset + copy_len].copy_from_slice(&slice[..copy_len]);
                        offset += copy_len;
                        if offset >= data.len() {
                            break;
                        }
                    }
                    if offset < data.len() {
                        return SysErrNo::EFAULT as isize;
                    }
                    data
                }
                _ => return SysErrNo::EFAULT as isize,
            };
            
            let sockaddr_in = unsafe { *(sockaddr_bytes.as_ptr() as *const SockaddrIn) };
            
            if sockaddr_in.sin_family as u32 != AF_INET {
                return SysErrNo::EAFNOSUPPORT as isize;
            }
            
            let port = u16::from_be(sockaddr_in.sin_port);
            let ip_addr = Ipv4Addr::from(u32::from_be(sockaddr_in.sin_addr.s_addr));
            
            let socket_addr = SocketAddr::V4(SocketAddrV4::new(ip_addr, port));
            
            debug!("sys_bind: binding to address {:?}", socket_addr);
            
            match socket_arc.bind(socket_addr) {
                Ok(_) => 0,
                Err(e) => {
                    debug!("sys_bind: bind failed with error {:?}", e);
                    match e {
                        crate::net::AxError::AddrInUse => SysErrNo::EADDRINUSE as isize,
                        crate::net::AxError::InvalidInput => SysErrNo::EINVAL as isize,
                        crate::net::AxError::PermissionDenied => SysErrNo::EACCES as isize,
                        _ => SysErrNo::EINVAL as isize,
                    }
                }
            }
        }
        Err(_) => SysErrNo::ENOTSOCK as isize,
    }
}

pub fn sys_getsockopt(
    _fd: usize,
    _level: usize,
    _optname: usize,
    _optval: usize,     
    _optlen_ptr: usize, 
) -> isize {
    unimplemented!()
}

pub fn sys_getsocketopt(
    _fd: usize,
    _level: usize,
    _optname: usize,
    _optval: usize,     
    _optlen_ptr: usize, 
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
