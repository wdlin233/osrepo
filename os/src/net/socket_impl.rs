use alloc::{sync::Arc, vec, vec::Vec};
use core::ffi::{c_char, c_int, c_void};
use core::mem::size_of;
use core::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use smoltcp::wire::IpEndpoint;
use spin::Mutex;

use crate::fs::{Kstat, Sock};
use crate::net::AxResult;
use crate::net::{socket::PollState, TcpSocket, UdpSocket};
use crate::syscall::PollEvents;
use crate::utils::{GeneralRet, SysErrNo, SyscallRet};

pub enum Socket {
    Udp(Mutex<UdpSocket>),
    Tcp(Mutex<TcpSocket>),
}

impl Socket {
    // fn from_fd(fd: c_int) -> GeneralRet<Arc<Self>> {
    //     let f = super::fd_ops::get_file_like(fd)?;
    //     f.into_any()
    //         .downcast::<Self>()
    //         .map_err(|_| SysErrNo::EINVAL.into())
    // }

    pub fn send(&self, buf: &[u8]) -> AxResult<usize> {
        match self {
            Socket::Udp(udpsocket) => Ok(udpsocket.lock().send(buf)?),
            Socket::Tcp(tcpsocket) => Ok(tcpsocket.lock().send(buf)?),
        }
    }

    fn recv(&self, buf: &mut [u8]) -> AxResult<usize> {
        match self {
            Socket::Udp(udpsocket) => Ok(udpsocket.lock().recv_from(buf).map(|e| e.0)?),
            Socket::Tcp(tcpsocket) => Ok(tcpsocket.lock().recv(buf)?),
        }
    }

    pub fn poll(&self) -> AxResult<PollState> {
        match self {
            Socket::Udp(udpsocket) => Ok(udpsocket.lock().poll()?),
            Socket::Tcp(tcpsocket) => Ok(tcpsocket.lock().poll()?),
        }
    }

    fn local_addr(&self) -> AxResult<SocketAddr> {
        match self {
            Socket::Udp(udpsocket) => Ok(udpsocket.lock().local_addr()?),
            Socket::Tcp(tcpsocket) => Ok(tcpsocket.lock().local_addr()?),
        }
    }

    fn peer_addr(&self) -> AxResult<SocketAddr> {
        match self {
            Socket::Udp(udpsocket) => Ok(udpsocket.lock().peer_addr()?),
            Socket::Tcp(tcpsocket) => Ok(tcpsocket.lock().peer_addr()?),
        }
    }

    fn bind(&self, addr: SocketAddr) -> AxResult<()> {
        match self {
            Socket::Udp(udpsocket) => Ok(udpsocket.lock().bind(addr)?),
            Socket::Tcp(tcpsocket) => Ok(tcpsocket.lock().bind(addr)?),
        }
    }

    fn connect(&self, addr: SocketAddr) -> AxResult {
        match self {
            Socket::Udp(udpsocket) => Ok(udpsocket.lock().connect(addr)?),
            Socket::Tcp(tcpsocket) => Ok(tcpsocket.lock().connect(addr)?),
        }
    }

    pub fn sendto(&self, buf: &[u8], addr: SocketAddr) -> SyscallRet {
        match self {
            // diff: must bind before sendto
            Socket::Udp(udpsocket) => Ok(udpsocket.lock().send_to(buf, addr)?),
            Socket::Tcp(_) => Err(SysErrNo::EISCONN.into()),
        }
    }

    fn recvfrom(&self, buf: &mut [u8]) -> AxResult<(usize, Option<SocketAddr>)> {
        match self {
            // diff: must bind before recvfrom
            Socket::Udp(udpsocket) => Ok(udpsocket
                .lock()
                .recv_from(buf)
                .map(|res| (res.0, Some(res.1)))?),
            Socket::Tcp(tcpsocket) => Ok(tcpsocket.lock().recv(buf).map(|res| (res, None))?),
        }
    }

    fn listen(&self) -> AxResult {
        match self {
            Socket::Udp(_) => Err(SysErrNo::EOPNOTSUPP.into()),
            Socket::Tcp(tcpsocket) => Ok(tcpsocket.lock().listen()?),
        }
    }

    fn accept(&self) -> AxResult<TcpSocket> {
        match self {
            Socket::Udp(_) => Err(SysErrNo::EOPNOTSUPP.into()),
            Socket::Tcp(tcpsocket) => Ok(tcpsocket.lock().accept()?),
        }
    }

    fn shutdown(&self) -> AxResult {
        match self {
            Socket::Udp(udpsocket) => {
                let udpsocket = udpsocket.lock();
                udpsocket.peer_addr()?;
                udpsocket.shutdown()?;
                Ok(())
            }

            Socket::Tcp(tcpsocket) => {
                let tcpsocket = tcpsocket.lock();
                tcpsocket.peer_addr()?;
                tcpsocket.shutdown()?;
                Ok(())
            }
        }
    }
}

impl Sock for Socket {
    fn read(&self, buf: &mut [u8]) -> AxResult<usize> {
        self.recv(buf)
    }

    fn write(&self, buf: &[u8]) -> AxResult<usize> {
        self.send(buf)
    }

    fn fstat(&self) -> Kstat {
        // not really implemented
        let st_mode = 0o140000 | 0o777u32; // S_IFSOCK | rwxrwxrwx
        Kstat {
            st_mode,
            ..Default::default()
        }
    }

    fn poll(&self) -> AxResult<PollState> {
        self.poll()
    }

    fn set_nonblocking(&self, nonblock: bool) -> AxResult<usize> {
        match self {
            Socket::Udp(udpsocket) => udpsocket.lock().set_nonblocking(nonblock),
            Socket::Tcp(tcpsocket) => tcpsocket.lock().set_nonblocking(nonblock),
        }
        Ok(0)
    }

    fn bind(&self, addr: SocketAddr) -> AxResult<()> {
        self.bind(addr)
    }

    fn local_addr(&self) -> AxResult<SocketAddr> {
        match self {
            Socket::Udp(udpsocket) => udpsocket.lock().local_addr(),
            Socket::Tcp(tcpsocket) => tcpsocket.lock().local_addr(),
        }
    }

    fn sendto(&self, buf: &[u8], addr: SocketAddr) -> AxResult<usize> {
        match self.sendto(buf, addr) {
            Ok(sent) => Ok(sent),
            Err(e) => Err(crate::net::AxError::from(e)),
        }
    }

    fn recvfrom(&self, buf: &mut [u8]) -> AxResult<(usize, Option<SocketAddr>)> {
        match self {
            Socket::Udp(udpsocket) => {
                match udpsocket.lock().recv_from(buf) {
                    Ok((len, addr)) => Ok((len, Some(addr))),
                    Err(e) => Err(crate::net::AxError::from(e)),
                }
            }
            Socket::Tcp(tcpsocket) => {
                match tcpsocket.lock().recv(buf) {
                    Ok(len) => Ok((len, None)),
                    Err(e) => Err(crate::net::AxError::from(e)),
                }
            }
        }
    }

    fn recvfrom_timeout(&self, buf: &mut [u8], timeout_ms: u64) -> AxResult<(usize, Option<SocketAddr>)> {
        match self {
            Socket::Udp(udpsocket) => {
                match udpsocket.lock().recv_from_timeout(buf, timeout_ms) {
                    Ok((len, addr)) => Ok((len, Some(addr))),
                    Err(e) => Err(crate::net::AxError::from(e)),
                }
            }
            Socket::Tcp(tcpsocket) => {
                match tcpsocket.lock().recv(buf) {
                    Ok(len) => Ok((len, None)),
                    Err(e) => Err(crate::net::AxError::from(e)),
                }
            }
        }
    }

    fn listen(&self, backlog: i32) -> AxResult<()> {
        match self {
            Socket::Udp(_) => Err(SysErrNo::EOPNOTSUPP.into()),
            Socket::Tcp(tcpsocket) => {
                debug!("TCP socket listen with backlog: {}", backlog);
                match tcpsocket.lock().listen() {
                    Ok(_) => Ok(()),
                    Err(e) => Err(crate::net::AxError::from(e)),
                }
            }
        }
    }

    fn connect(&self, addr: core::net::SocketAddr) -> AxResult<()> {
        match self {
            Socket::Udp(_) => Err(SysErrNo::EOPNOTSUPP.into()),
            Socket::Tcp(tcpsocket) => {
                debug!("TCP socket connect to: {}", addr);
                match tcpsocket.lock().connect(addr) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(crate::net::AxError::from(e)),
                }
            }
        }
    }

    fn accept(&self) -> AxResult<(Arc<dyn Sock>, core::net::SocketAddr)> {
        match self {
            Socket::Udp(_) => Err(SysErrNo::EOPNOTSUPP.into()),
            Socket::Tcp(tcpsocket) => {
                debug!("TCP socket accept");
                match tcpsocket.lock().accept() {
                    Ok(new_tcp_socket) => {
                        // Get peer address from the new socket
                        let peer_addr = new_tcp_socket.peer_addr()?;
                        let new_socket = Socket::Tcp(Mutex::new(new_tcp_socket));
                        Ok((Arc::new(new_socket), peer_addr))
                    }
                    Err(e) => Err(crate::net::AxError::from(e)),
                }
            }
        }
    }
}

impl From<SocketAddrV4> for SockaddrIn {
    fn from(addr: SocketAddrV4) -> SockaddrIn {
        SockaddrIn {
            sin_family: AF_INET as u16,
            sin_port: addr.port().to_be(),
            sin_addr: Inaddr {
                // `s_addr` is stored as BE on all machines and the array is in BE order.
                // So the native endian conversion method is used so that it's never swapped.
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            },
            sin_zero: [0; 8],
        }
    }
}

impl From<SockaddrIn> for SocketAddrV4 {
    fn from(addr: SockaddrIn) -> SocketAddrV4 {
        SocketAddrV4::new(
            Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
            u16::from_be(addr.sin_port),
        )
    }
}

fn into_sockaddr(addr: SocketAddr) -> (SockaddrImpl, u32) {
    debug!("    Sockaddr: {}", addr);
    match addr {
        SocketAddr::V4(addr) => (
            unsafe { *(&SockaddrIn::from(addr) as *const _ as *const SockaddrImpl) },
            size_of::<SockaddrImpl>() as _,
        ),
        SocketAddr::V6(_) => panic!("IPv6 is not supported"),
    }
}

fn from_sockaddr(addr: *const SockaddrImpl, addrlen: u32) -> GeneralRet<SocketAddr> {
    if addr.is_null() {
        return Err(SysErrNo::EFAULT.into());
    }
    if addrlen != size_of::<SockaddrImpl>() as _ {
        return Err(SysErrNo::EINVAL.into());
    }

    let mid = unsafe { *(addr as *const SockaddrIn) };
    if mid.sin_family != AF_INET as u16 {
        return Err(SysErrNo::EINVAL.into());
    }

    let res = SocketAddr::V4(mid.into());
    debug!("    load sockaddr:{:#x} => {:?}", addr as usize, res);
    Ok(res)
}

pub const AF_INET: usize = 2;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockaddrImpl {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockaddrIn {
    pub sin_family: u16,
    pub sin_port: u16, // network byte order
    pub sin_addr: Inaddr,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Inaddr {
    pub s_addr: u32, // network byte order
}
