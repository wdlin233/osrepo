use super::SocketAddrIn;

pub struct Socket {
    domain: u32,   // 地址族
    typ: u32,      // socket类型
    protocol: u32, // 具体协议号
    inner: SocketInner,
}

enum SocketInner {
    Tcp(TcpSocket),
    Udp(UdpSocket),
}

////Socket type
//tcp
pub const SOCK_STREAM: usize = 1;
//udp
pub const SOCK_DFRAM: usize = 2;

//////////////////////////////////////////////////////////////////////////
#[repr(C)]
pub struct SockAddr {
    sa_family: u16,    // 地址族
    sa_data: [u8; 14], // 地址数据
}

// IPv4 地址结构 (与 Linux 的 sockaddr_in 兼容)
#[repr(C)]
pub struct SockAddrIn {
    pub sin_family: u16,   // 地址族 (AF_INET)
    pub sin_port: u16,     // 端口号 (网络字节序)
    pub sin_addr: u32,     // IPv4 地址 (网络字节序)
    pub sin_zero: [u8; 8], // 填充字段
}

impl SockAddrIn {
    /// 将网络字节序转换为本地地址表示
    pub fn to_socket_addr(&self) -> SocketAddrIn {
        SocketAddrIn {
            ip: self.sin_addr.to_be(),   // 网络字节序转为主机字节序
            port: self.sin_port.to_be(), // 网络字节序转为主机字节序
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SocketFamily {
    Inet,  // AF_INET
    Inet6, // AF_INET6
    Unix,  // AF_UNIX
}
