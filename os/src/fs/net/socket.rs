use super::SocketAddrIn;

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

/// 地址族常量
pub const AF_UNSPEC: u16 = 0; // 未指定
pub const AF_INET: u16 = 2; // IPv4
pub const AF_INET6: u16 = 10; // IPv6
