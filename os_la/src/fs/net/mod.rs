use alloc::sync::Arc;

use super::{File, Kstat};
use crate::syscall::PollEvents;

mod simple_net;
mod tcp;
mod udp;
pub use simple_net::*;
pub use tcp::*;
pub use udp::*;

// pub struct Socket;

// pub fn make_socket() -> Arc<dyn File> {
//     Arc::new(Socket {})
// }

// impl File for Socket {
//     fn readable(&self) -> bool {
//         false
//     }
//     fn fstat(&self) -> Kstat {
//         unimplemented!()
//     }
// }

// IPv4 地址结构 (与 Linux 的 sockaddr_in 兼容)
#[repr(C)]
pub struct SockAddrIn {
    pub sin_family: u16,   // 地址族 (AF_INET)
    pub sin_port: u16,     // 端口号 (网络字节序)
    pub sin_addr: u32,     // IPv4 地址 (网络字节序)
    pub sin_zero: [u8; 8], // 填充字段
}

pub const AF_INET: u16 = 2; // IPv4 地址族
