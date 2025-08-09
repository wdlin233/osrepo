use alloc::sync::Arc;

use super::{File, Kstat};
use crate::syscall::PollEvents;

mod port;
mod socket;
mod tcp;
mod udp;
pub use port::*;
pub use socket::*;
pub use tcp::*;
pub use udp::*;

/// 地址族常量
pub const AF_UNSPEC: u16 = 0; // 未指定
pub const AF_INET: u16 = 2; // IPv4
pub const AF_INET6: u16 = 10; // IPv6
