// src/net/port.rs

use crate::utils::SysErrNo;
use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use lazy_static::lazy_static;
use spin::{Mutex, MutexGuard};

/// 套接字地址 (IPv4)
#[derive(Debug, Clone, Copy)]
pub struct SocketAddrIn {
    pub ip: u32,   // IPv4地址 (主机字节序)
    pub port: u16, // 端口号 (主机字节序)
}

impl SocketAddrIn {
    /// 创建新地址
    pub fn new(ip: u32, port: u16) -> Self {
        Self { ip, port }
    }

    /// 转换为字符串表示
    pub fn to_string(&self) -> String {
        let octets = [
            (self.ip >> 24) as u8,
            (self.ip >> 16) as u8,
            (self.ip >> 8) as u8,
            self.ip as u8,
        ];
        format!(
            "{}.{}.{}.{}:{}",
            octets[0], octets[1], octets[2], octets[3], self.port
        )
    }
}

// 全局端口管理
lazy_static! {
    pub static ref TCP_PORTS: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());
    pub static ref UDP_PORTS: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());
}

/// 分配端口（如果端口为0则自动分配）
pub fn allocate_port(requested_port: u16, is_tcp: bool) -> Result<u16, SysErrNo> {
    if is_tcp {
        let mut guard = TCP_PORTS.lock();
        allocate_port_impl(requested_port, &mut guard)
    } else {
        let mut guard = UDP_PORTS.lock();
        allocate_port_impl(requested_port, &mut guard)
    }
}

// 内部实现，处理实际的端口分配逻辑
fn allocate_port_impl(
    requested_port: u16,
    port_set: &mut MutexGuard<BTreeSet<u16>>,
) -> Result<u16, SysErrNo> {
    // 自动分配端口
    if requested_port == 0 {
        // 从动态端口范围分配 (49152-65535)
        for port in 49152..=65535 {
            if port_set.insert(port) {
                return Ok(port);
            }
        }
        return Err(SysErrNo::EADDRNOTAVAIL);
    }

    // 检查指定端口是否可用
    if port_set.insert(requested_port) {
        Ok(requested_port)
    } else {
        Err(SysErrNo::EADDRINUSE)
    }
}

/// 检查端口是否可用
///
/// # 参数
/// - port: 要检查的端口
/// - is_tcp: 是否为TCP端口
///
/// # 返回值
/// - true: 端口可用
/// - false: 端口已被占用
pub fn is_port_available(port: u16, is_tcp: bool) -> bool {
    if port == 0 {
        return true; // 端口0表示自动分配
    }

    if is_tcp {
        let guard = TCP_PORTS.lock();
        !guard.contains(&port) // 检查端口是否不存在（即可用）
    } else {
        let guard = UDP_PORTS.lock();
        !guard.contains(&port) // 检查端口是否不存在（即可用）
    }
}

/// 释放端口
pub fn release_port(port: u16, is_tcp: bool) {
    if port == 0 {
        return;
    }

    if is_tcp {
        let mut guard = TCP_PORTS.lock();
        guard.remove(&port);
    } else {
        let mut guard = UDP_PORTS.lock();
        guard.remove(&port);
    }
}
