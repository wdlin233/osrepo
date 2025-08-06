// src/net/udp.rs

use super::{is_port_available, release_port, SocketAddrIn};
use crate::sync::UPSafeCell;
use crate::{
    fs::{File, Kstat, StMode},
    mm::UserBuffer,
    syscall::PollEvents,
    utils::{SysErrNo, SyscallRet},
};
use alloc::vec::Vec;
use alloc::{collections::VecDeque, sync::Arc};
use spin::Mutex;

struct UdpBuffer {
    rx: VecDeque<u8>,                 // 接收队列
    tx: VecDeque<u8>,                 // 发送队列（loopback 用）
    bound_addr: Option<SocketAddrIn>, // 绑定地址 (IP, port)
    peer_addr: Option<SocketAddrIn>,  // 记录远端，简化处理
    //  IP 层选项
    ip_tos: u8, // IP 服务类型
    ip_ttl: u8, // IP 生存时间
}

pub struct UdpSocket {
    inner: Arc<Mutex<UdpBuffer>>,
}

impl UdpSocket {
    /// 绑定套接字到本地地址
    pub fn bind(&self, addr: SocketAddrIn) -> Result<(), SysErrNo> {
        let mut inner = self.inner.lock();

        if inner.bound_addr.is_some() {
            return Err(SysErrNo::EINVAL); // 已绑定
        }

        if !is_port_available(addr.port, false) {
            return Err(SysErrNo::EADDRINUSE);
        }

        inner.bound_addr = Some(addr);
        Ok(())
    }
}

impl UdpSocket {
    pub fn new() -> Arc<Self> {
        let buffer = UdpBuffer {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            bound_addr: None,
            peer_addr: None,
            ip_tos: 0,  // 默认服务类型
            ip_ttl: 64, // 默认TTL
        };

        unsafe {
            Arc::new(Self {
                inner: Arc::new(Mutex::new(buffer)),
            })
        }
    }

    pub fn get_ip_tos(&self) -> u8 {
        self.inner.lock().ip_tos
    }

    pub fn get_ip_ttl(&self) -> u8 {
        self.inner.lock().ip_ttl
    }

    pub fn set_ip_tos(&self, tos: u8) {
        self.inner.lock().ip_tos = tos;
    }

    pub fn set_ip_ttl(&self, ttl: u8) {
        self.inner.lock().ip_ttl = ttl;
    }
}

impl File for UdpSocket {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn readable(&self) -> bool {
        true
    }
    fn writable(&self) -> bool {
        true
    }

    fn read(&self, mut buf: UserBuffer) -> SyscallRet {
        let mut inner = self.inner.lock();
        if inner.rx.is_empty() {
            return Err(SysErrNo::EAGAIN);
        }

        // 1. 先把 VecDeque 线性化
        let (front, back) = inner.rx.as_slices();
        let mut temp = Vec::new();
        temp.extend_from_slice(front);
        temp.extend_from_slice(back);

        // 2. 拷贝到 UserBuffer
        let n = buf.write(&temp);
        inner.rx.drain(..n);
        Ok(n)
    }

    // 写：把用户缓冲区拷到 tx 队列
    fn write(&self, buf: UserBuffer) -> SyscallRet {
        let mut inner = self.inner.lock();
        // 1. 读出用户数据（零拷贝视图）
        for seg in &buf.buffers {
            inner.tx.extend(seg.iter().copied());
        }
        Ok(buf.len())
    }
    fn fstat(&self) -> Kstat {
        Kstat {
            st_mode: StMode::FSOCK.bits(),
            st_nlink: 1,
            ..Default::default()
        }
    }

    fn poll(&self, events: PollEvents) -> PollEvents {
        let inner = self.inner.lock();
        let mut revents = PollEvents::empty();
        if events.contains(PollEvents::IN) && !inner.rx.is_empty() {
            revents |= PollEvents::IN;
        }
        if events.contains(PollEvents::OUT) {
            revents |= PollEvents::OUT; // UDP 总是可写
        }
        revents
    }
}

// UDP 连接实现
pub fn udp_connect(socket: &UdpSocket, addr: (u32, u16)) -> isize {
    let mut inner = socket.inner.lock();

    // UDP 连接只是设置默认目标地址
    inner.peer_addr = Some(SocketAddrIn {
        ip: addr.0,
        port: addr.1,
    });

    // // 设置绑定端口（如果尚未绑定）
    // if socket.bound_port.is_none() {
    //     // 分配临时端口 (范围 49152-65535)
    //     // 实际实现中应从端口管理器中获取
    //     socket.bound_port = Some(49152);
    // }

    0 // 成功
}
