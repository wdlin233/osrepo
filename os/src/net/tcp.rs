// src/net/tcp.rs

use super::{is_port_available, release_port, SocketAddrIn};
use crate::{
    fs::{File, Kstat, StMode},
    mm::UserBuffer,
    syscall::PollEvents,
    timer::get_time_ms,
    utils::{SysErrNo, SyscallRet},
};
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

pub struct TcpSocket {
    pub inner: Arc<Mutex<TcpInner>>,
}

pub struct TcpInner {
    rx: VecDeque<u8>,
    tx: VecDeque<u8>,
    state: TcpState,                      // CLOSED / LISTEN / ESTAB 等
    peer_addr: Option<SocketAddrIn>,      // 对端地址 (IP, port)
    pub local_addr: Option<SocketAddrIn>, // 本地地址
    bound_port: Option<u16>,              // 绑定的本地端口（用于资源释放）
    tcp_nodelay: bool,                    // TCP_NODELAY 选项
    //IP 层选项
    ip_tos: u8, // IP 服务类型 (0-255)
    ip_ttl: u8, // IP 生存时间 (1-255)
    // 新增字段支持 listen
    backlog: u32,                                    // 监听队列的最大长度
    pending_conns: VecDeque<PendingConnection>,      // 半连接队列 (SYN_RECEIVED)
    completed_conns: VecDeque<Arc<Mutex<TcpInner>>>, // 已完成连接队列 (等待 accept)

    // TCP 协议相关字段
    rcv_nxt: u32,     // 下一个期望接收的序列号
    snd_nxt: u32,     // 下一个发送序列号
    window_size: u16, // 接收窗口大小
}

// TCP 连接队列中的条目
struct PendingConnection {
    peer_addr: SocketAddrIn,  // 对端地址
    local_addr: SocketAddrIn, // 本地地址
    state: TcpState,          // 连接状态 (通常是 SynReceived)
                              // 其他连接相关的字段...
}

impl TcpInner {
    pub fn new() -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            state: TcpState::Closed,
            peer_addr: None,
            local_addr: None,
            bound_port: None,
            tcp_nodelay: false,
            ip_tos: 0,
            ip_ttl: 64, // 默认 TTL
            backlog: 5, // 默认 backlog
            pending_conns: VecDeque::new(),
            completed_conns: VecDeque::new(),
            rcv_nxt: 0,
            snd_nxt: 0,
            window_size: 1024, // 默认窗口大小
        }
    }

    /// 准备套接字进入监听状态
    pub fn listen(&mut self, backlog: u32) -> Result<(), SysErrNo> {
        // 检查状态是否允许监听
        match self.state {
            TcpState::Closed => {
                // 检查是否已绑定地址
                if self.local_addr.is_none() {
                    return Err(SysErrNo::EINVAL); // 未绑定地址
                }
            }
            TcpState::Listen => {
                // 已经是监听状态，允许更新 backlog
            }
            _ => {
                return Err(SysErrNo::EOPNOTSUPP); // 不支持的操作
            }
        }

        // 设置 backlog 大小 (限制在合理范围)
        self.backlog = backlog.min(128).max(1);

        // 更新状态为监听
        self.state = TcpState::Listen;

        // 清空连接队列
        self.pending_conns.clear();
        self.completed_conns.clear();

        Ok(())
    }

    /// 接受一个已完成连接
    pub fn accept(&mut self) -> Option<Arc<Mutex<TcpInner>>> {
        self.completed_conns.pop_front()
    }
}

// TCP套接字释放时
impl Drop for TcpSocket {
    fn drop(&mut self) {
        if let Some(addr) = self.inner.lock().local_addr {
            release_port(addr.port, true);
        }
    }
}

impl TcpSocket {
    /// 绑定套接字到本地地址
    pub fn bind(&self, addr: SocketAddrIn) -> Result<(), SysErrNo> {
        let mut inner = self.inner.lock();

        // 检查是否已绑定
        if inner.local_addr.is_some() {
            return Err(SysErrNo::EINVAL); // 套接字已绑定
        }

        // 检查端口是否可用
        if !is_port_available(addr.port, true) {
            return Err(SysErrNo::EADDRINUSE); // 地址已使用
        }

        // 设置本地地址
        inner.local_addr = Some(addr);
        inner.bound_port = Some(addr.port);

        // 如果是服务器套接字，进入LISTEN状态
        if inner.state == TcpState::Closed {
            inner.state = TcpState::Listen;
        }

        Ok(())
    }
    pub fn listen(&self, backlog: u32) -> Result<(), SysErrNo> {
        let mut inner = self.inner.lock();
        inner.listen(backlog)
    }
}

//set&get
impl TcpSocket {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(Mutex::new(TcpInner::new())),
        })
    }
    pub fn get_tcp_nodelay(&self) -> bool {
        self.inner.lock().tcp_nodelay
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

    pub fn set_tcp_nodelay(&self, nodelay: bool) {
        self.inner.lock().tcp_nodelay = nodelay;
    }
    /// 设置TCP_NODELAY选项
    pub fn set_nodelay(&self, nodelay: bool) -> Result<(), SysErrNo> {
        let mut inner = self.inner.lock();
        inner.tcp_nodelay = nodelay;
        Ok(())
    }

    /// 设置IP_TOS选项
    pub fn set_tos(&self, tos: u8) -> Result<(), SysErrNo> {
        let mut inner = self.inner.lock();
        inner.ip_tos = tos;
        Ok(())
    }
}

//File trait
impl File for TcpSocket {
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

        // 1. 把 VecDeque 线性化
        let (front, back) = inner.rx.as_slices();
        let mut temp = Vec::new();
        temp.extend_from_slice(front);
        temp.extend_from_slice(back);

        // 2. 实际拷贝长度
        let cp_len = buf.len().min(temp.len());

        // 3. 写入用户缓冲区
        let n = buf.write(&temp[..cp_len]);
        inner.rx.drain(..n);
        Ok(n)
    }

    /* ---------- write ---------- */
    fn write(&self, buf: UserBuffer) -> SyscallRet {
        let mut inner = self.inner.lock();
        for seg in &buf.buffers {
            inner.tx.extend(seg.iter().copied());
        }
        // TODO: 把 tx 真正发到网络
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
            revents |= PollEvents::OUT; // 简化：始终可写
        }
        revents
    }
}
