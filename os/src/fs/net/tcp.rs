// src/net/tcp.rs

use crate::{
    fs::{File, Kstat, StMode},
    mm::UserBuffer,
    syscall::PollEvents,
    utils::{SysErrNo, SyscallRet},
};
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

struct TcpInner {
    rx: VecDeque<u8>,
    tx: VecDeque<u8>,
    state: TcpState,                // CLOSED / LISTEN / ESTAB 等
    peer_addr: Option<(u32, u16)>,  // 对端地址 (IP, port)
    local_addr: Option<(u32, u16)>, // 本地地址
}

#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub enum TcpState {
    #[default]
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
    inner: Arc<Mutex<TcpInner>>,
}

impl TcpSocket {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(Mutex::new(TcpInner::default())),
        })
    }
}
impl Default for TcpInner {
    fn default() -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            state: TcpState::Closed,
            peer_addr: None,
            local_addr: None,
        }
    }
}

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

// TCP 连接实现
pub fn tcp_connect(socket: &TcpSocket, addr: (u32, u16)) -> isize {
    let mut inner = socket.inner.lock();

    // 检查套接字状态
    match inner.state {
        TcpState::Closed => {
            // 可以开始连接
        }
        TcpState::Established | TcpState::SynSent => {
            return SysErrNo::EALREADY as isize;
        }
        _ => {
            return SysErrNo::EISCONN as isize;
        }
    }

    // 设置目标地址和状态
    inner.peer_addr = Some(addr);
    inner.state = TcpState::SynSent;

    // TODO: 实际网络实现中这里会发送 SYN 包
    // 伪代码: net_send_syn(socket, addr);

    // 等待连接完成（简化实现中直接成功）
    inner.state = TcpState::Established;

    // 唤醒等待的读/写操作
    // TODO: 实际实现中需要唤醒等待的线程

    // 返回成功
    0
}
