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

#[derive(Default)]
struct TcpInner {
    rx: VecDeque<u8>,
    tx: VecDeque<u8>,
    state: TcpState, // CLOSED / LISTEN / ESTAB 等
}

#[derive(Copy, Clone, PartialEq, Eq, Default)]
enum TcpState {
    #[default]
    Closed,
    Listen,
    SynSent,
    Established,
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

impl File for TcpSocket {
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
