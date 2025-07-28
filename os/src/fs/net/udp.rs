// src/net/udp.rs

use crate::{
    fs::{File, Kstat, StMode},
    mm::UserBuffer,
    syscall::PollEvents,
    utils::{SysErrNo, SyscallRet},
};
use alloc::vec::Vec;
use alloc::{collections::VecDeque, sync::Arc};
use spin::Mutex;

#[derive(Default)]
struct UdpBuffer {
    rx: VecDeque<u8>,              // 接收队列
    tx: VecDeque<u8>,              // 发送队列（loopback 用）
    peer_addr: Option<(u32, u16)>, // 记录远端，简化处理
}

pub struct UdpSocket {
    inner: Arc<Mutex<UdpBuffer>>,
    bound_port: Option<u16>,
}

impl UdpSocket {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(Mutex::new(UdpBuffer::default())),
            bound_port: None,
        })
    }
}

impl File for UdpSocket {
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
