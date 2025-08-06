use alloc::sync::Arc;

use super::{File, Kstat};
use crate::syscall::PollEvents;

mod port;
mod simple_net;
mod socket;
mod tcp;
mod udp;
pub use port::*;
pub use simple_net::*;
pub use socket::*;
pub use tcp::*;
pub use udp::*;

// // TCP 连接实现
// pub fn tcp_connect(socket: &TcpSocket, addr: (u32, u16)) -> isize {
//     let mut inner = socket.inner.lock();

//     // 检查套接字状态
//     match inner.state {
//         TcpState::Closed => {
//             // 可以开始连接
//         }
//         TcpState::Established | TcpState::SynSent => {
//             return SysErrNo::EALREADY as isize;
//         }
//         _ => {
//             return SysErrNo::EISCONN as isize;
//         }
//     }

//     // 设置目标地址
//     let peer_addr = SocketAddrIn {
//         ip: addr.0,
//         port: addr.1,
//     };
//     inner.peer_addr = Some(peer_addr);

//     // 如果没有绑定本地地址，分配一个临时端口
//     if inner.local_addr.is_none() {
//         let local_port = allocate_ephemeral_port();
//         inner.local_addr = Some(SocketAddrIn {
//             ip: 0, // 0.0.0.0 表示任意本地地址
//             port: local_port,
//         });
//         // 记录绑定的端口用于资源释放
//         inner.bound_port = Some(local_port);
//     }

//     // 生成初始序列号
//     inner.snd_nxt = generate_initial_seq_number();

//     // 设置状态为 SYN_SENT
//     inner.state = TcpState::SynSent;

//     // 初始化窗口大小（默认值）
//     inner.window_size = DEFAULT_WINDOW_SIZE;

//     // 保存本地地址副本用于发送
//     let local_addr = inner.local_addr.unwrap();

//     // 创建并发送 SYN 包
//     let mut packet = TcpPacket::new(
//         local_addr,
//         peer_addr,
//         inner.snd_nxt,     // 序列号
//         0,                 // ACK号 (SYN不需要ACK)
//         TCP_FLAG_SYN,      // SYN标志
//         inner.window_size, // 窗口大小
//         &[],               // 无负载
//     );

//     // 设置选项（MSS）
//     packet.set_option(TcpOption::MSS(DEFAULT_MSS));

//     // 发送数据包
//     if let Err(e) = net_send_tcp(packet) {
//         inner.state = TcpState::Closed;
//         return e as isize;
//     }

//     // 更新发送序列号（SYN消耗一个序列号）
//     inner.snd_nxt += 1;

//     // 初始化重传相关字段
//     inner.last_send_time = timer::current_time_ms();
//     inner.retransmit_count = 0;

//     // 释放锁，避免在等待时持有锁
//     drop(inner);

//     // 等待连接完成（三次握手）
//     let start_time = timer::current_time_ms();
//     const CONNECT_TIMEOUT_MS: u64 = 5000; // 5秒超时

//     loop {
//         let mut inner = socket.inner.lock();

//         match inner.state {
//             TcpState::Established => {
//                 // 连接成功
//                 debug!(
//                     "TCP connection established to {}:{}",
//                     ip_to_string(peer_addr.ip),
//                     peer_addr.port
//                 );
//                 return 0;
//             }
//             TcpState::Closed => {
//                 // 连接被拒绝或失败
//                 debug!(
//                     "TCP connection refused to {}:{}",
//                     ip_to_string(peer_addr.ip),
//                     peer_addr.port
//                 );
//                 return SysErrNo::ECONNREFUSED as isize;
//             }
//             _ => {
//                 // 检查超时
//                 if timer::current_time_ms() - start_time > CONNECT_TIMEOUT_MS {
//                     debug!(
//                         "TCP connection timeout to {}:{}",
//                         ip_to_string(peer_addr.ip),
//                         peer_addr.port
//                     );
//                     inner.state = TcpState::Closed;
//                     return SysErrNo::ETIMEDOUT as isize;
//                 }

//                 // 检查是否需要重传 SYN
//                 if inner.retransmit_count > 0 {
//                     let elapsed = timer::current_time_ms() - inner.last_send_time;
//                     if elapsed > SYN_RETRANSMIT_INTERVAL {
//                         // 重传 SYN
//                         let mut retry_packet = TcpPacket::new(
//                             local_addr,
//                             peer_addr,
//                             inner.snd_nxt - 1, // 原始SYN序列号
//                             0,
//                             TCP_FLAG_SYN,
//                             inner.window_size,
//                             &[],
//                         );
//                         retry_packet.set_option(TcpOption::MSS(DEFAULT_MSS));

//                         if net_send_tcp(retry_packet).is_ok() {
//                             inner.last_send_time = timer::current_time_ms();
//                             inner.retransmit_count += 1;
//                         }
//                     }
//                 }
//             }
//         }

//         // 释放锁并让出 CPU
//         drop(inner);
//         scheduler::yield_now();
//     }
// }

// // 封装SYN发送逻辑
// fn send_syn_packet(
//     socket: &TcpSocket,
//     peer_addr: SocketAddrIn,
//     inner: &mut MutexGuard<TcpInner>,
// ) -> Result<(), SysError> {
//     let local_addr = inner.local_addr.unwrap();
//     let mut packet = TcpPacket::new(
//         local_addr,
//         peer_addr,
//         inner.snd_nxt - inner.retransmit_count as u32, // 原始序列号
//         0,
//         TCP_FLAG_SYN,
//         inner.window_size,
//         &[],
//     );
//     packet.set_option(TcpOption::MSS(DEFAULT_MSS));

//     net_send_tcp(packet)?;

//     inner.last_send_time = timer::current_time_ms();
//     inner.retransmit_count += 1;

//     Ok(())
// }

// // 处理接收到的 SYN-ACK 包（在 TCP 输入处理中调用）
// pub fn handle_syn_ack(socket: &TcpSocket, packet: &TcpPacket) {
//     let mut inner = socket.inner.lock();

//     // 只处理 SYN-SENT 状态的包
//     if inner.state != TcpState::SynSent {
//         return;
//     }

//     // 验证目标地址和端口
//     if inner.local_addr != Some(packet.dst_addr()) || inner.peer_addr != Some(packet.src_addr()) {
//         return;
//     }

//     // 验证 SYN-ACK 标志
//     if !packet.flags().syn || !packet.flags().ack {
//         return;
//     }

//     // 验证 ACK 号是否正确（应该是我们的 SYN 序列号 +1）
//     if packet.ack() != inner.snd_nxt {
//         debug!(
//             "Invalid ACK number: expected {}, got {}",
//             inner.snd_nxt,
//             packet.ack()
//         );
//         return;
//     }

//     // 更新序列号
//     inner.rcv_nxt = packet.seq() + 1; // SYN 消耗一个序列号

//     // 发送 ACK 完成三次握手
//     let ack_packet = TcpPacket::new(
//         inner.local_addr.unwrap(),
//         packet.src_addr(),
//         inner.snd_nxt,     // 序列号
//         inner.rcv_nxt,     // ACK号
//         TCP_FLAG_ACK,      // ACK标志
//         inner.window_size, // 窗口大小
//         &[],               // 无负载
//     );

//     if let Err(e) = net_send_tcp(ack_packet) {
//         warn!("Failed to send ACK: {:?}", e);
//         inner.state = TcpState::Closed;
//         return;
//     }

//     // 更新状态
//     inner.state = TcpState::Established;

//     debug!(
//         "Received SYN-ACK from {}:{} (seq={}, ack={}), connection established",
//         ip_to_string(packet.src_addr().ip),
//         packet.src_addr().port,
//         packet.seq(),
//         packet.ack()
//     );
// }

// // 常量定义
// const SYN_RETRANSMIT_INTERVAL: u64 = 1000; // 1秒重传间隔
// const DEFAULT_MSS: u16 = 1460; // 默认最大段大小
// const DEFAULT_WINDOW_SIZE: u16 = 1024; // 默认窗口大小

// // 辅助函数：分配临时端口
// fn allocate_ephemeral_port() -> u16 {
//     static NEXT_PORT: AtomicU16 = AtomicU16::new(49152); // IANA 动态端口范围
//     NEXT_PORT.fetch_add(1, Ordering::SeqCst)
// }

// // 辅助函数：生成初始序列号
// fn generate_initial_seq_number() -> u32 {
//     // 简单的随机序列号生成
//     (timer::current_time_ms() as u32) ^ 0x12345678
// }
