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
