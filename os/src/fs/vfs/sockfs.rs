use alloc::sync::Arc;
use spin::Mutex;

use crate::fs::{OpenFlags, Socket};

pub struct SocketFile {
    socket_inode: Arc<dyn Socket>,
    socket: Mutex<Option<Arc<Connection>>>,
    open_flags: OpenFlags,
}

impl SocketFile {
    pub fn new(socket_inode: Arc<dyn Socket>, flags: OpenFlags) -> Self {
        Self {
            socket_inode,
            socket: Mutex::new(None),
            open_flags: flags,
        }
    }

    pub fn socket(&self) -> Option<Arc<Connection>> {
        let guard = self.socket.lock();
        guard.as_ref().cloned()
    }

    pub fn set_socket(&self, socket: Arc<Connection>) {
        let mut guard = self.socket.lock();
        *guard = Some(socket);
    }
}
