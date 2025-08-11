use crate::net::{SocketDomain, SocketProtocol, SocketType};

pub struct Connection {
    socket_fd: SocketFd,
    socket_domain: SocketDomain,
    socket_type: SocketType,
    socket_protocol: SocketProtocol,
    local_endpoint: Mutex<Option<IpListenEndpoint>>,
    remote_endpoint: Mutex<Option<IpEndpoint>>,
    is_nonblocking: AtomicBool, // default io mode is blocking, use O_NONBLOCK to set non-blocking
    recv_timeout: Mutex<Option<Duration>>, // block indefinitely as default
    send_timeout: Mutex<Option<Duration>>, // block indefinitely as default
    ipc_reply: Arc<OperationIPCReply>,
}

impl Connection {
    pub fn new(
        socket_fd: SocketFd,
        socket_domain: SocketDomain,
        socket_type: SocketType,
        socket_protocol: SocketProtocol,
    ) -> Self {
        Self {
            socket_fd,
            socket_domain,
            socket_type,
            socket_protocol,
            local_endpoint: Mutex::new(None),
            remote_endpoint: Mutex::new(None),
            is_nonblocking: AtomicBool::new(false),
            recv_timeout: Mutex::new(None),
            send_timeout: Mutex::new(None),
            ipc_reply: Arc::new(OperationIPCReply::new()),
        }
    }
}
