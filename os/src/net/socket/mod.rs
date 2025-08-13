mod addr;
mod bench;
mod dns;
mod listen_table;
mod macros;

mod tcp;
mod udp;
use alloc::vec;
use core::cell::RefCell;
use core::ops::DerefMut;

use crate::utils::SysErrNo;

use super::lazy_init::LazyInit;
use crate::drivers::{NetDeviceImpl, AxNetDeviceType, NetBufPtr, NetError, VirtIoHalImpl, NetTxBufPtr};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{self, AnySocket, Socket};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use spin::Mutex;

use self::listen_table::ListenTable;
pub use smoltcp::wire::{IpAddress as IpAddr, IpEndpoint as SocketAddr, Ipv4Address as Ipv4Addr};

pub use self::dns::dns_query;
pub use self::tcp::TcpSocket;
pub use self::udp::UdpSocket;
pub use addr::{from_core_sockaddr, into_core_sockaddr};
#[allow(unused)]
macro_rules! env_or_default {
    ($key:literal) => {
        match option_env!($key) {
            Some(val) => val,
            None => "",
        }
    };
}

pub const NANOS_PER_MICROS: u64 = 1_000;
const DNS_SEVER: &str = "8.8.8.8";

const RANDOM_SEED: u64 = 0xA2CE_05A2_CE05_A2CE;
const STANDARD_MTU: usize = 1500;
const TCP_RX_BUF_LEN: usize = 64 * 1024;
const TCP_TX_BUF_LEN: usize = 64 * 1024;
const UDP_RX_BUF_LEN: usize = 64 * 1024;
const UDP_TX_BUF_LEN: usize = 64 * 1024;
const LISTEN_QUEUE_SIZE: usize = 512;

static LISTEN_TABLE: LazyInit<ListenTable> = LazyInit::new();
static SOCKET_SET: LazyInit<SocketSetWrapper> = LazyInit::new();

mod loopback;
static LOOPBACK_DEV: LazyInit<Mutex<LoopbackDev>> = LazyInit::new();
static LOOPBACK: LazyInit<Mutex<Interface>> = LazyInit::new();
use self::loopback::LoopbackDev;

#[repr(i32)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AxError {
    /// A socket address could not be bound because the address is already in use elsewhere.
    AddrInUse = 1,
    /// An entity already exists, often a file.
    AlreadyExists,
    /// Bad address.
    BadAddress,
    /// Bad internal state.
    BadState,
    /// The connection was refused by the remote server,
    ConnectionRefused,
    /// The connection was reset by the remote server.
    ConnectionReset,
    /// A non-empty directory was specified where an empty directory was expected.
    DirectoryNotEmpty,
    /// Data not valid for the operation were encountered.
    ///
    /// Unlike [`InvalidInput`], this typically means that the operation
    /// parameters were valid, however the error was caused by malformed
    /// input data.
    ///
    /// For example, a function that reads a file into a string will error with
    /// `InvalidData` if the file's contents are not valid UTF-8.
    ///
    /// [`InvalidInput`]: AxError::InvalidInput
    InvalidData,
    /// Invalid parameter/argument.
    InvalidInput,
    /// Input/output error.
    Io,
    /// The filesystem object is, unexpectedly, a directory.
    IsADirectory,
    /// Not enough space/cannot allocate memory.
    NoMemory,
    /// A filesystem object is, unexpectedly, not a directory.
    NotADirectory,
    /// The network operation failed because it was not connected yet.
    NotConnected,
    /// The requested entity is not found.
    NotFound,
    /// The operation lacked the necessary privileges to complete.
    PermissionDenied,
    /// Device or resource is busy.
    ResourceBusy,
    /// The underlying storage (typically, a filesystem) is full.
    StorageFull,
    /// An error returned when an operation could not be completed because an
    /// "end of file" was reached prematurely.
    UnexpectedEof,
    /// This operation is unsupported or unimplemented.
    Unsupported,
    /// The operation needs to block to complete, but the blocking operation was
    /// requested to not occur.
    WouldBlock,
    /// An error returned when an operation could not be completed because a
    /// call to `write()` returned [`Ok(0)`](Ok).
    WriteZero,
    /// Syscall interrupted by a caught signal
    Interrupted,
    /// Syscall timed out
    Timeout,
}

impl From<SysErrNo> for AxError {
    fn from(errno: SysErrNo) -> Self {
        match errno {
            SysErrNo::EADDRINUSE => AxError::AddrInUse,
            SysErrNo::EEXIST => AxError::AlreadyExists,
            SysErrNo::EFAULT => AxError::BadAddress,
            SysErrNo::EBADF | SysErrNo::EINVAL => AxError::BadState, // 简化映射
            SysErrNo::ECONNREFUSED => AxError::ConnectionRefused,
            SysErrNo::ECONNRESET => AxError::ConnectionReset,
            SysErrNo::ENOTEMPTY => AxError::DirectoryNotEmpty,
            SysErrNo::EILSEQ | SysErrNo::EDOM | SysErrNo::ERANGE => AxError::InvalidData,
            SysErrNo::EINVAL => AxError::InvalidInput,
            SysErrNo::EIO | SysErrNo::EREMOTEIO => AxError::Io,
            SysErrNo::EISDIR => AxError::IsADirectory,
            SysErrNo::ENOMEM => AxError::NoMemory,
            SysErrNo::ENOTDIR => AxError::NotADirectory,
            SysErrNo::ENOTCONN => AxError::NotConnected,
            SysErrNo::ENOENT => AxError::NotFound,
            SysErrNo::EACCES => AxError::PermissionDenied,
            SysErrNo::EBUSY => AxError::ResourceBusy,
            SysErrNo::ENOSPC => AxError::StorageFull,
            SysErrNo::EOVERFLOW | SysErrNo::EFBIG => AxError::UnexpectedEof,
            SysErrNo::ENOSYS => AxError::Unsupported,
            SysErrNo::EAGAIN | SysErrNo::EAGAIN => AxError::WouldBlock,
            SysErrNo::EPIPE | SysErrNo::ENOSR => AxError::WriteZero,
            SysErrNo::EINTR => AxError::Interrupted,
            SysErrNo::ETIMEDOUT => AxError::Timeout,

            // 其余全部兜底
            _ => AxError::Io,
        }
    }
}
/// A specialized [`Result`] type with [`AxError`] as the error type.
pub type AxResult<T = ()> = Result<T, AxError>;

/// I/O poll results.
#[derive(Debug, Default, Clone, Copy)]
pub struct PollState {
    /// Object can be read now.
    pub readable: bool,
    /// Object can be writen now.
    pub writable: bool,
}

pub trait Read {
    /// Pull some bytes from this source into the specified buffer, returning
    /// how many bytes were read.
    fn read(&mut self, buf: &mut [u8]) -> AxResult<usize>;
}

pub trait Write {
    /// Write a buffer into this writer, returning how many bytes were written.
    fn write(&mut self, buf: &[u8]) -> AxResult<usize>;
    /// Flush this output stream, ensuring that all intermediately buffered
    /// contents reach their destination.
    fn flush(&mut self) -> AxResult;
}

struct SocketSetWrapper<'a>(Mutex<SocketSet<'a>>);

struct DeviceWrapper {
    inner: RefCell<AxNetDeviceType>, // use `RefCell` is enough since it's wrapped in `Mutex` in `InterfaceWrapper`.
}

struct InterfaceWrapper {
    name: &'static str,
    ether_addr: EthernetAddress,
    dev: Mutex<DeviceWrapper>,
    iface: Mutex<Interface>,
}

impl<'a> SocketSetWrapper<'a> {
    fn new() -> Self {
        Self(Mutex::new(SocketSet::new(vec![])))
    }

    pub fn new_tcp_socket() -> socket::tcp::Socket<'a> {
        let tcp_rx_buffer = socket::tcp::SocketBuffer::new(vec![0; TCP_RX_BUF_LEN]);
        let tcp_tx_buffer = socket::tcp::SocketBuffer::new(vec![0; TCP_TX_BUF_LEN]);
        socket::tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer)
    }

    pub fn new_udp_socket() -> socket::udp::Socket<'a> {
        let udp_rx_buffer = socket::udp::PacketBuffer::new(
            vec![socket::udp::PacketMetadata::EMPTY; 256],
            vec![0; UDP_RX_BUF_LEN],
        );
        let udp_tx_buffer = socket::udp::PacketBuffer::new(
            vec![socket::udp::PacketMetadata::EMPTY; 256],
            vec![0; UDP_TX_BUF_LEN],
        );
        socket::udp::Socket::new(udp_rx_buffer, udp_tx_buffer)
    }

    pub fn new_dns_socket() -> socket::dns::Socket<'a> {
        let server_addr = DNS_SEVER.parse().expect("invalid DNS server address");
        socket::dns::Socket::new(&[server_addr], vec![])
    }

    pub fn add<T: AnySocket<'a>>(&self, socket: T) -> SocketHandle {
        let handle = self.0.lock().add(socket);
        debug!("socket {}: created", handle);
        handle
    }

    pub fn with_socket<T: AnySocket<'a>, R, F>(&self, handle: SocketHandle, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        let set = self.0.lock();
        let socket = set.get(handle);
        f(socket)
    }

    pub fn with_socket_mut<T: AnySocket<'a>, R, F>(&self, handle: SocketHandle, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut set = self.0.lock();
        let socket = set.get_mut(handle);
        f(socket)
    }

    pub fn bind_check(&self, addr: IpAddress, _port: u16) -> AxResult {
        let mut sockets = self.0.lock();
        for item in sockets.iter_mut() {
            match item.1 {
                Socket::Udp(s) => {
                    if s.endpoint().addr == Some(addr) {
                        return Err(AxError::AddrInUse);
                    }
                }
                _ => continue,
            };
        }
        Ok(())
    }

    pub fn poll_interfaces(&self) {
        let timestamp = Instant::from_micros_const((0 / NANOS_PER_MICROS) as i64);
        let mut sockets = self.0.lock();
        LOOPBACK
            .lock()
            .poll(timestamp, LOOPBACK_DEV.lock().deref_mut(), &mut sockets);
    }

    pub fn remove(&self, handle: SocketHandle) {
        self.0.lock().remove(handle);
        debug!("socket {}: destroyed", handle);
    }
}

#[allow(unused)]
impl InterfaceWrapper {
    fn new(name: &'static str, dev: AxNetDeviceType, ether_addr: EthernetAddress) -> Self {
        let mut config = Config::new(HardwareAddress::Ethernet(ether_addr));
        config.random_seed = RANDOM_SEED;

        let mut dev = DeviceWrapper::new(dev);
        let iface = Mutex::new(Interface::new(config, &mut dev, Self::current_time()));
        Self {
            name,
            ether_addr,
            dev: Mutex::new(dev),
            iface,
        }
    }

    fn current_time() -> Instant {
        Instant::from_micros_const((0 / NANOS_PER_MICROS) as i64)
    }

    pub fn name(&self) -> &str {
        self.name
    }

    pub fn ethernet_address(&self) -> EthernetAddress {
        self.ether_addr
    }

    pub fn setup_ip_addr(&self, ip: IpAddress, prefix_len: u8) {
        let mut iface = self.iface.lock();
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs.push(IpCidr::new(ip, prefix_len)).unwrap();
        });
    }

    pub fn setup_gateway(&self, gateway: IpAddress) {
        let mut iface = self.iface.lock();
        match gateway {
            IpAddress::Ipv4(v4) => iface.routes_mut().add_default_ipv4_route(v4).unwrap(),
        };
    }

    pub fn poll(&self, sockets: &Mutex<SocketSet>) {
        let mut dev = self.dev.lock();
        let mut iface = self.iface.lock();
        let mut sockets = sockets.lock();
        let timestamp = Self::current_time();
        iface.poll(timestamp, dev.deref_mut(), &mut sockets);
    }
}

impl DeviceWrapper {
    fn new(inner: AxNetDeviceType) -> Self {
        Self {
            inner: RefCell::new(inner),
        }
    }
}

impl Device for DeviceWrapper {
    type RxToken<'a>
        = AxNetRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = AxNetTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut dev = self.inner.borrow_mut();
        if let Err(e) = dev.recycle_tx_buffers() {
            warn!("recycle_tx_buffers failed: {:?}", e);
            return None;
        }

        if !dev.can_transmit() {
            return None;
        }
        let rx_buf = match dev.receive() {
            Ok(buf) => buf,
            Err(err) => {
                // if !matches!(err, DevError::Again) {
                //     warn!("receive failed: {:?}", err);
                // }
                error!( "receive failed: {:?}", err);
                return None;
            }
        };
        Some((AxNetRxToken(&self.inner, rx_buf), AxNetTxToken(&self.inner)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let mut dev = self.inner.borrow_mut();
        if let Err(e) = dev.recycle_tx_buffers() {
            warn!("recycle_tx_buffers failed: {:?}", e);
            return None;
        }
        if dev.can_transmit() {
            Some(AxNetTxToken(&self.inner))
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = None;
        caps.medium = Medium::Ethernet;
        caps
    }
}

struct AxNetRxToken<'a>(&'a RefCell<AxNetDeviceType>, NetBufPtr);
struct AxNetTxToken<'a>(&'a RefCell<AxNetDeviceType>);

impl<'a> RxToken for AxNetRxToken<'a> {
    fn preprocess(&self, sockets: &mut SocketSet<'_>) {
        snoop_tcp_packet(self.1.packet(), sockets).ok();
    }

    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut rx_buf = self.1;
        trace!(
            "RECV {} bytes: {:02X?}",
            rx_buf.packet_len(),
            rx_buf.packet()
        );
        let result = f(rx_buf.packet_mut());
        self.0.borrow_mut().recycle_rx_buffer(rx_buf).unwrap();
        result
    }
}

impl<'a> TxToken for AxNetTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut dev = self.0.borrow_mut();
        let mut tx_buf = dev.alloc_tx_buffer(len).unwrap();
        let ret = f(tx_buf.packet_mut());
        trace!("SEND {} bytes: {:02X?}", len, tx_buf.packet());
        dev.transmit(tx_buf).unwrap();
        ret
    }
}

fn snoop_tcp_packet(buf: &[u8], sockets: &mut SocketSet<'_>) -> Result<(), smoltcp::wire::Error> {
    use smoltcp::wire::{EthernetFrame, IpProtocol, Ipv4Packet, TcpPacket};

    let ether_frame = EthernetFrame::new_checked(buf)?;
    let ipv4_packet = Ipv4Packet::new_checked(ether_frame.payload())?;

    if ipv4_packet.next_header() == IpProtocol::Tcp {
        let tcp_packet = TcpPacket::new_checked(ipv4_packet.payload())?;
        let src_addr = (ipv4_packet.src_addr(), tcp_packet.src_port()).into();
        let dst_addr = (ipv4_packet.dst_addr(), tcp_packet.dst_port()).into();
        let is_first = tcp_packet.syn() && !tcp_packet.ack();
        if is_first {
            // create a socket for the first incoming TCP packet, as the later accept() returns.
            LISTEN_TABLE.incoming_tcp_packet(src_addr, dst_addr, sockets);
        }
    }
    Ok(())
}

/// Poll the network stack.
///
/// It may receive packets from the NIC and process them, and transmit queued
/// packets to the NIC.
pub fn poll_interfaces() {
    SOCKET_SET.poll_interfaces();
}

/// Add multicast_addr to the loopback device.
pub fn add_membership(_multicast_addr: IpAddress, _interface_addr: IpAddress) {
    let timestamp = Instant::from_micros_const((0 / NANOS_PER_MICROS) as i64);
    let _ = LOOPBACK.lock().join_multicast_group(
        LOOPBACK_DEV.lock().deref_mut(),
        _multicast_addr,
        timestamp,
    );
}

/// Initialize the network stack
pub fn init() {
    let mut device = LoopbackDev::new(Medium::Ip);
    let config = Config::new(smoltcp::wire::HardwareAddress::Ip);

    let mut iface = Interface::new(
        config,
        &mut device,
        Instant::from_micros_const((0 / NANOS_PER_MICROS) as i64),
    );
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
            .unwrap();
    });
    LOOPBACK.init_by(Mutex::new(iface));
    LOOPBACK_DEV.init_by(Mutex::new(device));

    SOCKET_SET.init_by(SocketSetWrapper::new());
    LISTEN_TABLE.init_by(ListenTable::new());
}
