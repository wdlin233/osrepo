use smoltcp::socket::tcp::Socket;

mod connection;
mod socket;
pub use connection::*;
pub use socket::*;

//domain
pub const AF_INET: usize = 2;
pub const AF_INET6: usize = 10;
//type
pub const SOCK_STREAM: usize = 1;
pub const SOCK_DGRAM: usize = 2;
pub const SOCK_RAW: usize = 3;
//protocol
pub const IPPROTO_IP: usize = 0;
pub const IPPROTO_ICMP: usize = 1;
pub const IPPROTO_TCP: usize = 6;
pub const IPPROTO_UDP: usize = 17;
pub const IPPROTO_IPV6: usize = 41;
pub const IPPROTO_ICMPV6: usize = 58;

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum SocketDomain {
    AfInet,
    AfInet6,
}

impl SocketDomain {
    pub fn try_get(domain: u32) -> Option<Self> {
        match domain as usize {
            AF_INET => Some(SocketDomain::AfInet),
            AF_INET6 => Some(SocketDomain::AfInet6),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, PartialOrd, Ord)]
pub enum SocketType {
    SockStream, // TCP
    SockDgram,  // UDP
    SockRaw,    // ICMPv4/ICMPv6 only
}

impl SocketType {
    pub fn try_get(type_: u32) -> Option<Self> {
        match type_ as usize {
            SOCK_STREAM => Some(SocketType::SockStream),
            SOCK_DGRAM => Some(SocketType::SockDgram),
            SOCK_RAW => Some(SocketType::SockRaw),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum SocketProtocol {
    Ip,
    Ipv6,
    Icmp,
    Icmpv6,
    Tcp,
    Udp,
}

impl SocketProtocol {
    pub fn try_get(protocol_: u32) -> Option<Self> {
        match protocol_ as usize {
            IPPROTO_IP => Some(SocketProtocol::Ip),
            IPPROTO_IPV6 => Some(SocketProtocol::Ipv6),
            IPPROTO_ICMP => Some(SocketProtocol::Icmp),
            IPPROTO_ICMPV6 => Some(SocketProtocol::Icmpv6),
            IPPROTO_TCP => Some(SocketProtocol::Tcp),
            IPPROTO_UDP => Some(SocketProtocol::Udp),
            _ => None,
        }
    }
}
