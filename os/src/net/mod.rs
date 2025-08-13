pub mod lazy_init;
pub mod socket;
pub mod socket_impl;
pub use socket::*;
pub use socket_impl::*;

pub use crate::net::socket::{init as net_init, TcpSocket};
pub use crate::net::socket::UdpSocket;
pub use crate::net::socket::{
    add_membership, dns_query, from_core_sockaddr, into_core_sockaddr, poll_interfaces,
};

pub use smoltcp::wire::{IpAddress as IpAddr, IpEndpoint as SocketAddr, Ipv4Address as Ipv4Addr};
