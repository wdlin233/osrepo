// Copyright (c) 2025 vivo Mobile Communication Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::{
    cell::RefCell,
    fmt::{self, Display},
};

use alloc::{rc::Rc, string::String};
use smoltcp::{
    iface::{Interface, PollResult, SocketHandle, SocketSet},
    phy::Loopback,
    socket::AnySocket,
    time::{Duration, Instant},
    wire::IpAddress,
};

#[cfg(virtio)]
use crate::devices::net::virtio_net_device::VirtIONetDevice;

// Use enum to keep all device in a vec or array
// Why not use trait ?
//      we have method using generic T like `get_socket_mut<T>` which is not allow in trait
pub enum NetDevice {
    Loopback(Loopback),
    #[cfg(virtio)]
    VirtioNetDevice(VirtIONetDevice),
}

pub struct NetInterface<'a> {
    name: String,
    smoltcp_device: Rc<RefCell<NetDevice>>,
    smoltcp_interface: Rc<RefCell<Interface>>,
    smoltcp_socket_sets: Rc<RefCell<SocketSet<'a>>>,
}

impl<'a> NetInterface<'a> {
    pub fn new(
        name: String,
        smoltcp_enum_device: Rc<RefCell<NetDevice>>,
        interface: Rc<RefCell<Interface>>,
        socket_sets: Rc<RefCell<SocketSet<'a>>>,
    ) -> NetInterface<'a> {
        NetInterface {
            name,
            smoltcp_device: smoltcp_enum_device,
            smoltcp_interface: interface,
            smoltcp_socket_sets: socket_sets,
        }
    }

    pub fn socket_sets_mut(&mut self) -> Rc<RefCell<SocketSet<'a>>> {
        self.smoltcp_socket_sets.clone()
    }

    pub fn inner_interface_mut(&mut self) -> Rc<RefCell<Interface>> {
        self.smoltcp_interface.clone()
    }

    /// Operation done with cloneable result , do in net_interface
    /// Operation done with ref which need ref to net_interface, use rc::refcell to cut down ref chain to prevent multi borrow_mut
    pub fn add_socket<T>(&mut self, socket: T) -> Option<SocketHandle>
    where
        T: AnySocket<'a>,
    {
        Some(self.smoltcp_socket_sets.borrow_mut().add(socket))
    }

    pub fn poll_delay(&mut self, timestamp: Instant) -> Option<Duration> {
        self.smoltcp_interface
            .borrow_mut()
            .poll_delay(timestamp, &self.smoltcp_socket_sets.borrow())
    }

    pub fn contains_addr(&self, remote_addr: IpAddress) -> bool {
        self.smoltcp_interface
            .borrow()
            .ip_addrs()
            .iter()
            .any(|cidr| cidr.contains_addr(&remote_addr))
    }

    pub fn poll(&mut self, timestamp: Instant) -> PollResult {
        match &mut *self.smoltcp_device.borrow_mut() {
            NetDevice::Loopback(loopback) => self.smoltcp_interface.borrow_mut().poll(
                timestamp,
                loopback,
                &mut self.smoltcp_socket_sets.borrow_mut(),
            ),

            #[cfg(virtio)]
            NetDevice::VirtioNetDevice(virt_ionet_device) => {
                self.smoltcp_interface.borrow_mut().poll(
                    timestamp,
                    virt_ionet_device,
                    &mut self.smoltcp_socket_sets.borrow_mut(),
                )
            }
        }
    }
}

impl Display for NetInterface<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetInterface({})", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blueos_test_macro::test;
    // NetInterface owned FrameBUf, so in test case the Buffer will be alloc
    // in stack memory, all these network resource related interface is not
    // suitable for unit test, and should be run in integration test in specific
    // thread ,un comment this test case
    // #[test]
    fn test_net_interface_create() {
        let net_interface = NetInterface::create_loopback_interface();

        assert!(net_interface.name.contains("Loopback"));
        assert!(net_interface.contains_addr(IpAddress::v4(127, 0, 0, 1)));
    }
}
