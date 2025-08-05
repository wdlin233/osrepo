use alloc::{format, string::ToString, sync::Arc};

use crate::{
    fs::{
        make_socket, make_socketpair, tcp_connect, udp_connect, File, FileClass, FileDescriptor,
        OpenFlags, SockAddrIn, TcpSocket, UdpSocket, AF_INET,
    },
    mm::{translated_byte_buffer, translated_ref, translated_refmut, UserBuffer},
    task::current_process,
    utils::{SysErrNo, SyscallRet},
};
use log::debug;

pub fn sys_socket(domain: u32, _type: u32, _protocol: u32) -> isize {
    const AF_INET: u32 = 2;
    const SOCK_DGRAM: u32 = 2;
    const SOCK_STREAM: u32 = 1;

    if domain != AF_INET {
        return SysErrNo::EAFNOSUPPORT as isize;
    }
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let new_fd = inner.fd_table.alloc_fd().unwrap();
    let close_on_exec = (_type & 0o2000000) == 0o2000000;
    let non_block = (_type & 0o4000) == 0o4000;
    let mut flags = OpenFlags::empty();
    if close_on_exec {
        flags |= OpenFlags::O_CLOEXEC;
    }
    if non_block {
        flags |= OpenFlags::O_NONBLOCK;
    }
    let sock: Arc<dyn File> = match _type & 0xF {
        SOCK_DGRAM => UdpSocket::new(),
        SOCK_STREAM => TcpSocket::new(),
        _ => return SysErrNo::EPROTONOSUPPORT as isize,
    };

    inner
        .fd_table
        .set(new_fd, FileDescriptor::new(flags, FileClass::Abs(sock)));
    inner
        .fs_info
        .insert(format!("socket{}", new_fd).to_string(), new_fd);
    new_fd as isize
}

pub fn sys_bind(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    0
}

pub fn sys_getsockname(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    0
}

pub fn sys_getpeername(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    SysErrNo::Default as isize
}

pub fn sys_setsockopt(
    _sockfd: usize,
    _level: u32,
    _optname: u32,
    _optcal: *const u8,
    _optlen: u32,
) -> isize {
    0
}

pub fn sys_sendto(
    _sockfd: usize,
    _buf: *const u8,
    _len: usize,
    _flags: u32,
    _dest_addr: *const u8,
    _addrlen: u32,
) -> isize {
    1
}

pub fn sys_recvfrom(
    _sockfd: usize,
    buf: *mut u8,
    _len: usize,
    _flags: u32,
    _src_addr: *const u8,
    _addrlen: u32,
) -> isize {
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    *translated_refmut(token, buf) = b'x';
    *translated_refmut(token, unsafe { buf.add(1) }) = b'0';
    1
}

pub fn sys_listen(_sockfd: usize, _backlog: u32) -> isize {
    0
}

pub fn sys_connect(sockfd: usize, addr: *const u8, addrlen: u32) -> isize {
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();

    // 1. 验证地址长度
    let sockaddr_in_size = size_of::<SockAddrIn>() as u32;
    if addrlen < sockaddr_in_size {
        return SysErrNo::EINVAL as isize;
    }
    // 2. 创建临时缓冲区
    let mut addr_buf = [0u8; size_of::<SockAddrIn>()];

    debug!("to 3");
    // 3. 从用户空间读取数据到内核缓冲区
    {
        // 计算实际需要读取的字节数
        let read_size = sockaddr_in_size as usize;

        // 安全地读取用户空间数据
        let user_buffers = translated_byte_buffer(token, addr as *const u8, read_size);

        // 创建UserBuffer用于读取用户空间
        let mut user_buf = UserBuffer::new(user_buffers);

        // 使用read方法读取数据
        let read_data = user_buf.read(read_size);

        // 检查是否读取了足够的数据
        if read_data.len() != read_size {
            return SysErrNo::EFAULT as isize;
        }

        // 将数据复制到内核缓冲区
        addr_buf[..read_size].copy_from_slice(&read_data[..read_size]);
    }

    debug!("3 ok");
    // 4. 解释为 sockaddr_in 结构
    let sockaddr_in = unsafe { &*(addr_buf.as_ptr() as *const SockAddrIn) };

    // 5. 验证地址族
    if sockaddr_in.sin_family != AF_INET {
        return SysErrNo::EAFNOSUPPORT as isize;
    }

    // 6. 获取当前任务的文件描述符表

    let file = match inner.fd_table.try_get(sockfd) {
        Some(f) => f,
        None => return SysErrNo::EBADF as isize,
    };

    // 7. 转换端口和地址到主机字节序
    let port = u16::from_be(sockaddr_in.sin_port);
    let ip = u32::from_be(sockaddr_in.sin_addr);
    let addr = (ip, port);

    // 8. 根据套接字类型执行连接操作
    if let Some(tcp_socket) = file.any().as_any().downcast_ref::<TcpSocket>() {
        tcp_connect(tcp_socket, addr)
    } else if let Some(udp_socket) = file.any().as_any().downcast_ref::<UdpSocket>() {
        udp_connect(udp_socket, addr)
    } else {
        debug!("error socket");
        SysErrNo::ENOTSOCK as isize
    }
}

pub fn sys_accept(_sockfd: usize, _addr: *const u8, _addrlen: u32) -> isize {
    0
}

pub fn sys_accept4(_sockfd: usize, _addr: *const u8, _addrlen: u32, _flags: u32) -> isize {
    0
}

pub fn sys_sendmsg(_sockfd: usize, _addr: *const u8, _flags: u32) -> isize {
    0
// }
// pub fn sys_getsocketopt(
//     fd: usize,
//     level: usize,
//     optname: usize,
//     optval: *mut u8,
//     optlen: usize, // 用户空间指向optlen的指针
// ) -> SyscallRet {
//     // 检查参数有效性
//     if optval.is_null() || optlen == 0 {
//         return SysErrNo::EFAULT as isize;
//     }

//     // 从用户空间读取optlen值
//     let mut kernel_opt_len: u32 = 0;


//     // 检查缓冲区长度
//     if kernel_opt_len == 0 || kernel_opt_len > 1000 {
//         return SysErrNo::EINVAL as isize;
//     }

//     // 解析socket选项层级
//     let level = ;

//     // 获取当前任务和文件描述符
//     let process = current_process();
//     let inner = process.inner_exclusive_access();
//     let file = inner.fd_table.get(fd).any();

//     // 转换为Socket类型
//     let socket = file
//         .as_any()
//         .downcast_ref::<Socket>()
//         .ok_or(SysErrNo::ENOTSOCK)?;

//     // 处理不同层级的选项
//     match level {
//         Socket => {
         

//             // 创建内核缓冲区
//             let mut kernel_buf = vec![0u8; kernel_opt_len as usize];
//             let mut actual_len = kernel_opt_len as usize;

//             // 获取选项值
//             option.get(socket, &mut kernel_buf, &mut actual_len)?;

//             log::debug!("Got socket option, actual_len={}", actual_len);

//             0
//         }

//        Tcp => {


//             // 创建内核缓冲区
  

//             // 获取选项值
        

//             log::debug!("Got TCP option, actual_len={}", actual_len);

//             0
//         }

//        IP => {
//             // 简化的IP选项处理
//             if optname == 18446744073709551615 {
//             }

//             // 更新实际长度为0
//             let actual_len: u32 = 0;

//             0
//         }
//         _ => SysErrNo::ENOPROTOOPT as isize,
//     }
// }

pub fn sys_socketpair(domain: u32, stype: u32, protocol: u32, sv: *mut u32) -> isize {
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    let (socket1, socket2) = make_socketpair();
    let close_on_exec = (stype & 0o2000000) == 0o2000000;
    let non_block = (stype & 0o4000) == 0o4000;
    let mut flags = OpenFlags::empty();
    if close_on_exec {
        flags |= OpenFlags::O_CLOEXEC;
    }
    if non_block {
        flags |= OpenFlags::O_NONBLOCK;
    }

    let new_fd1 = inner.fd_table.alloc_fd().unwrap();
    inner
        .fd_table
        .set(new_fd1, FileDescriptor::new(flags, FileClass::Abs(socket1)));
    inner
        .fs_info
        .insert(format!("socket{}", new_fd1).to_string(), new_fd1);

    let new_fd2 = inner.fd_table.alloc_fd().unwrap();
    inner
        .fd_table
        .set(new_fd2, FileDescriptor::new(flags, FileClass::Abs(socket2)));
    inner
        .fs_info
        .insert(format!("socket{}", new_fd2).to_string(), new_fd2);

    *translated_refmut(token, sv) = new_fd1 as u32;
    *translated_refmut(token, unsafe { sv.add(1) }) = new_fd2 as u32;
    0
}
