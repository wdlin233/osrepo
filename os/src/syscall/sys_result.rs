#![allow(missing_docs)]

//! Error Codes
pub type SysResult<T> = Result<T, SysError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum SysError {
    /// Operation not permitted
    EPERM = 1,
    /// No such file or directory
    ENOENT = 2,
    /// No such process
    ESRCH = 3,
    /// Interrupted system call
    EINTR = 4,
    /// I/O error
    EIO = 5,
    /// No such device or address
    ENXIO = 6,
    /// Argument list too long
    E2BIG = 7,
    /// Exec format error
    ENOEXEC = 8,
    /// Bad file number
    EBADF = 9,
    /// No child processes
    ECHILD = 10,
    /// Resource temporarily unavailable
    EAGAIN = 11,
    /// Out of memory
    ENOMEM = 12,
    /// Permission denied
    EACCES = 13,
    /// Bad address
    EFAULT = 14,
    /// Block device required
    ENOTBLK = 15,
    /// Device or resource busy
    EBUSY = 16,
    /// File exists
    EEXIST = 17,
    /// Cross-device link
    EXDEV = 18,
    /// No such device
    ENODEV = 19,
    /// Not a directory
    ENOTDIR = 20,
    /// Is a directory
    EISDIR = 21,
    /// Invalid argument
    EINVAL = 22,
    /// File table overflow
    ENFILE = 23,
    /// Too many open files
    EMFILE = 24,
    /// Not a typewriter
    ENOTTY = 25,
    /// Text file busy
    ETXTBSY = 26,
    /// File too large
    EFBIG = 27,
    /// No space left on device
    ENOSPC = 28,
    /// Illegal seek
    ESPIPE = 29,
    /// Read-only file system
    EROFS = 30,
    /// Too many links
    EMLINK = 31,
    /// Broken pipe
    EPIPE = 32,
    /// Math argument out of domain of func
    EDOM = 33,
    /// Math result not representable
    ERANGE = 34,
    /// Resource deadlock would occur
    EDEADLK = 35,
    /// File name too long
    ENAMETOOLONG = 36,
    /// No record locks available
    ENOLCK = 37,
    /// Invalid system call number
    ENOSYS = 38,
    /// Directory not empty
    ENOTEMPTY = 39,
    /// Too many symbolic links encountered
    ELOOP = 40,
    /// Socket operation on non-socket
    ENOTSOCK = 88,
    /// Unsupported
    EOPNOTSUPP = 95,
    ///
    EAFNOSUPPORT = 97,
    /// Socket address is already in use
    EADDRINUSE = 98,
    /// Address not available
    EADDRNOTAVAIL = 99,
    /// Connection reset
    ECONNRESET = 104,
    /// Transport endpoint is already connected
    EISCONN = 106,
    /// The socket is not connected
    ENOTCONN = 107,
    ///connection time out
    ETIMEDOUT = 110,
    /// Connection refused
    ECONNREFUSED = 111,
    ///
    EALREADY = 114,
    /// The socket is nonblocking and the connection cannot be completed
    /// immediately.(connect.2)
    EINPROGRESS = 115,
}

impl SysError {
    /// Returns the error description.
    pub const fn as_str(&self) -> &'static str {
        use self::SysError::*;
        match self {
            EALREADY => "Operation already in progress",
            EAFNOSUPPORT => "Address family not supported by protocol",
            ETIMEDOUT => "Time out",
            EPERM => "Operation not permitted",
            ENOENT => "No such file or directory",
            ESRCH => "No such process",
            EINTR => "Interrupted system call",
            EIO => "I/O error",
            ENXIO => "No such device or address",
            E2BIG => "Argument list too long",
            ENOEXEC => "Exec format error",
            EBADF => "Bad file number",
            ECHILD => "No child processes",
            EAGAIN => "Try again",
            ENOMEM => "Out of memory",
            EACCES => "Permission denied",
            EFAULT => "Bad address",
            ENOTBLK => "Block device required",
            EBUSY => "Device or resource busy",
            EEXIST => "File exists",
            EXDEV => "Cross-device link",
            ENODEV => "No such device",
            ENOTDIR => "Not a directory",
            EISDIR => "Is a directory",
            EINVAL => "Invalid argument",
            ENFILE => "File table overflow",
            EMFILE => "Too many open files",
            ENOTTY => "Not a typewriter",
            ETXTBSY => "Text file busy",
            EFBIG => "File too large",
            ENOSPC => "No space left on device",
            ESPIPE => "Illegal seek",
            EROFS => "Read-only file system",
            EMLINK => "Too many links",
            EPIPE => "Broken pipe",
            EDOM => "Math argument out of domain of func",
            ERANGE => "Math result not representable",
            EDEADLK => "Resource deadlock would occur",
            ENAMETOOLONG => "File name too long",
            ENOLCK => "No record locks available",
            ENOSYS => "Invalid system call number",
            ENOTEMPTY => "Directory not empty",
            ELOOP => "Too many symbolic links encountered",
            ENOTSOCK => "Socket operation on non-socket",
            ENOTCONN => "Transport endpoint is not connected",
            EOPNOTSUPP => "Unsupported Error",
            EADDRNOTAVAIL => "Address not available",
            EADDRINUSE => "Address already in use",
            EISCONN => "Transport endpoint is already connected",
            ECONNRESET => "Connection reset",
            ECONNREFUSED => "Connection refused",
            EINPROGRESS => "Operation now in progress",
        }
    }
}

extern "C" {
    fn ekernel();
}

#[derive(Debug)]
pub struct SysInfo {
    ///  系统自启动以来的总时间（秒）
    pub uptime: usize,
    /// 1分钟、5分钟和15分钟的平均负载
    pub loads: [usize; 3],
    /// 物理内存总量（字节）
    pub totalram: usize,
    /// 空闲的物理内存量（字节）
    pub freeram: usize,
    /// 共享内存的物理内存量（字节）
    pub sharedram: usize,
    /// 用作缓冲区的物理内存量（字节）
    pub bufferram: usize,
    /// 交换空间总量（字节）
    pub totalswap: usize,
    /// 空闲的交换空间量（字节）
    pub freeswap: usize,
    /// 当前运行的进程数
    pub procs: u16,
    /// 高内存区的物理内存总量（字节）
    pub totalhigh: usize,
    /// 高内存区的空闲物理内存量（字节）
    pub freehigh: usize,
    /// 内存单位大小（字节）
    pub mem_unit: u32,
}

impl SysInfo {
    pub fn new(newuptime: usize, newtotalram: usize, newprocs: usize) -> Self {
        Self {
            uptime: newuptime,
            loads: [0; 3],
            totalram: newtotalram,
            freeram: newtotalram - ekernel as usize,
            sharedram: 0,
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: newprocs as u16,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
        }
    }
}
