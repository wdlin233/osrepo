//! Implementation of syscalls
//!
//! The single entry point to all system calls, [`syscall()`], is called
//! whenever userspace wishes to perform a system call using the `ecall`
//! instruction. In this case, the processor raises an 'Environment call from
//! U-mode' exception, which is handled as one of the cases in
//! [`crate::trap::trap_handler`].
//!
//! For clarity, each single syscall is implemented as its own function, named
//! `sys_` then the name of the syscall. You can find functions like this in
//! submodules, and you should also implement syscalls this way.

/// getcwd syscall
pub const SYSCALL_GETCWD: usize = 17;
/// dup syscall
pub const SYSCALL_DUP: usize = 23;
/// dup3 syscall
pub const SYSCALL_DUP3: usize = 24;
/// ioctl syscall
pub const SYSCALL_IOCTL: usize = 29;
/// mkdirat syscall
pub const SYSCALL_MKDIRAT: usize = 34;
/// unlinkat syscall
pub const SYSCALL_UNLINKAT: usize = 35;
/// linkat syscall
pub const SYSCALL_LINKAT: usize = 37;
/// unmount syscall
pub const SYSCALL_UNMOUNT2: usize = 39;
/// mount syscall
pub const SYSCALL_MOUNT: usize = 40;
/// chdir syscall
pub const SYSCALL_CHDIR: usize = 49;
/// openat syscall
pub const SYSCALL_OPENAT: usize = 56;
/// close syscall
pub const SYSCALL_CLOSE: usize = 57;
/// pipe syscall
pub const SYSCALL_PIPE: usize = 59;
/// getdents syscall
pub const SYSCALL_GETDENTS64: usize = 61;
/// read syscall
pub const SYSCALL_READ: usize = 63;
/// write syscall
pub const SYSCALL_WRITE: usize = 64;
/// writev syscall
pub const SYSCALL_WRITEV: usize = 66;
/// fstat syscall
pub const SYSCALL_FSTAT: usize = 80;
/// exit syscall
pub const SYSCALL_EXIT: usize = 93;
/// exit_group
pub const SYSCALL_EXIT_GROUP: usize = 94;
/// set_tid_address syscall
pub const SYSCALL_TID_ADDRESS: usize = 96;
/// sleep syscall
pub const SYSCALL_SLEEP: usize = 101;
/// yield syscall
pub const SYSCALL_YIELD: usize = 124;
/// kill syscall
pub const SYSCALL_KILL: usize = 129;
/*
/// sigaction syscall
pub const SYSCALL_SIGACTION: usize = 134;

/// sigreturn syscall
pub const SYSCALL_SIGRETURN: usize = 139;
*/

/// sigprocmask syscall
pub const SYSCALL_SIGPROCMASK: usize = 135;
/// set priority syscall
pub const SYSCALL_SET_PRIORITY: usize = 140;
/// times
pub const SYSCALL_TIMES: usize = 153;
/// gettimeofday syscall
pub const SYSCALL_GETTIMEOFDAY: usize = 169;
/// get system name
pub const SYSCALL_UNAME: usize = 160;
/// getpid syscall
pub const SYSCALL_GETPID: usize = 172;
/// getppid syscall
pub const SYSCALL_GETPPID: usize = 173;
/// getuid syscall
pub const SYSCALL_GETUID: usize = 174;
/// getgid syscall
pub const SYSCALL_GETGID: usize = 176;
/// gettid syscall
pub const SYSCALL_GETTID: usize = 178;
/// fork syscall
pub const SYSCALL_FORK: usize = 220;
/// exec syscall
pub const SYSCALL_EXEC: usize = 221;
/// sbrk syscall
pub const SYSCALL_BRK: usize = 214;
/// munmap syscall
pub const SYSCALL_MUNMAP: usize = 215;
/// mmap syscall
pub const SYSCALL_MMAP: usize = 222;
/// waitpid syscall
pub const SYSCALL_WAITPID: usize = 260;
/// spawn syscall
pub const SYSCALL_SPAWN: usize = 400;
/*
/// mail read syscall
pub const SYSCALL_MAIL_READ: usize = 401;
/// mail write syscall
pub const SYSCALL_MAIL_WRITE: usize = 402;
*/

/// thread_create syscall
pub const SYSCALL_THREAD_CREATE: usize = 460;
/// waittid syscall
pub const SYSCALL_WAITTID: usize = 462;
/// mutex_create syscall
pub const SYSCALL_MUTEX_CREATE: usize = 463;
/// mutex_lock syscall
pub const SYSCALL_MUTEX_LOCK: usize = 464;
/// mutex_unlock syscall
pub const SYSCALL_MUTEX_UNLOCK: usize = 466;
/// semaphore_create syscall
pub const SYSCALL_SEMAPHORE_CREATE: usize = 467;
/// semaphore_up syscall
pub const SYSCALL_SEMAPHORE_UP: usize = 468;
/// enable deadlock detect syscall
pub const SYSCALL_ENABLE_DEADLOCK_DETECT: usize = 469;
/// semaphore_down syscall
pub const SYSCALL_SEMAPHORE_DOWN: usize = 470;
/// condvar_create syscall
pub const SYSCALL_CONDVAR_CREATE: usize = 471;
/// condvar_signal syscall
pub const SYSCALL_CONDVAR_SIGNAL: usize = 472;
/// condvar_wait syscallca
pub const SYSCALL_CONDVAR_WAIT: usize = 473;
/// statx syscall
pub const SYSCALL_STATX: usize = 291;

mod fs;
mod options;
mod process;
mod signal;
mod sync;
mod thread;
//mod tid;
pub mod sys_result;
mod uname;

use fs::*;
use process::*;
use signal::*;
use sync::*;
use thread::*;
//use tid::*;
pub use options::*;
use uname::*;

use crate::{
    fs::{Kstat, Statx},
    signal::{SigAction, SigInfo, SignalFlags},
    system::UTSname,
    task::TmsInner,
};

/// handle syscall exception with `syscall_id` and other arguments
pub fn syscall(syscall_id: usize, args: [usize; 6]) -> isize {
    match syscall_id {
        SYSCALL_SIGPROCMASK => sys_sigprocmask(
            args[0] as u32,
            args[1] as *const SignalFlags,
            args[2] as *mut SignalFlags,
        ),
        SYSCALL_MOUNT => sys_mount(
            args[0] as *const u8,
            args[1] as *const u8,
            args[2] as *const u8,
            args[3] as u32,
            args[4] as *const u8,
        ),
        SYSCALL_UNMOUNT2 => sys_unmount2(args[0] as *const u8, args[1] as u32),
        SYSCALL_MKDIRAT => sys_mkdirat(args[0] as isize, args[1] as *const u8, args[2] as u32),
        SYSCALL_GETDENTS64 => sys_getdents64(args[0], args[1] as *const u8, args[2]),
        SYSCALL_CHDIR => sys_chdir(args[0] as *const u8),
        SYSCALL_GETCWD => sys_getcwd(args[0] as *const u8, args[1]),
        SYSCALL_DUP3 => sys_dup3(args[0], args[1], args[2] as u32),
        SYSCALL_DUP => sys_dup(args[0]),
        SYSCALL_GETGID => sys_getgid(),
        SYSCALL_GETUID => sys_getuid(),
        SYSCALL_UNAME => sys_uname(args[0] as *mut UTSname),
        SYSCALL_TIMES => sys_tms(args[0] as *mut TmsInner),
        SYSCALL_BRK => sys_brk(args[0]),
        SYSCALL_SLEEP => sys_sleep(args[0] as *const TimeVal),
        SYSCALL_GETPPID => sys_getppid(),
        SYSCALL_WAITPID => sys_waitpid(args[0] as isize, args[1] as *mut i32, args[2]),
        SYSCALL_FORK => sys_fork(args[0], args[1], args[2], args[3], args[4]),
        SYSCALL_YIELD => sys_yield(),

        SYSCALL_LINKAT => sys_linkat(args[1] as *const u8, args[3] as *const u8),
        SYSCALL_UNLINKAT => sys_unlinkat(args[0] as isize, args[1] as *const u8, args[2] as u32),
        SYSCALL_OPENAT => sys_open(
            args[0] as isize,
            args[1] as *const u8,
            args[2] as u32,
            args[3] as u32,
        ),
        SYSCALL_CLOSE => sys_close(args[0]),
        SYSCALL_PIPE => sys_pipe(args[0] as *mut u32, args[1] as u32),
        SYSCALL_READ => sys_read(args[0], args[1] as *const u8, args[2]),
        SYSCALL_WRITE => sys_write(args[0], args[1] as *const u8, args[2]),
        SYSCALL_FSTAT => sys_fstat(args[0], args[1] as *mut Kstat),
        SYSCALL_EXIT => sys_exit(args[0] as i32),
        SYSCALL_GETPID => sys_getpid(),
        SYSCALL_GETTID => sys_gettid(),
        SYSCALL_EXEC => sys_exec(
            args[0] as *const u8,
            args[1] as *const usize,
            args[2] as *const usize,
        ),
        SYSCALL_GETTIMEOFDAY => sys_get_time(args[0] as *mut TimeVal, args[1]),
        SYSCALL_MMAP => sys_mmap(
            args[0],
            args[1],
            args[2] as u32,
            args[3] as u32,
            args[4],
            args[5],
        ),
        SYSCALL_MUNMAP => sys_munmap(args[0], args[1]),
        SYSCALL_SET_PRIORITY => sys_set_priority(args[0] as isize),
        SYSCALL_SPAWN => sys_spawn(args[0] as *const u8),
        SYSCALL_THREAD_CREATE => sys_thread_create(args[0], args[1]),
        SYSCALL_WAITTID => sys_waittid(args[0]) as isize,
        SYSCALL_MUTEX_CREATE => sys_mutex_create(args[0] == 1),
        SYSCALL_MUTEX_LOCK => sys_mutex_lock(args[0]),
        SYSCALL_MUTEX_UNLOCK => sys_mutex_unlock(args[0]),
        SYSCALL_SEMAPHORE_CREATE => sys_semaphore_create(args[0]),
        SYSCALL_SEMAPHORE_UP => sys_semaphore_up(args[0]),
        SYSCALL_ENABLE_DEADLOCK_DETECT => sys_enable_deadlock_detect(args[0]),
        SYSCALL_SEMAPHORE_DOWN => sys_semaphore_down(args[0]),
        SYSCALL_CONDVAR_CREATE => sys_condvar_create(),
        SYSCALL_CONDVAR_SIGNAL => sys_condvar_signal(args[0]),
        SYSCALL_CONDVAR_WAIT => sys_condvar_wait(args[0], args[1]),
        SYSCALL_KILL => sys_kill(args[0], args[1] as u32),
        SYSCALL_TID_ADDRESS => sys_set_tid_addr(args[0]),
        SYSCALL_IOCTL => sys_ioctl(args[0], args[1], args[2]),
        //SYSCALL_WRITEV => sys_writev(args[0], args[1] as *const IoVec, args[2]),
        SYSCALL_EXIT_GROUP => sys_exit(0),
        SYSCALL_STATX => sys_statx(
            args[0] as isize,
            args[1] as *const u8,
            args[2] as i32,
            args[3] as u32,
            args[4] as *mut Statx,
        ),
        _ => panic!("Unsupported syscall_id: {}", syscall_id),
    }
}

bitflags! {
    //表示对应在文件上等待或者发生过的事件
    pub struct PollEvents: u16 {
        /// 可读
        const IN = 0x0001;
        /// 可写
        const OUT = 0x0004;
        /// 报错
        const ERR = 0x0008;
        /// 已终止，如 pipe 的另一端已关闭连接的情况
        const HUP = 0x0010;
        /// 无效的 fd
        const INVAL = 0x0020;
    }
}
