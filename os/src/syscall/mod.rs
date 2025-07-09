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

pub const SYSCALL_GETCWD: usize = 17;
pub const SYSCALL_DUP: usize = 23;
pub const SYSCALL_DUP3: usize = 24;
pub const SYSCALL_FCNTL: usize = 25;
pub const SYSCALL_IOCTL: usize = 29;
pub const SYSCALL_MKDIRAT: usize = 34;
pub const SYSCALL_UNLINKAT: usize = 35;
pub const SYSCALL_LINKAT: usize = 37;
pub const SYSCALL_UNMOUNT2: usize = 39;
pub const SYSCALL_MOUNT: usize = 40;
pub const SYSCALL_FACCESSAT: usize = 48;
pub const SYSCALL_CHDIR: usize = 49;
pub const SYSCALL_OPENAT: usize = 56;
pub const SYSCALL_CLOSE: usize = 57;
pub const SYSCALL_PIPE: usize = 59;
pub const SYSCALL_GETDENTS64: usize = 61;
pub const SYSCALL_LSEEK: usize = 62;
pub const SYSCALL_READ: usize = 63;
pub const SYSCALL_WRITE: usize = 64;
pub const SYSCALL_READV: usize = 65;
pub const SYSCALL_WRITEV: usize = 66;
pub const SYSCALL_SENDFILE: usize = 71;
pub const SYSCALL_READLINKAT: usize = 78;
pub const SYSCALL_FSTAT: usize = 80;
pub const SYSCALL_UTIMENSAT: usize = 88;
pub const SYSCALL_EXIT: usize = 93;
pub const SYSCALL_EXIT_GROUP: usize = 94;
pub const SYSCALL_TID_ADDRESS: usize = 96;
pub const SYSCALL_SETROBUSTLIST: usize = 99;
pub const SYSCALL_SLEEP: usize = 101;
pub const SYSCALL_CLOCKGETTIME: usize = 113;
pub const SYSCALL_LOG: usize = 116;
pub const SYSCALL_YIELD: usize = 124;
pub const SYSCALL_KILL: usize = 129;
//pub const SYSCALL_TGKILL: usize = 131;
pub const SYSCALL_SIGRETURN: usize = 139;
pub const SYSCALL_SIGACTION: usize = 134;
pub const SYSCALL_SIGPROCMASK: usize = 135;
pub const SYSCALL_SET_PRIORITY: usize = 140;
pub const SYSCALL_TIMES: usize = 153;
pub const SYSCALL_UNAME: usize = 160;
pub const SYSCALL_GETTIMEOFDAY: usize = 169;
pub const SYSCALL_GETPID: usize = 172;
pub const SYSCALL_GETPPID: usize = 173;
pub const SYSCALL_GETUID: usize = 174;
pub const SYSCALL_GETEUID: usize = 175;
pub const SYSCALL_GETGID: usize = 176;
pub const SYSCALL_GETTID: usize = 178;
pub const SYSCALL_SYSINFO: usize = 179;
pub const SYSCALL_FORK: usize = 220;
pub const SYSCALL_EXEC: usize = 221;
pub const SYSCALL_BRK: usize = 214;
pub const SYSCALL_MUNMAP: usize = 215;
pub const SYSCALL_MMAP: usize = 222;
pub const SYSCALL_WAITPID: usize = 260;
pub const SYSCALL_STATX: usize = 291;
pub const SYSCALL_PPOLL: usize = 73;
pub const SYSCALL_FSTATAT: usize = 79;
pub const SYSCALL_SIGTIMEDWAIT: usize = 137;
pub const SYSCALL_PRLIMIT: usize = 261;
pub const SYSCALL_MPROTECT: usize = 226;
pub const SYSCALL_GETRANDOM: usize = 278;

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

use crate::syscall::sys_result::SysInfo;
use crate::{
    fs::{Kstat, Statx},
    signal::{SigAction, SigInfo, SignalFlags},
    system::UTSname,
    task::TmsInner,
    timer::TimeSpec,
};

/// handle syscall exception with `syscall_id` and other arguments
pub fn syscall(syscall_id: usize, args: [usize; 6]) -> isize {
    info!("##### syscall with id {} #####", syscall_id);
    match syscall_id {
        SYSCALL_SETROBUSTLIST => sys_set_robust_list(args[0], args[1]),
        SYSCALL_READLINKAT => sys_readlinkat(
            args[0] as isize,
            args[1] as *const u8,
            args[2] as *const u8,
            args[3],
        ),
        SYSCALL_LSEEK => sys_lseek(args[0], args[1] as isize, args[2]),
        SYSCALL_SYSINFO => sys_sysinfo(args[0] as *mut SysInfo),
        SYSCALL_READV => sys_readv(args[0], args[1] as *const u8, args[2]),
        SYSCALL_UTIMENSAT => sys_utimensat(
            args[0] as isize,
            args[1] as *const u8,
            args[2] as *const TimeVal,
            args[3],
        ),
        SYSCALL_FACCESSAT => sys_faccessat(
            args[0] as isize,
            args[1] as *const u8,
            args[2] as u32,
            args[3],
        ),
        SYSCALL_LOG => sys_log(args[0] as isize, args[1] as *const u8, args[2]),
        SYSCALL_CLOCKGETTIME => sys_clockgettime(args[0], args[1] as *mut TimeVal),
        SYSCALL_SENDFILE => sys_sendfile(args[0], args[1], args[2], args[3]),
        SYSCALL_GETEUID => sys_geteuid(),
        SYSCALL_FCNTL => sys_fcntl(args[0], args[1], args[2]),
        SYSCALL_SIGACTION => sys_sigaction(
            args[0],
            args[1] as *const SigAction,
            args[2] as *mut SigAction,
        ),
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
        SYSCALL_KILL => sys_kill(args[0] as isize, args[1]),
        SYSCALL_TID_ADDRESS => sys_set_tid_addr(args[0]),
        SYSCALL_IOCTL => sys_ioctl(args[0], args[1], args[2]),
        SYSCALL_WRITEV => sys_writev(args[0], args[1] as *const u8, args[2]),
        SYSCALL_EXIT_GROUP => sys_exit_group(args[0] as i32),
        SYSCALL_STATX => sys_statx(
            args[0] as isize,
            args[1] as *const u8,
            args[2] as i32,
            args[3] as u32,
            args[4] as *mut Statx,
        ),
        SYSCALL_PPOLL => sys_ppoll(args[0], args[1], args[2], args[3]),
        SYSCALL_FSTATAT => sys_fstatat(
            args[0] as isize,
            args[1] as *const u8,
            args[2] as *mut Kstat,
            args[3],
        ),
        SYSCALL_SIGTIMEDWAIT => sys_sigtimedwait(
            args[0] as *const SignalFlags,
            args[1] as *const SigInfo,
            args[2] as *const TimeSpec,
        ),
        SYSCALL_PRLIMIT => sys_prlimit(
            args[0],
            args[1] as u32,
            args[2] as *const RLimit,
            args[3] as *mut RLimit,
        ),
        SYSCALL_MPROTECT => sys_mprotect(args[0], args[1], args[2] as u32),
        SYSCALL_GETRANDOM => sys_getrandom(
            args[0] as *mut u8,
            args[1],
            args[2] as u32,
        ),
        _ => panic!("Unsupported syscall_id: {}", syscall_id),
    }
}
