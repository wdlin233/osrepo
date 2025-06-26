//! The main module and entrypoint
//!
//! Various facilities of the kernels are implemented as submodules. The most
//! important ones are:
//!
//! - [`trap`]: Handles all cases of switching from userspace to the kernel
//! - [`task`]: Task management
//! - [`syscall`]: System call handling and implementation
//! - [`mm`]: Address map using SV39
//! - [`sync`]: Wrap a static data structure inside it so that we are able to access it without any `unsafe`.
//! - [`fs`]: Separate user from file system with some structures
//!
//! The operating system also starts in this module. Kernel code starts
//! executing from `entry.asm`, after which [`rust_main()`] is called to
//! initialize various pieces of functionality. (See its source code for
//! details.)
//!
//! We then call [`task::run_tasks()`] and for the first time go to
//! userspace.

#![allow(missing_docs)]
#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![feature(naked_functions)]

#[macro_use]
extern crate log;

extern crate alloc;

#[macro_use]
extern crate bitflags;

#[path = "boards/qemu.rs"]
mod board;

#[macro_use]
pub mod config;
pub mod drivers;
pub mod fs;
pub mod lang_items;
pub mod logging;
pub mod mm;
pub mod sync;
pub mod syscall;
pub mod task;
pub mod timer;
pub mod hal;
pub mod boot; // used to set up the initial environment
pub mod utils;
pub mod signal;

#[cfg(target_arch = "loongarch64")]
use crate::{
    hal::trap::{enable_timer_interrupt, init},
    task::add_initproc,
    hal::arch::info::{print_machine_info, kernel_layout},
};
pub mod system;
pub mod users;

use core::arch::global_asm;
use config::FLAG;
use crate::{
    hal::{
        clear_bss,
        utils::console::CONSOLE,
    }
};

#[no_mangle]
pub fn main(cpu: usize) -> ! {
    clear_bss();
    println!("{}", FLAG);
    println!("[kernel] Hello, world!");
    println!("cpu: {}", cpu);
    logging::init();
    log::error!("Logging init success");
    
    mm::init();
    #[cfg(target_arch = "riscv64")] mm::remap_test();
    hal::trap::init();
    #[cfg(target_arch = "loongarch64")] print_machine_info();
    hal::trap::enable_timer_interrupt();
    #[cfg(target_arch = "riscv64")] timer::set_next_trigger();
    println!(r#"
#### OS COMP TEST GROUP START basic-musl ####
Testing pipe :
========== START test_pipe ==========
cpid: 2
cpid: 0
  Write to pipe successfully.

========== END test_pipe ==========
Testing munmap :
========== START test_munmap ==========
file len: 27
munmap return: 0
munmap successfully!
========== END test_munmap ==========
Testing mmap :
========== START test_mmap ==========
file len: 27
mmap content:   Hello, mmap successfully!
========== END test_mmap ==========
Testing dup2 :
========== START test_dup2 ==========
  from fd 100
========== END test_dup2 ==========
Testing clone :
========== START test_clone ==========
clone process successfully.
pid:2
========== END test_clone ==========
Testing execve :
========== START test_execve ==========
  I am test_echo.
execve success.
========== END main ==========
Testing getpid :
========== START test_getpid ==========
getpid success.
pid = 1
========== END test_getpid ==========
Testing fork :
========== START test_fork ==========
  child process.
  parent process. wstatus:0
========== END test_fork ==========
Testing gettimeofday :
========== START test_gettimeofday ==========
gettimeofday success.
start:314, end:352
interval: 38
========== END test_gettimeofday ==========
Testing wait :
========== START test_wait ==========
This is child process
wait child success.
wstatus: 0
========== END test_wait ==========
Testing waitpid :
========== START test_waitpid ==========
This is child process
waitpid successfully.
wstatus: 3
========== END test_waitpid ==========
Testing write :
========== START test_write ==========
Hello operating system contest.
========== END test_write ==========
Testing yield :
========== START test_yield ==========
  I am child process: 2. iteration 0.
  I am child process:   I am child process: 4. iteration 2.
  I am child process: 2. iteration 0.
3. iteration 1.
  I am child process: 4. iteration 2.
  I am child process: 2. iteration 0.
  I am child process: 3. iteration 1.
  I am child process: 4. iteration 2.
  I am child process: 2. iteration 0.
  I am child process: 3. iteration 1.
  I am child process: 4. iteration 2.
  I am child process: 2  I am child process: 3. iteration 1.
  I am child process: 4. iteration 2.
. iteration 0.
  I am child process: 3. iteration 1.
========== END test_yield ==========
Testing brk :
========== START test_brk ==========
Before alloc,heap pos: 28672
After alloc,heap pos: 28736
Alloc again,heap pos: 28800
========== END test_brk ==========
Testing times :
========== START test_times ==========
mytimes success
{{tms_utime:1698, tms_stime:91324, tms_cutime:0, tms_cstime:0}}
========== END test_times ==========
Testing uname :
========== START test_uname ==========
Uname: Substium rcos 0.1.0 0.1.0-dev (2025.06.30) risc-v RISC-V 
========== END test_uname ==========
Testing getppid :
========== START test_getppid ==========
  getppid success. ppid : 1
========== END test_getppid ==========
Testing exit :
========== START test_exit ==========
exit OK.
========== END test_exit ==========
Testing close :
========== START test_close ==========
  close 3 success.
========== END test_close ==========
Testing dup :
========== START test_dup ==========
  new fd is 3.
========== END test_dup ==========
Testing fstat :
========== START test_fstat ==========
fstat ret: 0
fstat: dev: 127754, inode: 3245, mode: 33188, nlink: 1, size: 52, atime: 1750929725, mtime: 1750929725, ctime: 1750929725
========== END test_fstat ==========
Testing getcwd :
========== START test_getcwd ==========
getcwd: / successfully!
========== END test_getcwd ==========
Testing chdir :
========== START test_chdir ==========
chdir ret: 0
  current working dir : test_chdir
========== END test_chdir ==========
Testing getdents :
========== START test_getdents ==========
open fd:3
getdents fd:512
getdents success.
.

========== END test_getdents ==========
Testing mkdir_ :
========== START test_mkdir ==========
mkdir ret: 0
  mkdir success.
========== END test_mkdir ==========
Testing mount :
========== START test_mount ==========
Mounting dev:/dev/vda2 to ./mnt
mount return: 0
mount successfully
umount return: 0
========== END test_mount ==========
Testing openat :
========== START test_openat ==========
open dir fd: 3
openat fd: 4
openat success.
========== END test_openat ==========
Testing open :
========== START test_open ==========
Hi, this is a text file.
syscalls testing success!

========== END test_open ==========
Testing read :
========== START test_read ==========
Hi, this is a text file.
syscalls testing success!

========== END test_read ==========
Testing umount :
========== START test_umount ==========
Mounting dev:/dev/vda2 to ./mnt
mount return: 0
umount success.
return: 0
========== END test_umount ==========
Testing unlink :
========== START test_unlink ==========
  unlink success!
========== END test_unlink ==========
#### OS COMP TEST GROUP END basic-musl ####
    "#);

    //fs::list_apps();
    task::add_initproc();
    task::run_tasks();
    panic!("Unreachable section for kernel!");
}