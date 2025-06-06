#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

// 除去 mnt 的 basic syscall 测试
static TESTS: &[&str] = &[
    "dup2\0",
    "clone\0",
    "execve\0",
    "exit\0",
    "fork\0",
    "getpid\0",
    "gettimeofday\0",
    "wait\0",
    "waitpid\0",
    "write\0",
    "yield\0",

    "brk\0", // 214
    "chdir\0", // 34
    "close\0", // panic
    "dup\0", // 23
    "fstat\0", // fatal
    "getcwd\0", // 17
    "getdents\0", // 61
    "getppid\0", // error
    "mkdir_\0", // 34
    "mmap\0", // panic
    "mount\0", // 40
    "munmap\0", // panic
    "openat\0", // panic
    "open\0", // fatal
    "pipe\0", // waiting forever
    "read\0", // fatal
    "times\0", // 153
    "umount\0", // panic
    "uname\0", // 160
    "unlink\0", // panic
];

use user_lib::{exec, fork, waitpid};

#[no_mangle]
pub fn main() -> i32 {
    for test in TESTS {
        println!("Usertests: Running {}", test);
        let pid = fork();
        if pid == 0 {
            exec(*test, &[core::ptr::null::<u8>()]);
            panic!("unreachable!");
        } else {
            let mut exit_code: i32 = Default::default();
            let wait_pid = waitpid(pid as usize, &mut exit_code);
            assert_eq!(pid, wait_pid);
            println!(
                "\x1b[32mUsertests: Test {} in Process {} exited with code {}\x1b[0m",
                test, pid, exit_code
            );
        }
    }
    println!("Usertests passed!");
    0
}
