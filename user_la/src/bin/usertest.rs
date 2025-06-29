#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

// 除去 mnt 的 basic
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
    "brk\0",
    "getppid\0",
    "times\0",
    
    "chdir\0", 
    "close\0", 
    "dup\0", 
    "fstat\0", 
    "getcwd\0", 
    "getdents\0", 
    "mkdir_\0", 
    "mmap\0", 
    "mount\0", 
    "munmap\0", 
    "openat\0", 
    "open\0", 
    "pipe\0", 
    "read\0", 
    "umount\0", 
    "uname\0", 
    "unlink\0",
];

const TEST_NUM: usize = TESTS.len();

use user_lib::{exec, fork, waitpid};

#[no_mangle]
pub fn main() -> i32 {
    let mut pids = [0; TEST_NUM];
    for (i, &test) in TESTS.iter().enumerate() {
        println!("Testing {} :", test);
        let pid = fork();
        if pid == 0 {
            exec(&*test, &[core::ptr::null::<u8>()]);
            panic!("unreachable!");
        } else {
            pids[i] = pid;
        }
        let mut exit_code: i32 = Default::default();
        println!("Usertests: Forked process with pid {}", pids[i]);
        let wait_pid = waitpid(pids[i] as usize, &mut exit_code);
        // println!(
        //     "Usertests: Process {} exited with code {}",
        //     pids[i], exit_code
        // );
        assert_eq!(pids[i], wait_pid);
        // println!(
        //     "\x1b[32mUsertests: Test {} in Process {} exited with code {}\x1b[0m",
        //     test, pids[i], exit_code
        // );
    }
    //println!("Usertests passed!");
    0
}
