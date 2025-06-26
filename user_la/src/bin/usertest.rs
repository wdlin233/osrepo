#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

// 除去 mnt 的 basic
static TESTS: &[&str] = &[
    "basic/dup2\0",
    "basic/clone\0",
    "basic/execve\0",
    "basic/exit\0",
    "basic/fork\0",
    "basic/getpid\0",
    "basic/gettimeofday\0",
    "basic/wait\0",
    "basic/waitpid\0",
    "basic/write\0",
    "basic/yield\0",
    "basic/brk\0",
    "basic/getppid\0",
    "basic/times\0",
    
    "basic/chdir\0", 
    "basic/close\0", 
    "basic/dup\0", 
    "basic/fstat\0", 
    "basic/getcwd\0", 
    "basic/getdents\0", 
    "basic/mkdir_\0", 
    "basic/mmap\0", 
    "basic/mount\0", 
    "basic/munmap\0", 
    "basic/openat\0", 
    "basic/open\0", 
    "basic/pipe\0", 
    "basic/read\0", 
    "basic/umount\0", 
    "basic/uname\0", 
    "basic/unlink\0",
];

const TEST_NUM: usize = TESTS.len();

use user_lib::{exec, fork, waitpid};

#[no_mangle]
pub fn main() -> i32 {
    let mut pids = [0; TEST_NUM];
    println!("#### OS COMP TEST GROUP START basic-musl ####");
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
    println!("#### OS COMP TEST GROUP END basic-musl ####");
    0
}
