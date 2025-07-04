#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;
/*

const TESTS: &[&str] = &[
    //"mnt/test_mount\0",
    "pipe\0",
    "munmap\0",
            "mmap\0",

                "dup2\0",
    "clone\0",
    "execve\0",
    "getpid\0",
    "fork\0",
    "gettimeofday\0",
    "wait\0",
    "waitpid\0",
    "write\0",
    "yield\0",
    "brk\0",
    "times\0",
    "uname\0",
    "getppid\0",
    "exit\0",
    "close\0",
    "dup\0",
    "fstat\0",
    "getcwd\0",
    "chdir\0",
    "getdents\0",
        "mkdir_\0",
    "mount\0",
    "openat\0",
    "open\0",
    "read\0",
    "umount\0",
    "unlink\0",
*/
const TESTS: &[&str] = &["basic_testcode.sh\0"];

const TEST_NUM: usize = TESTS.len();

use user_lib::{exec, fork, waitpid};

#[no_mangle]
pub fn main() -> i32 {
    let mut pids = [0; TEST_NUM];
    for (i, &test) in TESTS.iter().enumerate() {
        println!("Usertests: Running {}", test);
        let pid = fork();
        if pid == 0 {
            exec(&*test, &[core::ptr::null::<u8>()]);
            panic!("unreachable!");
        } else {
            pids[i] = pid;
        }
        let mut xstate: i32 = Default::default();
        let wait_pid = waitpid(pids[i] as usize, &mut xstate, 0);
        assert_eq!(pids[i], wait_pid);
        println!(
            "\x1b[32mUsertests: Test {} in Process {} exited with code {}\x1b[0m",
            test, pids[i], xstate
        );
    }
    println!("[usertest] Basic usertests passed!");
    0
}
