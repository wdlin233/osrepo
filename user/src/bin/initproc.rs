#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

const TESTS: &[&str] = &[
    //"glibc/busybox_testcode.sh\0",
    "/musl/busybox_testcode.sh\0",
    //"musl/basic_testcode.sh\0",
    // "glibc/basic_testcode.sh\0",
];

const TEST_NUM: usize = TESTS.len();

use user_lib::{exec, fork, run_busyboxsh, sched_yield, waitpid};

#[no_mangle]
pub fn main() -> i32 {
    let mut pids = [0; TEST_NUM];
    for (i, &test) in TESTS.iter().enumerate() {
        println!("Usertests: Running {}", test);
        let pid = fork();
        if pid == 0 {
            let cwd = if test.contains("/musl") {
                "/musl/busybox\0"
            } else {
                "/glibc/busybox\0"
            };
            run_busyboxsh(test, cwd);
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
