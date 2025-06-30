#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

use user_lib::{exec, fork, run_busyboxsh, wait, yield_};

const TESTS: &[&str] = &[
    "musl/busybox_testcode.sh\0", 
    "glibc/busybox_testcode.sh\0",
    "musl/basic_testcode.sh\0",
    "glibc/basic_testcode.sh\0",
];

const TEST_NUM: usize = TESTS.len();

#[no_mangle]
fn main() -> i32 {
    println!("[initproc] Init process started");
    let mut pids = [0; TEST_NUM];
    for (i, &test) in TESTS.iter().enumerate() {
        println!("[initproc] Running test: {}", test);
        let pid = fork();
        if pid == 0 {
            run_busyboxsh(test);
            panic!("unreachable! Child process should not return here.");
        } else {
            pids[i] = pid;
        }
        let mut exit_code: i32 = Default::default();
        let wait_pid = wait(&mut exit_code);
        assert_eq!(pids[i], wait_pid, "Expected to wait for the same PID");
        println!(
            "[initproc] Test {} in Process {} exited with code {}",
            test, pids[i], exit_code
        );
    }
    println!("[initproc] All basic usertests passed!");
    0
}
