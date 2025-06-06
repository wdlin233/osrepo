#![no_std]
#![no_main]

extern crate user_lib;
use user_lib::println;
use user_lib::{exec, fork, wait, yield_};

#[no_mangle]
fn main() -> i32 {
    println!("[initproc] Init process started");
    if fork() == 0 {
        //println!("[initproc] Forked child process, executing user_shell");
        exec("usertests\0", &[core::ptr::null::<u8>()]);
    } else {
        //println!("[initproc] Parent process waiting for child to finish");
        loop {
            let mut exit_code: i32 = 0;
            let pid = wait(&mut exit_code);
            if pid == -1 {
                yield_();
                continue;
            }
            println!(
                "[initproc] Released a zombie process, pid={}, exit_code={}",
                pid,
                exit_code,
            );
        }
    }
    0
}
