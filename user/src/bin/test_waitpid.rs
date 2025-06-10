#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

use user_lib::{fork,sched_yield,exit,waitpid};

#[no_mangle]
fn main() -> i32 {
    let mut i = 1000;
    let mut wstatus: i32 =0;
    let cpid = fork();
    if cpid == 0 {
        while i !=0 {
            i -=1;
        }
        sched_yield();
        println!("this is child process");
        exit(3);
    }
    else {
        let ret = waitpid(cpid as usize, &mut wstatus , 0);
        if ret == cpid && wstatus ==3{
            println!("waitpid sucess");
        }
        else {
            println!("waitpid error");
        }
    }
    0
}