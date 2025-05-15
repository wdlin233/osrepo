#![no_std]
#![no_main]

extern crate user_lib;

use user_lib::{println, trace_read, trace_write, mmap, munmap};

#[no_mangle]
pub fn main() -> usize {
    #[allow(unused_mut)]
    let mut var = 111u8;
    assert_eq!(Some(111), trace_read(&var as *const _));
    var = 22;
    assert_eq!(Some(22), trace_read(&var as *const _));
    assert_eq!(0, trace_write(&var as *const _, 33));

    assert_eq!(None, trace_read(isize::MAX as usize as *const _));
    assert_eq!(-1, trace_write(isize::MAX as usize as *const _, 0));
    assert_eq!(None, trace_read(0x80200000 as *const _));
    assert_eq!(-1, trace_write(0x80200000 as *const _, 0));
    
    let start: usize = 0x10000000;
    let len: usize = 4096;
    let prot: usize = 1; // READONLY

    assert_eq!(0, mmap(start, len, prot));

    assert!(None != trace_read(start as *const u8));
    assert_eq!(-1, trace_write(start as *const u8, 0));

    assert_eq!(0, munmap(start, len));

    assert_eq!(None, trace_read(start as *const u8));
    assert_eq!(-1, trace_write(start as *const u8, 0));

    println!("Test trace_1 OK!");
    0
}
