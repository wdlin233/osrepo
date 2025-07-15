use crate::system::UTSname;

/// get some system information
pub fn sys_uname(uname: *mut UTSname)-> isize {
    let mut name = UTSname::new();
    name.get();
    unsafe {
        *uname = name
    }
    0
}