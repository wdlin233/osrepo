use crate::system::UTSname;
use crate::mm::copy_to_virt;

/// get some system information
pub fn sys_uname(uname: *mut UTSname)-> isize {
    let mut name = UTSname::new();
    name.get();
    copy_to_virt(&name,uname);
    0
}