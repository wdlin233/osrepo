use crate::mm::{translated_byte_buffer, translated_ref, UserBuffer};
use crate::task::{current_task, current_user_token};

#[repr(C)]
pub struct IoVec {
    pub iov_base: *mut u8,  
    pub iov_len: usize,   
}

pub fn sys_ioctl() -> isize {
    0
}

pub fn sys_writev(fd: usize, iov: *const IoVec, iovcnt: usize) -> isize {
    let mut total_write_size: isize = 0;
    let token = current_user_token();
    let process = current_task();
    let inner = process.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        if !file.writable() {
            return -1;
        }
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        for i in 0..iovcnt {
            let iov_ptr = translated_ref(token, iov.wrapping_add(i));
            total_write_size += file.write(UserBuffer::new(translated_byte_buffer(
                token, 
                (*iov_ptr).iov_base,
                (*iov_ptr).iov_len,
            )).as_bytes()) as isize;
        }
    } else {
        return -1;
    }
    total_write_size
}