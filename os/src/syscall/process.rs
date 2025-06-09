use crate::{
    fs::{open_file, OpenFlags},
    mm::{copy_to_virt, translated_ref, translated_refmut, translated_str},
    task::{
        current_process, current_task, current_user_token, exit_current_and_run_next, pid2process,
        suspend_current_and_run_next, SignalFlags, mmap, munmap,block_current_and_run_next,
        TmsInner,
    }, 
    config::PAGE_SIZE,
};
use alloc::{string::String, sync::Arc, vec::Vec};

#[repr(C)]
#[derive(Debug,Copy,Clone)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// exit syscall
///
/// exit the current task and run the next task in task list
pub fn sys_exit(exit_code: i32) -> ! {
    // trace!(
    //     "kernel:pid[{}] sys_exit",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    // let current_process = current_process();
    // let pid = current_process.getpid();
    // debug!("exiting pid is:{},exit code is:{}",pid,exit_code);
    // drop(current_process);
    exit_current_and_run_next(exit_code);
    //debug!("exit ok");
    panic!("Unreachable in sys_exit!");
}
/// yield syscall
pub fn sys_yield() -> isize {
    //debug!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// fork child process syscall
pub fn sys_fork() -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_fork",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    let current_process = current_process();
    //current_process.inner_exclusive_access().is_blocked+=1;
    let new_process = current_process.fork();
    //debug!("sys_fork: current process pid is : {}",current_process.getpid());
    let new_pid = new_process.getpid();
    // modify trap context of new_task, because it returns immediately after switching
    let new_process_inner = new_process.inner_exclusive_access();
    let task = new_process_inner.tasks[0].as_ref().unwrap();
    let trap_cx = task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    #[cfg(target_arch = "riscv64")]
    {
        trap_cx.x[10] = 0;
    }
    #[cfg(target_arch = "loongarch64")]
    {
        trap_cx.x[4] = 0;
    }
    //debug!("sys_fork: the new pid is : {}",new_pid);
    new_pid as isize
}
/// exec syscall
pub fn sys_exec(path: *const u8, mut args: *const usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_exec(path: 0x{:x?}, args: 0x{:x?})",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     path,
    //     args
    // );
    let token = current_user_token();
    let path = translated_str(token, path);
    let mut args_vec: Vec<String> = Vec::new();
    loop {
        let arg_str_ptr = *translated_ref(token, args);
        if arg_str_ptr == 0 {
            break;
        }
        args_vec.push(translated_str(token, arg_str_ptr as *const u8));
        unsafe {
            args = args.add(1);
        }
    }
    use crate::fs::ROOT_INODE;
    let root_ino = ROOT_INODE.clone();
    if let Some(app_inode_entry) = open_file(root_ino, path.as_str(), OpenFlags::O_RDONLY) {
        let all_data = app_inode_entry.inode().read_all();
        let process = current_process();
        let argc = args_vec.len();
        //trace!("argc in syscall {}", argc);
        //trace!("args_vec {:?}", args_vec);
        process.exec(all_data.as_slice(), args_vec);
        // return argc because cx.x[10] will be covered with it later
        argc as isize
    } else {
        -1
    }
}

/// waitpid syscall
///
/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
/// block to wait
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32,options: usize) -> isize {
    debug!("kernel: sys_waitpid");
    {
        let process = current_process();
        //debug!("{} is waiting child",process.getpid());
        // find a child process
        let inner = process.inner_exclusive_access();
        if !inner
            .children
            .iter()
            .any(|p| pid == -1 || pid as usize == p.getpid())
        {
            //debug!("can not find the child");
            return -1;
            // ---
            //- release current PCB
        }
    }
    if options ==0 {
        loop {
            let process = current_process();
            let mut inner = process.inner_exclusive_access();
            let pair = inner.children.iter().enumerate().find(|(_, p)| {
                // ++++ temporarily access child PCB exclusively
                p.inner_exclusive_access().is_zombie && (pid == -1 || pid as usize == p.getpid())
                // ++++ release child PCB
            });
            if let Some((idx, _)) = pair {
                let child = inner.children.remove(idx);
                // confirm that child will be deallocated after being removed from children list
                assert_eq!(Arc::strong_count(&child), 1);
                let found_pid = child.getpid();
                // ++++ temporarily access child PCB exclusively
                let exit_code = child.inner_exclusive_access().exit_code;
                debug!(
                    "sys_waitpid: found child pid {}, exit_code {}",
                    found_pid,
                    exit_code
                );
                // ++++ release child PCB
                *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code << 8;
                return found_pid as isize;
            }else {
                drop(inner);
                debug!("sys_waitpid: no child found, block current process");
                block_current_and_run_next();
            }
        }
    }
    -2
}

/// getpid syscall
pub fn sys_getpid() -> isize {
    // trace!(
    //     "kernel: sys_getpid pid:{}",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    current_task().unwrap().process.upgrade().unwrap().getpid() as isize
}
/// getppid syscall
pub fn sys_getppid() -> isize {
    current_task().unwrap().process.upgrade().unwrap().getppid() as isize
}

/// getuid syscall
pub fn sys_getuid()->isize{
    current_task().unwrap().process.upgrade().unwrap().getuid() as isize
}
/// getgid syscall
pub fn sys_getgid()->isize{
    current_task().unwrap().process.upgrade().unwrap().getgid() as isize
}

/// kill syscall
pub fn sys_kill(pid: usize, signal: u32) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_kill",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    if let Some(process) = pid2process(pid) {
        if let Some(flag) = SignalFlags::from_bits(signal) {
            process.inner_exclusive_access().signals |= flag;
            0
        } else {
            -1
        }
    } else {
        -1
    }
}

/// get_time syscall
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_get_time(ts: {:?}, tz: {})",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     ts,
    //     _tz
    // );
    let us = crate::timer::get_time_us();
    let time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    copy_to_virt(&time_val, ts);
    0
}

/// get times
pub fn sys_tms(tms: *mut TmsInner)->isize {
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let process_tms = inner.tms.inner;
    drop(inner);
    copy_to_virt(&process_tms,tms);
    0
}


/// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_mmap)(start: 0x{start:x}, len: 0x{len:x}, port: 0x{port:x})",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    const PORT_MASK: usize = 0b111;
     
    let aligned_start = start % PAGE_SIZE == 0;
    let port_valid = (port & !PORT_MASK) == 0;
    let port_not_none = (port & PORT_MASK) != 0;
     
    //trace!("each condition: aligned_start={}, port_valid={}, port_not_none={}", aligned_start, port_valid, port_not_none);
    if aligned_start && port_valid && port_not_none {
        return mmap(start, len, port)
    }
    -1
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_munmap(start: 0x{start:x}, len: 0x{len:x})",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    let aligned_start = start % PAGE_SIZE == 0;
    if aligned_start {
        return munmap(start, len)
    }
    -1
}

// change data segment size
pub fn sys_brk(_path: i32) -> isize {
    //trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().process.upgrade().unwrap().getpid());
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if let Some(result) = inner.res.as_mut().unwrap().change_program_brk(_path) {
        debug!("to returning result : {}",result);
        result as isize
    } else {
        -1
    }
    
}
// like sys_spawn a unnecessary syscall

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(path: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_spawn(path: 0x{path:x?})",
        current_task().unwrap().process.upgrade().unwrap().getpid()
    );
    // let token = current_user_token();
    // let path = translated_str(token, path);
    // if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
    //     let all_data = app_inode.read_all();
    //     let task = current_task().unwrap().spwan(all_data.as_slice());
    //     let new_pid = task.getpid();
    //     add_task(task);
    //     new_pid as isize
    // } else {
    //     -1
    // }
    -1
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(prio: isize) -> isize {
    // debug!(
    //     "kernel:pid[{}] sys_set_priority(prio: {})",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     prio
    // );
    let process = current_process();
    let mut inner = process.inner_exclusive_access();
    if prio >= 2 {
        inner.priority = prio as usize;
        prio
    } else {
        -1
    }
}
