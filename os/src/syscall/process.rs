use super::sys_gettid;
use crate::alloc::string::ToString;
use crate::mm::MemorySet;
use crate::signal::{send_access_signal, send_signal_to_thread_group};
use crate::task::{exit_current_group_and_run_next, move_child_process_to_init, remove_all_from_thread_group, PROCESS_GROUP};
use crate::timer::get_time_ms;
use crate::{
    config::PAGE_SIZE,
    fs::{open, vfs::File, OpenFlags, NONE_MODE},
    mm::{
        copy_to_virt, insert_bad_address, is_bad_address, remove_bad_address, translated_ref,
        translated_refmut, translated_str, MapPermission, PhysAddr, VirtAddr,
    },
    signal::SignalFlags,
    syscall::{process, sys_result::SysInfo, MmapFlags, MmapProt},
    task::{
        add_task, block_current_and_run_next, current_task, current_user_token,
        exit_current_and_run_next, mmap, munmap, tid2task, process_num,
        suspend_current_and_run_next, TmsInner,
    },
    utils::{c_ptr_to_string, get_abs_path, page_round_up, trim_start_slash, SysErrNo, SyscallRet},
};
use alloc::{string::String, sync::Arc, vec::Vec};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

//sys info
pub fn sys_sysinfo(info: *mut SysInfo) -> isize {
    let token = current_task().unwrap().inner_exclusive_access().get_user_token();
    *translated_refmut(token, info) = SysInfo::new(get_time_ms() / 1000, 1 << 56, process_num());
    0
}

/// exit syscall
///
/// exit the current task and run the next task in task list
pub fn sys_exit(exit_code: i32) -> ! {
    // trace!(
    //     "kernel:pid[{}] sys_exit",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    let current_task = current_task().unwrap();
    let pid = current_task.getpid();
    debug!("exiting pid is:{},exit code is:{}", pid, exit_code);
    drop(current_task);
    exit_current_and_run_next(exit_code);
    debug!("exit ok");
    panic!("Unreachable in sys_exit!");
}
/// yield syscall
pub fn sys_yield() -> isize {
    //debug!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// fork child process syscall
pub fn sys_fork(
    flags: usize,
    stack_ptr: usize,
    parent_tid_ptr: usize,
    tls_ptr: usize,
    child_tid_ptr: usize,
) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_fork",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    use crate::syscall::CloneFlags;
    debug!("(sys_fork) flags: {}, stack_ptr: {:#x}, parent_tid_ptr: {:#x}, tls_ptr: {:#x}, child_tid_ptr: {:#x}",
        flags, stack_ptr, parent_tid_ptr, tls_ptr, child_tid_ptr);
    let flags = CloneFlags::from_bits(flags as u32).unwrap();
    let current_task = current_task().unwrap();
    //current_task.inner_exclusive_access().is_blocked+=1;
    let new_process = current_task.fork(
        flags,
        stack_ptr,
        parent_tid_ptr as *mut u32,
        tls_ptr,
        child_tid_ptr as *mut u32,
    );
    //debug!("sys_fork: current process pid is : {}",current_task.getpid());
    let new_pid = new_process.getpid();
    debug!("(sys_fork) the new pid is :{}", new_pid);

    //debug!("sys_fork: the new pid is : {}",new_pid);
    new_pid as isize
}
/// exec syscall
pub fn sys_exec(pathp: *const u8, mut args: *const usize, mut envp: *const usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_exec(path: 0x{:x?}, args: 0x{:x?})",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     path,
    //     args
    // );
    //unimplemented!()
    debug!("in sys exec");
    let current_task = current_task().unwrap();
    debug!("current process id is :{}", current_task.getpid());
    let inner = current_task.inner_exclusive_access();
    //debug!("get inner ok");
    let mut argv = Vec::<String>::new();
    let mut env = Vec::<String>::new();
    let mut path;
    let token = inner.get_user_token();
    unsafe {
        //debug!("in unsafe");
        debug!("the pathp is :{:?}", pathp);
        debug!("the path is :{}", translated_str(token, pathp));
        path = trim_start_slash(translated_str(token, pathp));
        debug!("trim path ok,the path is :{}", path);
        if path.contains("/musl") {
            debug!("in set cwd");
            inner.fs_info.set_cwd(String::from("/musl"));
        }
        if path.contains("/glibc") {
            inner.fs_info.set_cwd(String::from("/glibc"));
        }
        if path.ends_with(".sh") && path.contains("/musl") {
            //.sh文件不是可执行文件，需要用busybox的sh来启动
            debug!("push busybox");
            argv.push(String::from("busybox"));
            argv.push(String::from("sh"));
            path = String::from("/busybox");
        }
        if path.ends_with(".sh") && path.contains("/glic") {
            //.sh文件不是可执行文件，需要用busybox的sh来启动
            debug!("push busybox");
            argv.push(String::from("/glibc/busybox"));
            argv.push(String::from("sh"));
            path = String::from("/glibc/busybox");
        }

        //处理argv参数
        // loop {
        //     let argv_ptr = *args;
        //     if argv_ptr == 0 {
        //         break;
        //     }
        //     argv.push(c_ptr_to_string(argv_ptr as *const u8));
        //     args = args.add(1);
        // }
        // debug!("to deal the argv");
        // if !envp.is_null() {
        //     loop {
        //         let envp_ptr = *envp;
        //         if envp_ptr == 0 {
        //             break;
        //         }
        //         env.push(c_ptr_to_string(envp_ptr as *const u8));
        //         envp = envp.add(1);
        //     }
        // }

        loop {
            let arg_str_ptr = *translated_ref(token, args);
            if arg_str_ptr == 0 {
                break;
            }
            debug!(
                "the argv is : {}",
                translated_str(token, arg_str_ptr as *const u8)
            );
            argv.push(translated_str(token, arg_str_ptr as *const u8));
            args = args.add(1);
        }

        //处理envp参数
        if !envp.is_null() {
            debug!("envp is not null");
            loop {
                let envp_ptr = *translated_ref(token, envp);
                if envp_ptr == 0 {
                    break;
                }
                env.push(translated_str(token, envp_ptr as *const u8));
                envp = envp.add(1);
            }
        }
    }
    let env_path = "PATH=/:/bin:".to_string();
    if !env.contains(&env_path) {
        env.push(env_path);
    }

    let env_ld_library_path = "LD_LIBRARY_PATH=/lib:/lib/glibc:/lib/musl:".to_string();
    if !env.contains(&env_ld_library_path) {
        env.push(env_ld_library_path);
    }

    let env_enough = "ENOUGH=100000".to_string();
    if !env.contains(&env_enough) {
        //设置系统最大负载
        env.push(env_enough);
    }
    let cwd = if !path.starts_with('/') {
        //debug!("the path is not start with / ");
        inner.fs_info.cwd()
    } else {
        "/"
    };
    debug!("get cwd ok, the cwd is :{}, the path is :{}", cwd, path);
    let abs_path = get_abs_path(&cwd, &path);
    debug!("to open,the path is: {}", abs_path);
    let app_inode = open(&abs_path, OpenFlags::O_RDONLY, NONE_MODE)
        .unwrap()
        .file()
        .unwrap();
    inner.fs_info.set_exe(abs_path);
    let elf_data = app_inode.inode.read_all().unwrap();
    drop(inner);
    let len = argv.len();
    current_task.exec(&elf_data, argv, &mut env);
    debug!("in sys exec, return argv len is :{}", len);
    0
}

/// waitpid syscall
///
/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
/// block to wait
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32, options: usize) -> isize {
    //debug!("kernel: sys_waitpid");
    if (pid as i32) == i32::MIN {
        return SysErrNo::ESRCH as isize;
    }
    if options < 0 || options > 100 {
        return SysErrNo::EINVAL as isize;
    }
    loop {
        let mut process_group = PROCESS_GROUP.exclusive_access();
        let process = current_task().unwrap();
        let inner = process.inner_exclusive_access();
        if !process_group.contains_key(&process.getpid()) {
            return SysErrNo::ECHILD as isize;
        }
        // 放入 Fork 出来的子进程
        let children = process_group.get_mut(&process.getpid()).unwrap();
        if !children.iter().any(|p| pid == -1 || pid as usize == p.getpid()) {
            return SysErrNo::ECHILD as isize;
        }
        // 寻找符合条件的进程组
        let pair = children
            .iter()
            .enumerate()
            .find(|(_, p)| {
                // ++++ temporarily access child PCB exclusively
                p.inner_exclusive_access().is_group_exit() && (pid == -1 || pid as usize == p.getpid())
                // ++++ release child PCB
            })
            .map(|(idx, t)| (idx, Arc::clone(t)));
        
        if let Some((idx, child)) = pair {
            let found_pid = child.getpid();
            let child_inner = child.inner_exclusive_access();
            // ++++ temporarily access child PCB exclusively
            let exit_code = child_inner.sig_table.exit_code();
            debug!(
                "sys_waitpid: found child pid {}, exit_code {}",
                found_pid, exit_code
            );
            if exit_code_ptr as usize != 0x0 {
                if exit_code >= 128 && exit_code <= 255 {
                    *translated_refmut(child_inner.memory_set.token(), exit_code_ptr) = exit_code;    
                } else {
                    *translated_refmut(child_inner.memory_set.token(), exit_code_ptr) = exit_code << 8;
                }
            }
            drop(child_inner);
            // 从进程组中删除子进程
            children.remove(idx);
            drop(inner);
            drop(process);
            drop(process_group);
            // 从线程组移除
            remove_all_from_thread_group(found_pid);
            // 转移子进程
            move_child_process_to_init(found_pid);
            assert_eq!(Arc::strong_count(&child), 1,
                "process{} can't recycled", child.getpid()
            );
            return found_pid as isize;
        } else {
            drop(inner);
            drop(process);
            drop(process_group);
            debug!("sys_waitpid: no child found, block current process");
            block_current_and_run_next();
        }
    }
      
}

/// getpid syscall
pub fn sys_getpid() -> isize {
    // trace!(
    //     "kernel: sys_getpid pid:{}",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    current_task().unwrap().getpid() as isize
}
/// getppid syscall
pub fn sys_getppid() -> isize {
    current_task().unwrap().getppid() as isize
}

/// getuid syscall
pub fn sys_getuid() -> isize {
    current_task().unwrap().getuid() as isize
}
///
pub fn sys_geteuid() -> isize {
    current_task().unwrap().getuid() as isize
}
/// getgid syscall
pub fn sys_getgid() -> isize {
    current_task().unwrap().getgid() as isize
}

/// set tid addr
pub fn sys_set_tid_addr(tidptr: usize) -> isize {
    current_task()
        .unwrap()
        .set_clear_child_tid(tidptr);
    sys_gettid()
}

/// kill syscall
pub fn sys_kill(pid: isize, signal: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_kill",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    if signal == 0 {
        return 0;
    }
    let sig = SignalFlags::from_sig(signal);
    match pid {
        _ if pid > 0 => send_signal_to_thread_group(pid as usize , sig),
        0 => send_signal_to_thread_group(current_task().unwrap().getpid(), sig),
        -1 => send_access_signal(current_task().unwrap().gettid(), sig),
        _ => send_signal_to_thread_group(-pid as usize, sig),
    }
    return 0;
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
//
pub fn sys_clockgettime(_clockid: usize, tp: *mut TimeVal) -> isize {
    let ms = crate::timer::get_time_ms();
    let time = TimeVal {
        sec: ms / 1000,
        usec: (ms % 1000) * 1000000,
    };
    copy_to_virt(&time, tp);
    0
}

/// get times
pub fn sys_tms(tms: *mut TmsInner) -> isize {
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    let process_tms = inner.tms.inner;
    drop(inner);
    copy_to_virt(&process_tms, tms);
    0
}

/// mmap syscall ref: https://man7.org/linux/man-pages/man2/mmap.2.html
/// `flags` determins whether updates mapping,
/// `fd` as file descriptor, `off` as offset in file
pub fn sys_mmap(addr: usize, len: usize, port: u32, flags: u32, fd: usize, off: usize) -> isize {
    debug!(
        "[sys_mmap] addr={:#x}, len={:#x}, port={:#x}, flags={:#x}, fd={}, off={:#x}",
        addr, len, port, flags, fd, off
    );
    if flags == 0 {
        return SysErrNo::EINVAL as isize;
    }
    let flags = MmapFlags::from_bits(flags).unwrap();
    if fd == usize::MAX && !flags.contains(MmapFlags::MAP_ANONYMOUS) {
        return SysErrNo::EBADF as isize;
    }
    if len == 0 {
        return SysErrNo::EINVAL as isize;
    }
    let mmap_prot = MmapProt::from_bits(port).unwrap();
    let permission: MapPermission = mmap_prot.into();
    if flags.contains(MmapFlags::MAP_FIXED) && addr == 0 {
        return SysErrNo::EPERM as isize;
    }
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    let len = page_round_up(len);
    if fd == usize::MAX {
        let ret = inner
            .memory_set
            .mmap(addr, len, permission, flags, None, usize::MAX);
        return ret as isize;
    }
    if flags.contains(MmapFlags::MAP_ANONYMOUS) {
        // anonymous mapping
        let ret = inner
            .memory_set
            .mmap(0, 1, MapPermission::empty(), flags, None, usize::MAX);
        insert_bad_address(ret);
        debug!("[sys_mmap] bad address is {:x}", ret);
        return ret as isize;
    }
    // file mapping
    let inode = inner.fd_table.get(fd);
    let file = match inode.file() {
        Ok(n) => n,
        Err(_) => return SysErrNo::EBADF as isize, //?
    };
    #[cfg(target_arch = "riscv64")]
    if (permission.contains(MapPermission::R) && !file.readable())
        || (permission.contains(MapPermission::W) && !file.writable())
        || (mmap_prot != MmapProt::PROT_NONE && inode.flags.contains(OpenFlags::O_WRONLY))
    {
        //如果需要读/写/执行方式映射，必须要求文件可读
        return SysErrNo::EACCES as isize;
    }
    #[cfg(target_arch = "loongarch64")]
    if (permission.contains(MapPermission::NR) && file.readable())
        || (permission.contains(MapPermission::W) && !file.writable())
        || (mmap_prot != MmapProt::PROT_NONE && inode.flags.contains(OpenFlags::O_WRONLY))
    {
        //如果需要读/写/执行方式映射，必须要求文件可读
        return SysErrNo::EACCES as isize;
    }
    let ret = inner
        .memory_set
        .mmap(addr, len, permission, flags, Some(file), off);
    info!(
        "[sys_mmap] alloc addr={:#x}, return from MemorySetInner mmap",
        ret
    );
    return ret as isize;
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(addr: usize, len: usize) -> isize {
    debug!("[sys_munmap] addr={:#x}, len={:#x}", addr, len);
    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    let len = page_round_up(len);
    if is_bad_address(addr) {
        remove_bad_address(addr);
    }
    inner.memory_set.munmap(addr, len)
}

// change data segment size
pub fn sys_brk(path: usize) -> isize {
    debug!("in sys brk, the path is : {}", path);
    let process = current_task().unwrap();
    let fromer_addr: usize = process.change_program_brk(0);
    debug!("in sys brk, the fromer addr is : {}", fromer_addr);
    if path == 0 {
        return fromer_addr as isize;
    }
    let grow_size: isize = (path - fromer_addr) as isize;
    debug!("in sys brk, the grow size is : {}", grow_size);
    process.change_program_brk(grow_size) as isize

    // if let Some(result) = inner.res.as_mut().unwrap().change_program_brk(0) {
    //     if path == 0 {
    //         return result;
    //     }
    //     let grow_size: isize = (brk_addr - fromer_addr) as isize;

    //     debug!("to returning result : {}", result as isize);
    //     result as isize
    // } else {
    //     -1
    // }
}
// like sys_spawn a unnecessary syscall


pub fn sys_set_priority(prio: isize) -> isize {
    // debug!(
    //     "kernel:pid[{}] sys_set_priority(prio: {})",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     prio
    // );
    let process = current_task().unwrap();
    let mut inner = process.inner_exclusive_access();
    if prio >= 2 {
        inner.priority = prio as usize;
        prio
    } else {
        -1
    }
}

//伪实现
pub fn sys_log(_logtype: isize, _bufp: *const u8, _len: usize) -> isize {
    0
}

pub fn sys_exit_group(exit_code: i32) -> isize {
    exit_current_group_and_run_next(exit_code);
    unreachable!();
}

pub fn sys_mprotect(addr: usize, len: usize, prot: u32) -> isize {
    if addr == 0 {
        return SysErrNo::ENOMEM as isize;
    }

    if (addr % PAGE_SIZE != 0) || (len % PAGE_SIZE != 0) {
        log::warn!("sys_mprotect: not align");
        return SysErrNo::EINVAL as isize;
    }
    let map_perm: MapPermission = MmapProt::from_bits(prot).unwrap().into();

    debug!(
        "[sys_mprotect] addr is {:x}, len is {:#x}, map_perm is {:?}",
        addr, len, map_perm
    );

    let process = current_task().unwrap();
    let inner = process.inner_exclusive_access();
    let memory_set = inner.memory_set.get_mut();
    let start_vpn = VirtAddr::from(addr).floor();
    let end_vpn = VirtAddr::from(addr + len).ceil();
    //修改各段的mappermission
    memory_set.mprotect(start_vpn, end_vpn, map_perm);
    return 0;
}

pub fn sys_set_robust_list(head: usize, len: usize) -> isize {
    if len != crate::task::RobustList::HEAD_SIZE {
        return SysErrNo::EINVAL as isize;
    }
    let process = current_task().unwrap();
    let mut inner = process.inner_exclusive_access();
    inner.robust_list.head = head;
    //inner.robust_list.len = len;
    0
}
