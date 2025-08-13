use super::sys_gettid;
use crate::alloc::string::ToString;
use crate::mm::MemorySet;
use crate::task::exit_current_group_and_run_next;
use crate::timer::TimeVal;
use crate::timer::{
    add_timer, calculate_left_timespec, get_time_ms, get_time_spec, Itimerval, TimeSpec,
    ITIMER_PROF, ITIMER_REAL, ITIMER_VIRTUAL,
};
use crate::{
    config::PAGE_SIZE,
    fs::{open, vfs::File, OpenFlags, NONE_MODE},
    mm::{
        copy_to_virt, insert_bad_address, is_bad_address, remove_bad_address, shm_attach,
        shm_create, shm_drop, shm_find, translated_ref, translated_refmut, translated_str,
        MapPermission, PhysAddr, ShmFlags, VirtAddr,
    },
    signal::{check_if_any_sig_for_current_task, SignalFlags},
    syscall::{process, sys_result::SysInfo, FutexCmd, FutexOpt, MmapFlags, MmapProt},
    task::{
        add_task, block_current_and_run_next, current_process, current_task, current_user_token,
        exit_current_and_run_next, futex_requeue, futex_wait, futex_wake_up, mmap, munmap,
        pid2process, process_num, remove_all_from_thread_group, remove_from_pid2process,
        suspend_current_and_run_next, CloneFlags, FutexKey, TmsInner,
    },
    utils::{c_ptr_to_string, get_abs_path, page_round_up, trim_start_slash, SysErrNo, SyscallRet},
};
use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicI32, Ordering};

pub fn sys_setsid() -> isize {
    0
}

//madvise
pub fn sys_madvise(_addr: usize, _len: usize, _advice: usize) -> isize {
    0
}

// sys futex
pub fn sys_futex(
    uaddr: *mut i32,
    futex_op: u32,
    val: i32,
    timeoutp: *const TimeSpec,
    uaddr2: *mut u32,
    val3: i32,
) -> isize {
    debug!("sys_futex");
    debug!("the futex op is : {}", futex_op & 0x7f);

    let cmd = FutexCmd::from_bits(futex_op & 0x7f).unwrap();
    let opt = FutexOpt::from_bits_truncate(futex_op);
    if uaddr.align_offset(4) != 0 {
        return SysErrNo::EINVAL as isize;
    }

    let process = current_process();
    let mut inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    let pa = inner
        .memory_set
        .translate_va(VirtAddr::from(uaddr as usize))
        .unwrap();

    let private = opt.contains(FutexOpt::FUTEX_PRIVATE_FLAG);

    let key = if private {
        FutexKey::new(pa, process.getpid())
    } else {
        FutexKey::new(pa, 0)
    };

    let va1 = VirtAddr::from(uaddr as usize);
    let va2 = VirtAddr::from(uaddr2 as usize);

    warn!(
        "uaddr={:#x} va1={:#x} -> {:?}, \
     uaddr2={:#x} va2={:#x} -> {:?}, \
     align(uaddr2)={}",
        uaddr as usize,
        va1.0,
        inner.memory_set.translate_va(va1),
        uaddr2 as usize,
        va2.0,
        inner.memory_set.translate_va(va2),
        (uaddr2 as usize) % 4
    );
    match cmd {
        FutexCmd::FUTEX_WAIT => {
            //let futex_word =  *uaddr;
            let futex_word = *translated_ref(token, uaddr);
            //log::debug!("[sys_futex] futex_word = {}", futex_word,);
            if futex_word != val {
                return SysErrNo::EAGAIN as isize;
            }
            if !timeoutp.is_null() {
                //let timeout = data_flow!({ *timeoutp });
                let timeout = *translated_ref(token, timeoutp);
                //log::debug!("[sys_futex] timeout={:?}", timeout);
                let time = get_time_ms();
                let timespec = TimeSpec {
                    tv_sec: time / 1000,
                    tv_nsec: (time % 1000) * 1000000,
                };
                add_timer(timespec, current_task().unwrap());
            }
            drop(inner);
            drop(process);
            futex_wait(key)
        }
        FutexCmd::FUTEX_WAKE => {
            drop(inner);
            drop(process);
            futex_wake_up(key, val) as isize
        }
        FutexCmd::FUTEX_REQUEUE => {
            let pa2 = inner
                .memory_set
                .translate_va(VirtAddr::from(uaddr2 as usize))
                .ok_or(SysErrNo::EINVAL)
                .unwrap();

            let new_key = if private {
                FutexKey::new(pa2, process.getpid())
            } else {
                FutexKey::new(pa2, 0)
            };
            drop(inner);
            drop(process);
            futex_requeue(key, val, new_key, timeoutp as i32) as isize
        }
        FutexCmd::FUTEX_WAKE_OP => {
            let op_arg1 = ((val3 >> 28) & 0xF) as u8;
            let op = ((val3 >> 24) & 0xF) as u8;
            let op_arg2 = (val3 & 0x00FF_FFFF) as i32;

            let pa2 = inner
                .memory_set
                .translate_va(VirtAddr::from(uaddr2 as usize))
                .ok_or(SysErrNo::EINVAL)
                .unwrap();

            if pa2.0 == 0 {
                return SysErrNo::EINVAL as isize;
            }
            debug!("the pa2 is : {:#x}", pa2.0);
            debug!("to get old");
            let atomic_ref = translated_refmut::<AtomicI32>(token, uaddr2 as *mut AtomicI32);
            let old = match op_arg1 {
                0 => atomic_ref.swap(op_arg2, Ordering::Relaxed),
                1 => atomic_ref.fetch_add(op_arg2, Ordering::Relaxed),
                2 => atomic_ref.fetch_or(op_arg2, Ordering::Relaxed),
                3 => atomic_ref.fetch_and(!op_arg2, Ordering::Relaxed),
                4 => atomic_ref.fetch_xor(op_arg2, Ordering::Relaxed),
                _ => return SysErrNo::EINVAL as isize,
            };

            let cmp_ok = match op {
                0 => old == op_arg2,
                1 => old != op_arg2,
                2 => old < op_arg2,
                3 => old <= op_arg2,
                4 => old > op_arg2,
                5 => old >= op_arg2,
                _ => return SysErrNo::EINVAL as isize,
            };

            let new_key = if private {
                FutexKey::new(pa2, process.getpid())
            } else {
                FutexKey::new(pa2, 0)
            };
            let wake_key = if cmp_ok { key } else { new_key };
            drop(inner);
            drop(process);
            futex_wake_up(wake_key, val) as isize
        }
        _ => unimplemented!(),
    }
}

//sys info
pub fn sys_sysinfo(info: *mut SysInfo) -> isize {
    let token = current_process().inner_exclusive_access().get_user_token();
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
    let current_process = current_process();
    let pid = current_process.getpid();
    debug!("exiting pid is:{},exit code is:{}", pid, exit_code);
    drop(current_process);
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
    debug!("(sys_fork) flags: {}, stack_ptr: {:#x}, parent_tid_ptr: {:#x}, tls_ptr: {:#x}, child_tid_ptr: {:#x}",
        flags, stack_ptr, parent_tid_ptr, tls_ptr, child_tid_ptr);
    let flags = CloneFlags::from_bits(flags as u32).unwrap();
    let current_process = current_process();
    //current_process.inner_exclusive_access().is_blocked+=1;
    let new_process = current_process.fork(
        flags,
        stack_ptr,
        parent_tid_ptr as *mut u32,
        tls_ptr,
        child_tid_ptr as *mut u32,
    );
    //debug!("sys_fork: current process pid is : {}",current_process.getpid());
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
    let current_process = current_process();
    debug!("current process id is :{}", current_process.getpid());
    let mut inner = current_process.inner_exclusive_access();
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
        if path.ends_with(".sh")
            && (path.contains("/musl")
                || inner.fs_info.get_cwd() == "/musl"
                || inner.fs_info.get_cwd().contains("/musl"))
        {
            //.sh文件不是可执行文件，需要用busybox的sh来启动
            debug!("push busybox");
            argv.push(String::from("/musl/busybox"));
            argv.push(String::from("sh"));
            path = String::from("/musl/busybox");
        }
        if path.ends_with(".sh")
            && (path.contains("/glibc")
                || inner.fs_info.get_cwd() == "/glibc"
                || inner.fs_info.get_cwd().contains("/glibc"))
        {
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

    let env_ld_library_path = "LD_LIBRARY_PATH=/lib:/glibc/lib:/musl/lib:".to_string();
    if !env.contains(&env_ld_library_path) {
        env.push(env_ld_library_path);
    }

    let env_enough = "ENOUGH=100000".to_string();
    if !env.contains(&env_enough) {
        //设置系统最大负载
        env.push(env_enough);
    }
    let cwd = if !path.starts_with('/') {
        debug!("the path is not start with / ");
        inner.fs_info.cwd()
    } else {
        "/"
    };
    debug!("get cwd ok, the cwd is :{}, the path is :{}", cwd, path);
    let mut abs_path = get_abs_path(&cwd, &path);
    if abs_path.contains("basename") {
        abs_path = String::from("/musl/busybox");
    }
    debug!("to open,the path is: {}", abs_path);
    let app_inode = open(&abs_path, OpenFlags::O_RDONLY, NONE_MODE, cwd)
        .unwrap()
        .file()
        .unwrap();
    inner.fs_info.set_exe(abs_path);
    let elf_data = app_inode.inode.read_all().unwrap();
    drop(inner);
    let len = argv.len();
    current_process.exec(&elf_data, argv, &mut env);
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
    {
        let process = current_process();
        //debug!("{} is waiting child", process.getpid());
        // find a child process
        let inner = process.inner_exclusive_access();
        if !inner
            .children
            .iter()
            .any(|p| pid == -1 || pid as usize == p.getpid())
        {
            //debug!("can not find the child, the options is : {}", options);
            if options == 1 {
                return 0;
            }
            return -10 as isize;
            // ---
            //- release current PCB
        }
    }
    if options == 0 {
        loop {
            let process = current_process();
            let mut inner = process.inner_exclusive_access();
            debug!(
                "in sys waitpid, inner fd table len is :{}",
                inner.fd_table.len()
            );
            let pair = inner.children.iter().enumerate().find(|(_, p)| {
                // ++++ temporarily access child PCB exclusively
                p.inner_exclusive_access().is_zombie && (pid == -1 || pid as usize == p.getpid())
                // ++++ release child PCB
            });
            if let Some((idx, _)) = pair {
                let child = inner.children.remove(idx);

                let found_pid = child.getpid();
                // ++++ temporarily access child PCB exclusively
                let exit_code = child.inner_exclusive_access().exit_code;
                debug!(
                    "sys_waitpid: found child pid {}, exit_code {}",
                    found_pid, exit_code
                );
                if exit_code_ptr as usize != 0x0 {
                    if exit_code >= 128 && exit_code <= 255 {
                        //表示由于信号而退出的
                        *translated_refmut(inner.get_user_token(), exit_code_ptr) = exit_code;
                    } else {
                        *translated_refmut(inner.get_user_token(), exit_code_ptr) = exit_code << 8;
                    }
                }
                // ++++ release child PCB
                drop(inner);
                drop(process);
                remove_all_from_thread_group(found_pid);
                remove_from_pid2process(found_pid);
                // confirm that child will be deallocated after being removed from children list
                assert_eq!(Arc::strong_count(&child), 1);
                return found_pid as isize;
            } else {
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
pub fn sys_getuid() -> isize {
    current_task().unwrap().process.upgrade().unwrap().getuid() as isize
}
///
pub fn sys_geteuid() -> isize {
    current_task().unwrap().process.upgrade().unwrap().getuid() as isize
}
/// getgid syscall
pub fn sys_getgid() -> isize {
    current_task().unwrap().process.upgrade().unwrap().getgid() as isize
}

/// set tid addr
pub fn sys_set_tid_addr(tidptr: usize) -> isize {
    current_task()
        .unwrap()
        .process
        .upgrade()
        .unwrap()
        .set_clear_child_tid(tidptr);
    sys_gettid()
}

/// kill syscall
pub fn sys_kill(pid: usize, signal: u32) -> isize {
    // trace!(
    //     "kernel:pid[{}] sys_kill",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    use crate::task::pid2process;
    if let Some(process) = pid2process(pid) {
        if let Some(flag) = SignalFlags::from_bits(signal as usize) {
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

pub fn sys_set_timer(
    which: usize,
    new_value: *const Itimerval,
    old_value: *mut Itimerval,
) -> isize {
    if (which as isize) < 0 {
        return SysErrNo::EINVAL as isize;
    }
    if (new_value as isize) < 0 || is_bad_address(new_value as usize) {
        return SysErrNo::EFAULT as isize;
    }
    if (old_value as isize) < 0 || is_bad_address(old_value as usize) {
        return SysErrNo::EFAULT as isize;
    }

    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();

    let sig = match which {
        ITIMER_REAL => SignalFlags::SIGALRM,
        ITIMER_VIRTUAL => SignalFlags::SIGVTALRM,
        ITIMER_PROF => SignalFlags::SIGPROF,
        _ => return SysErrNo::EINVAL as isize,
    };

    if old_value as usize != 0 {
        *translated_refmut(token, old_value) = inner.timer.timer();
    }
    if new_value as usize != 0 {
        let new_timer = *translated_ref(token, new_value);

        inner.timer.set_timer(new_timer, sig);
        inner.timer.set_last_time(TimeVal::now());
        if new_timer.it_interval.is_empty() {
            if !new_timer.it_value.is_empty() {
                inner.timer.set_trigger_once(true);
            }
        } else {
            inner.timer.set_trigger_once(false);
        }
    }
    0
}
//
pub fn sys_clockgettime(clockid: usize, tp: *mut TimeVal) -> isize {
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
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let process_tms = inner.tms.inner;
    drop(inner);
    copy_to_virt(&process_tms, tms);
    0
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

//伪实现
pub fn sys_log(_logtype: isize, _bufp: *const u8, _len: usize) -> isize {
    0
}

pub fn sys_exit_group(exit_code: i32) -> isize {
    exit_current_group_and_run_next(exit_code);
    unreachable!();
    -1
}

pub fn sys_set_robust_list(head: usize, len: usize) -> isize {
    if len != crate::task::RobustList::HEAD_SIZE {
        return SysErrNo::EINVAL as isize;
    }
    let process = current_process();
    let mut inner = process.inner_exclusive_access();
    inner.robust_list.head = head;
    //inner.robust_list.len = len;
    0
}

pub fn sys_sched_getaffinity(_pid: usize, _cpusetsize: usize, _mask: usize) -> isize {
    0
}

//clock nano sleep
pub fn sys_clock_nano_sleep(
    clockid: usize,
    flags: u32,
    time_ptr: *const TimeSpec,
    remain: *mut TimeSpec,
) -> isize {
    const TIME_ABSTIME: u32 = 1;
    // let task = current_task().unwrap();
    // let task_inner = task.inner_lock();
    // drop(task_inner);
    // drop(task);
    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    drop(inner);
    drop(process);

    if clockid != 0 && clockid != 1 {
        return SysErrNo::EOPNOTSUPP as isize;
    }

    if (time_ptr as isize) <= 0 || is_bad_address(time_ptr as usize) {
        return SysErrNo::EFAULT as isize;
    }

    if (remain as isize) < 0 || is_bad_address(remain as usize) {
        return SysErrNo::EFAULT as isize;
    }

    // let t = get_data(memory_set.token(), time_ptr);
    //let t = data_flow!({ *time_ptr });
    let t = *translated_ref(token, time_ptr);

    if (t.tv_sec as isize) < 0 || (t.tv_nsec as isize) < 0 || t.tv_nsec >= 1_000_000_000usize {
        return SysErrNo::EINVAL as isize;
    }

    let waittime = t.tv_sec * 1_000_000_000usize + t.tv_nsec;

    let begin = get_time_ms() * 1_000_000usize;
    let endtime = if flags == TIME_ABSTIME {
        //绝对时间
        t
    } else {
        //相对时间
        get_time_spec() + t
    };

    debug!(
        "[sys_clock_nanosleep] ready to sleep for {} sec, {} nsec",
        t.tv_sec, t.tv_nsec
    );

    while get_time_ms() * 1_000_000usize - begin < waittime {
        if let Some(_) = check_if_any_sig_for_current_task() {
            //被信号唤醒
            debug!("interupt by signal");
            if remain as usize != 0 {
                // put_data(memory_set, remain, calculate_left_timespec(endtime));
                //data_flow!({ *remain = calculate_left_timespec(endtime) })
                *translated_refmut(token, remain) = calculate_left_timespec(endtime);
            }
            //handle_signal(signo);
            return SysErrNo::EINTR as isize;
        }
        suspend_current_and_run_next();
    }
    0
}

pub fn sys_getegid() -> isize {
    0
}