use crate::mm::{is_bad_address, translated_ref, translated_refmut};
use crate::signal::check_if_any_sig_for_current_task;
use crate::sync::{
    alloc, dealloc, disable_banker_algo, enable_banker_algo, init_available_resource, request,
    Condvar, Mutex, MutexBlocking, MutexSpin, RequestResult, Semaphore,
};
use crate::task::{
    current_process, current_task, current_user_token, suspend_current_and_run_next,
};
use crate::timer::{add_timer, calculate_left_timespec, get_time_ms, get_time_spec, TimeSpec};
use crate::utils::SysErrNo;
use alloc::sync::Arc;
/// sleep syscall
pub fn sys_sleep(req_ptr: *const TimeSpec, rem: *mut TimeSpec) -> isize {
    if (req_ptr as isize) <= 0 || is_bad_address(req_ptr as usize) {
        return SysErrNo::EFAULT as isize;
    }

    if (rem as isize) < 0 || is_bad_address(rem as usize) {
        return SysErrNo::EFAULT as isize;
    }

    let process = current_process();
    let inner = process.inner_exclusive_access();
    let token = inner.get_user_token();
    drop(inner);
    drop(process);
    let req = *translated_ref(token, req_ptr);
    let waittime = req.tv_sec * 1_000_000_000usize + req.tv_nsec;
    let begin = get_time_ms() * 1_000_000usize;
    let endtime = get_time_spec() + req;

    if (req.tv_sec as isize) < 0 || (req.tv_nsec as isize) < 0 || req.tv_nsec >= 1000_000_000usize {
        return SysErrNo::EINVAL as isize;
    }

    // debug!(
    //     "[sys_nanosleep] ready to sleep for {} sec, {} nsec",
    //     req.tv_sec, req.tv_nsec
    // );

    while get_time_ms() * 1_000_000usize - begin < waittime {
        if let Some(_) = check_if_any_sig_for_current_task() {
            //被信号唤醒
            if rem as usize != 0 {
                *translated_refmut(token, rem) = calculate_left_timespec(endtime);
            }
            return SysErrNo::EINTR as isize;
        }
        suspend_current_and_run_next();
    }
    0
}
/// mutex create syscall
pub fn sys_mutex_create(blocking: bool) -> isize {
    // trace!(
    //     "kernel:pid[{}] tid[{}] sys_mutex_create",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     current_task()
    //         .unwrap()
    //         .inner_exclusive_access()
    //         .res
    //         .as_ref()
    //         .unwrap()
    //         .tid
    // );
    let process = current_process();
    let mutex: Option<Arc<dyn Mutex>> = if !blocking {
        Some(Arc::new(MutexSpin::new()))
    } else {
        Some(Arc::new(MutexBlocking::new()))
    };
    // init_available_resource(0, 1);
    let mut process_inner = process.inner_exclusive_access();
    if let Some(id) = process_inner
        .mutex_list
        .iter()
        .enumerate()
        .find(|(_, item)| item.is_none())
        .map(|(id, _)| id)
    {
        init_available_resource(id, 1);
        process_inner.mutex_list[id] = mutex;
        id as isize
    } else {
        init_available_resource(process_inner.mutex_list.len(), 1);
        process_inner.mutex_list.push(mutex);
        process_inner.mutex_list.len() as isize - 1
    }
}
/// mutex lock syscall
pub fn sys_mutex_lock(mutex_id: usize) -> isize {
    let tid = current_task().unwrap().inner_exclusive_access().tid;
    let process = current_process();
    let process_inner = process.inner_exclusive_access();
    let mutex: Arc<dyn Mutex + 'static> =
        Arc::clone(process_inner.mutex_list[mutex_id].as_ref().unwrap());
    drop(process_inner);
    drop(process);
    match request(tid, mutex_id, 1) {
        RequestResult::Error => return -0xDEAD,
        _ => {}
    }
    mutex.lock();
    alloc(tid, mutex_id, 1);
    0
}
/// mutex unlock syscall
pub fn sys_mutex_unlock(mutex_id: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] tid[{}] sys_mutex_unlock",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     current_task()
    //         .unwrap()
    //         .inner_exclusive_access()
    //         .res
    //         .as_ref()
    //         .unwrap()
    //         .tid
    // );
    let tid = current_task().unwrap().inner_exclusive_access().tid;
    let process = current_process();
    let process_inner = process.inner_exclusive_access();
    let mutex = Arc::clone(process_inner.mutex_list[mutex_id].as_ref().unwrap());
    drop(process_inner);
    drop(process);
    mutex.unlock();
    dealloc(tid, mutex_id, 1);
    0
}
/// semaphore create syscall
pub fn sys_semaphore_create(res_count: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] tid[{}] sys_semaphore_create",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     current_task()
    //         .unwrap()
    //         .inner_exclusive_access()
    //         .res
    //         .as_ref()
    //         .unwrap()
    //         .tid
    // );
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let id = if let Some(id) = process_inner
        .semaphore_list
        .iter()
        .enumerate()
        .find(|(_, item)| item.is_none())
        .map(|(id, _)| id)
    {
        //init_available_resource(id, res_count);
        process_inner.semaphore_list[id] = Some(Arc::new(Semaphore::new(res_count)));
        id
    } else {
        process_inner
            .semaphore_list
            .push(Some(Arc::new(Semaphore::new(res_count))));
        //info!("kernel: create semaphore {}", process_inner.semaphore_list.len());
        //init_available_resource(process_inner.semaphore_list.len(), res_count);
        process_inner.semaphore_list.len() - 1
    };
    init_available_resource(id, res_count);
    id as isize
}
/// semaphore up syscall
pub fn sys_semaphore_up(sem_id: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] tid[{}] sys_semaphore_up",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     current_task()
    //         .unwrap()
    //         .inner_exclusive_access()
    //         .res
    //         .as_ref()
    //         .unwrap()
    //         .tid
    // );
    let tid = current_task().unwrap().inner_exclusive_access().tid;
    dealloc(tid, sem_id, 1);
    let process = current_process();
    let process_inner = process.inner_exclusive_access();
    let sem = Arc::clone(process_inner.semaphore_list[sem_id].as_ref().unwrap());
    drop(process_inner);
    sem.up();
    // dealloc() is ok
    0
}
/// semaphore down syscall
pub fn sys_semaphore_down(sem_id: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] tid[{}] sys_semaphore_down",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     current_task()
    //         .unwrap()
    //         .inner_exclusive_access()
    //         .res
    //         .as_ref()
    //         .unwrap()
    //         .tid
    // );
    let tid = current_task().unwrap().inner_exclusive_access().tid;
    let process = current_process();
    let process_inner = process.inner_exclusive_access();
    let sem = Arc::clone(process_inner.semaphore_list[sem_id].as_ref().unwrap());
    drop(process_inner);
    match request(tid, sem_id, 1) {
        RequestResult::Error => return -0xDEAD,
        _ => {}
    }
    //trace!("sem.down() with sem_id: {}", sem_id);
    // alloc() cant be here
    sem.down();
    alloc(tid, sem_id, 1);
    0
}
/// condvar create syscall
pub fn sys_condvar_create() -> isize {
    // trace!(
    //     "kernel:pid[{}] tid[{}] sys_condvar_create",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     current_task()
    //         .unwrap()
    //         .inner_exclusive_access()
    //         .res
    //         .as_ref()
    //         .unwrap()
    //         .tid
    // );
    let process = current_process();
    let mut process_inner = process.inner_exclusive_access();
    let id = if let Some(id) = process_inner
        .condvar_list
        .iter()
        .enumerate()
        .find(|(_, item)| item.is_none())
        .map(|(id, _)| id)
    {
        process_inner.condvar_list[id] = Some(Arc::new(Condvar::new()));
        id
    } else {
        process_inner
            .condvar_list
            .push(Some(Arc::new(Condvar::new())));
        process_inner.condvar_list.len() - 1
    };
    id as isize
}
/// condvar signal syscall
pub fn sys_condvar_signal(condvar_id: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] tid[{}] sys_condvar_signal",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     current_task()
    //         .unwrap()
    //         .inner_exclusive_access()
    //         .res
    //         .as_ref()
    //         .unwrap()
    //         .tid
    // );
    let process = current_process();
    let process_inner = process.inner_exclusive_access();
    let condvar = Arc::clone(process_inner.condvar_list[condvar_id].as_ref().unwrap());
    drop(process_inner);
    condvar.signal();
    0
}
/// condvar wait syscall
pub fn sys_condvar_wait(condvar_id: usize, mutex_id: usize) -> isize {
    // trace!(
    //     "kernel:pid[{}] tid[{}] sys_condvar_wait",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     current_task()
    //         .unwrap()
    //         .inner_exclusive_access()
    //         .res
    //         .as_ref()
    //         .unwrap()
    //         .tid
    // );
    let process = current_process();
    let process_inner = process.inner_exclusive_access();
    let condvar = Arc::clone(process_inner.condvar_list[condvar_id].as_ref().unwrap());
    let mutex = Arc::clone(process_inner.mutex_list[mutex_id].as_ref().unwrap());
    drop(process_inner);
    condvar.wait(mutex);
    0
}
/// enable deadlock detection syscall
///
/// YOUR JOB: Implement deadlock detection, but might not all in this syscall
pub fn sys_enable_deadlock_detect(enabled: usize) -> isize {
    //trace!("kernel: sys_enable_deadlock_detect(enbaled={})", enabled);
    match enabled {
        0 => disable_banker_algo(),
        1 => enable_banker_algo(),
        _ => return -1,
    }
    0
}
