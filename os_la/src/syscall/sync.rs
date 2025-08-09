use super::process::TimeVal;
use crate::mm::translated_ref;
use crate::sync::{
    alloc, dealloc, disable_banker_algo, enable_banker_algo, init_available_resource, request,
    Condvar, Mutex, MutexBlocking, MutexSpin, RequestResult, Semaphore,
};
use crate::task::{block_current_and_run_next, current_process, current_task, current_user_token};
use crate::timer::{add_timer, get_time_ms};
use alloc::sync::Arc;
/// sleep syscall
pub fn sys_sleep(req: *const TimeVal) -> isize {
    // trace!(
    //     "kernel:pid[{}] tid[{}] sys_sleep",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     current_task()
    //         .unwrap()
    //         .inner_exclusive_access()
    //         .res
    //         .as_ref()
    //         .unwrap()
    //         .tid
    // );
    let re: TimeVal;
    let token = current_user_token();
    re = *translated_ref(token, req);
    //debug!("the expected sec is:{}",re.sec);
    let expire_ms = get_time_ms() + re.sec * 1000;
    let task = current_task().unwrap();
    add_timer(expire_ms, task);
    block_current_and_run_next();
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
    // trace!(
    //     "kernel:pid[{}] tid[{}] sys_mutex_lock",
    //     current_task().unwrap().process.upgrade().unwrap().getpid(),
    //     current_task()
    //         .unwrap()
    //         .inner_exclusive_access()
    //         .res
    //         .as_ref()
    //         .unwrap()
    //         .tid
    // );
    let tid = current_task()
        .unwrap()
        .inner_exclusive_access()
        .res
        .as_ref()
        .unwrap()
        .tid;
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
    let tid = current_task()
        .unwrap()
        .inner_exclusive_access()
        .res
        .as_ref()
        .unwrap()
        .tid;
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
    let tid = current_task()
        .unwrap()
        .inner_exclusive_access()
        .res
        .as_ref()
        .unwrap()
        .tid;
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
    let tid = current_task()
        .unwrap()
        .inner_exclusive_access()
        .res
        .as_ref()
        .unwrap()
        .tid;
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
