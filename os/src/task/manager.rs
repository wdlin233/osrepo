//! Implementation of [`TaskManager`]
//!
//! It is only used to manage processes and schedule process based on ready queue.
//! Other CPU process monitoring functions are in Processor.

use super::{ProcessControlBlock, TaskStatus};
use crate::sync::UPSafeCell;
use crate::task::INITPROC;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use lazy_static::*;
use spin::{Lazy, Mutex};
///A array of `ProcessControlBlock` that is thread-safe
pub struct TaskManager {
    ready_queue: VecDeque<Arc<ProcessControlBlock>>,
    ///block map : <pid,>
    block_map: BTreeMap<usize, Arc<ProcessControlBlock>>,
    /// The stopping task, leave a reference so that the kernel stack will not be recycled when switching tasks
    stop_task: Option<Arc<ProcessControlBlock>>,
}

/// A simple FIFO scheduler.
impl TaskManager {
    ///Creat an empty TaskManager
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
            block_map: BTreeMap::new(),
            stop_task: None,
        }
    }
    /// Add process back to ready queue
    pub fn add(&mut self, task: Arc<ProcessControlBlock>) {
        self.ready_queue.push_back(task);
    }
    /// Add a task to stopping task
    pub fn add_stop(&mut self, task: Arc<ProcessControlBlock>) {
        // NOTE: as the last stopping task has completely stopped (not
        // using kernel stack any more, at least in the single-core
        // case) so that we can simply replace it;
        self.stop_task = Some(task);
    }
    /// Add a task to block task
    pub fn add_block(&mut self, process: Arc<ProcessControlBlock>) {
        //The blocking queue
        // which temporarily holds tasks waiting for timer expiration.
        self.block_map.insert(process.getpid(), process);
    }

    /// Take a process out of the ready queue
    pub fn fetch(&mut self) -> Option<Arc<ProcessControlBlock>> {
        //debug!("ready queue size:{}", self.ready_queue.len());
        self.ready_queue.pop_front()
    }
    pub fn remove(&mut self, task: Arc<ProcessControlBlock>) {
        if let Some((id, _)) = self
            .ready_queue
            .iter()
            .enumerate()
            .find(|(_, t)| Arc::as_ptr(t) == Arc::as_ptr(&task))
        {
            self.ready_queue.remove(id);
        }
    }
    /// remove block
    pub fn remove_block(&mut self, process: &Arc<ProcessControlBlock>) {
        let pid = process.getpid();
        //debug!("remove block :{}",pid);
        self.block_map.remove(&pid);
    }
    /// remove block by pid
    pub fn remove_block_by_pid(&mut self, pid: usize) {
        //debug!("remove block by pid:{}",pid);
        if let Some(task) = self.block_map.remove(&pid) {
            let mut inner = task.inner_exclusive_access();
            if inner.task_status != TaskStatus::Ready {
                inner.task_status = TaskStatus::Ready;
                drop(inner);
                self.add(task);
                debug!("(remove_block_by_pid) Add task ok : {}", pid);
            }
        }
    }
    pub fn wakeup_parent(&mut self, pid: usize) {
        let idx = self
            .ready_queue
            .iter()
            .enumerate()
            .find(|(_, task)| {
                task.getpid() == pid && task.inner_exclusive_access().task_status == TaskStatus::Ready
            })
            .map(|(idx, _)| idx);
        if let Some(idx) = idx {
            // log::info!("wake up parent {}", pid);
            let p = self.ready_queue.remove(idx).unwrap();
            self.ready_queue.push_front(p);
        } else {
            // info!("no parent pid=={}", pid);
            // 父进程已被回收,被添加到了initproc下
            if pid != 1 {
                // log::info!("wake up parent {}", 0);
                self.wakeup_parent(1);
            }
        }
    }
}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
    /// TID_TO_TASK instance (map of pid to pcb)
    pub static ref TID_TO_TASK: UPSafeCell<BTreeMap<usize, Arc<ProcessControlBlock>>> =
        unsafe { UPSafeCell::new(BTreeMap::new()) };
}

/// Add a task to ready queue
pub fn add_task(task: Arc<ProcessControlBlock>) {
    //debug!("kernel: TaskManager::add_task");
    TASK_MANAGER.exclusive_access().add(task);
}
/// Add a task to block queue
pub fn add_block_task(task: Arc<ProcessControlBlock>) {
    TASK_MANAGER.exclusive_access().add_block(task);
}

/// Wake up a task
pub fn wakeup_task(task: Arc<ProcessControlBlock>) {
    //trace!("kernel: TaskManager::wakeup_task");
    let mut task_inner = task.inner_exclusive_access();
    task_inner.task_status = TaskStatus::Ready;
    drop(task_inner);
    TASK_MANAGER.exclusive_access().remove_block(&task);
    add_task(task);
}
/// wake up a task by pid
pub fn wakeup_task_by_pid(pid: usize) {
    //debug!("block task id:{}",pid);
    TASK_MANAGER.exclusive_access().remove_block_by_pid(pid);
    //debug!("wake up task {} ok",pid);
}

/// Remove a task from the ready queue
pub fn remove_task(task: Arc<ProcessControlBlock>) {
    //trace!("kernel: TaskManager::remove_task");
    TASK_MANAGER.exclusive_access().remove(task);
}

/// Set a task to stop-wait status, waiting for its kernel stack out of use.
pub fn add_stopping_task(task: Arc<ProcessControlBlock>) {
    TASK_MANAGER.exclusive_access().add_stop(task);
}

pub fn wakeup_parent(pid: usize) {
    TASK_MANAGER.exclusive_access().wakeup_parent(pid);
}



/// Get process by pid
pub fn tid2task(tid: usize) -> Option<Arc<ProcessControlBlock>> {
    info!("(tid2task) tid: {}", tid);
    match TID_TO_TASK.exclusive_access().get(&tid) {
        Some(process) => Some(process.clone()),
        None => {
            warn!("(tid2task) tid: {} not found", tid);
            None
        }
    }
}

/// Insert item(tid, pcb) into TID_TO_TASK map (called by do_fork AND ProcessControlBlock::new)
pub fn insert_into_tid2task(tid: usize, process: &Arc<ProcessControlBlock>) {
    info!("(insert_into_tid2task) tid: {}", tid);
    TID_TO_TASK.exclusive_access().insert(tid, process.clone());
}

/// Remove item(tid, _some_pcb) from PDI2PCB map (called by exit_current_and_run_next)
pub fn remove_from_tid2task(tid: usize) {
    info!("(remove_from_tid2task) tid: {}", tid);
    TID_TO_TASK.exclusive_access().remove(&tid);
}
/// Take a process out of the ready queue
pub fn fetch_task() -> Option<Arc<ProcessControlBlock>> {
    //debug!("kernel: TaskManager::fetch_task");
    TASK_MANAGER.exclusive_access().fetch()
}

// process num
pub fn process_num() -> usize {
    TID_TO_TASK.exclusive_access().len()
}



lazy_static! {
    /// 线程组实现
    pub static ref THREAD_GROUP: UPSafeCell<BTreeMap<usize, Vec<Arc<ProcessControlBlock>>>> =
        unsafe { UPSafeCell::new(BTreeMap::new()) };
    /// 进程组实现
    pub static ref PROCESS_GROUP: UPSafeCell<BTreeMap<usize, Vec<Arc<ProcessControlBlock>>>> =
        unsafe { UPSafeCell::new(BTreeMap::new()) };

}

pub fn insert_into_thread_group(pid: usize, process: &Arc<ProcessControlBlock>) {
    THREAD_GROUP
        .exclusive_access()
        .entry(pid)
        .or_insert_with(Vec::new)
        .push(process.clone());
}
/// 删除整个线程组,同时将线程从tid2task移除
pub fn remove_all_from_thread_group(pid: usize) {
    THREAD_GROUP.exclusive_access().remove(&pid);
}


pub fn insert_into_process_group(ppid: usize, process: &Arc<ProcessControlBlock>) {
    PROCESS_GROUP
        .exclusive_access()
        .entry(ppid)
        .or_insert_with(Vec::new)
        .push(Arc::clone(process));
}

pub fn remove_from_process_group(ppid: usize, pid: usize) {
    if let Some(processes) = PROCESS_GROUP.exclusive_access().get_mut(&ppid) {
        processes.retain(|p| p.getpid() != pid);
        if processes.is_empty() {
            PROCESS_GROUP.exclusive_access().remove(&ppid);
        }
    }
}

pub fn move_child_process_to_init(ppid: usize) {
    let mut inner = PROCESS_GROUP.exclusive_access();
    if let Some(processes) = inner.remove(&ppid) {
        let init_childer = inner.get_mut(&INITPROC.getpid()).unwrap();
        for child in processes {
            init_childer.push(child);
        }
    }
}
