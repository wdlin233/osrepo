//! Implementation of [`TaskManager`]
//!
//! It is only used to manage processes and schedule process based on ready queue.
//! Other CPU process monitoring functions are in Processor.

use super::{ProcessControlBlock, TaskControlBlock, TaskStatus};
use crate::sync::UPSafeCell;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use lazy_static::*;
///A array of `TaskControlBlock` that is thread-safe
pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
    ///block map : <pid,>
    block_map: BTreeMap<usize,Arc<TaskControlBlock>>,
    /// The stopping task, leave a reference so that the kernel stack will not be recycled when switching tasks
    stop_task: Option<Arc<TaskControlBlock>>,
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
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        //debug!("in taskmanager add");
        self.ready_queue.push_back(task);
        //debug!("task manager add ok");
    }
    /// Add a task to stopping task
    pub fn add_stop(&mut self, task: Arc<TaskControlBlock>) {
        // NOTE: as the last stopping task has completely stopped (not
        // using kernel stack any more, at least in the single-core
        // case) so that we can simply replace it;
        self.stop_task = Some(task);
    }
    /// Add a task to block task
    pub fn add_block(&mut self,task: Arc<TaskControlBlock>) {
        //The blocking queue
        // which temporarily holds tasks waiting for timer expiration.
        let process = task.process.upgrade().unwrap();
        self.block_map.insert(process.getpid(),task);
    }

    /// Take a process out of the ready queue
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        //debug!("ready queue size:{}",self.ready_queue.len());
        self.ready_queue.pop_front()
    }
    pub fn remove(&mut self, task: Arc<TaskControlBlock>) {
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
    pub fn remove_block(&mut self,task: &Arc<TaskControlBlock>){
        let process = task.process.upgrade().unwrap();
        let pid = process.getpid();
        //debug!("remove block :{}",pid);
        self.block_map.remove(&pid);
    }
    /// remove block by pid
    pub fn remove_block_by_pid(&mut self,pid: usize){
        //debug!("remove block by pid:{}",pid);
        if let Some(task) = self.block_map.remove(&pid){
            let mut inner = task.inner_exclusive_access();
            if inner.task_status != TaskStatus::Ready{
                inner.task_status = TaskStatus::Ready;
                drop(inner);
                self.add(task);
                debug!("add task ok : {}",pid);
            }
        }
    }
  

}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
    /// PID2PCB instance (map of pid to pcb)
    pub static ref PID2PCB: UPSafeCell<BTreeMap<usize, Arc<ProcessControlBlock>>> =
        unsafe { UPSafeCell::new(BTreeMap::new()) };
}

/// Add a task to ready queue
pub fn add_task(task: Arc<TaskControlBlock>) {
    //debug!("kernel: TaskManager::add_task");
    TASK_MANAGER.exclusive_access().add(task);
}
/// Add a task to block queue
pub fn add_block_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.exclusive_access().add_block(task);
}

/// Wake up a task
pub fn wakeup_task(task: Arc<TaskControlBlock>) {
    //trace!("kernel: TaskManager::wakeup_task");
    let mut task_inner = task.inner_exclusive_access();
    task_inner.task_status = TaskStatus::Ready;
    drop(task_inner);
    TASK_MANAGER.exclusive_access().remove_block(&task);
    add_task(task);
}
/// wake up a task by pid
pub fn wakeup_task_by_pid(pid: usize){
    //debug!("block task id:{}",pid);
    TASK_MANAGER.exclusive_access().remove_block_by_pid(pid);
    //debug!("wake up task {} ok",pid);
}

/// Remove a task from the ready queue
pub fn remove_task(task: Arc<TaskControlBlock>) {
    //trace!("kernel: TaskManager::remove_task");
    TASK_MANAGER.exclusive_access().remove(task);
}

/// Set a task to stop-wait status, waiting for its kernel stack out of use.
pub fn add_stopping_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.exclusive_access().add_stop(task);
}

/// Get process by pid
pub fn pid2process(pid: usize) -> Option<Arc<ProcessControlBlock>> {
    let map = PID2PCB.exclusive_access();
    map.get(&pid).map(Arc::clone)
}

/// Insert item(pid, pcb) into PID2PCB map (called by do_fork AND ProcessControlBlock::new)
pub fn insert_into_pid2process(pid: usize, process: Arc<ProcessControlBlock>) {
    PID2PCB.exclusive_access().insert(pid, process);
}

/// Remove item(pid, _some_pcb) from PDI2PCB map (called by exit_current_and_run_next)
pub fn remove_from_pid2process(pid: usize) {
    let mut map = PID2PCB.exclusive_access();
    if map.remove(&pid).is_none() {
        panic!("cannot find pid {} in pid2task!", pid);
    }
}
/// Take a process out of the ready queue
pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    //debug!("kernel: TaskManager::fetch_task");
    TASK_MANAGER.exclusive_access().fetch()
}

