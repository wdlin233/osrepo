use alloc::collections::btree_map::BTreeMap;
use lazy_static::*;
use crate::task::current_process;
use crate::log::*;

use super::UPSafeCell;

type ResourceIdentifier = usize;
type NumberOfResources = usize;
type TaskIdentifier = usize;

#[derive(Debug, Default)]
/// Banker algorithm data structure for single process
pub struct BankerAlgorithm {
    /// Available map, (Resource) = available number
    available: BTreeMap<ResourceIdentifier, NumberOfResources>,
    /// (Task, Resource) = Resource {allocation, need}
    task_state: BTreeMap<TaskIdentifier, BTreeMap<ResourceIdentifier, TaskResourceState>>,
}

#[derive(Debug, Default)]
pub struct TaskResourceState {
    // max: NumberOfResources,
    allocation: NumberOfResources,
    need: NumberOfResources,
}

lazy_static! {
    /// The banker algorithm instance
    pub static ref BANKER_ALGO: UPSafeCell<BTreeMap<TaskIdentifier, BankerAlgorithm>> = unsafe {UPSafeCell::new(BTreeMap::new())};
}

/// Request result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestResult {
    /// Request success
    Success,
    /// Request failed
    Error,
    /// Request null
    Null,
}

impl BankerAlgorithm {
    /// Add a resource to the available map
    pub fn init_available_resource(&mut self, resource: ResourceIdentifier, number: NumberOfResources) {
        *self.available.entry(resource).or_default() += number;
        //trace!("kernel: banker_algo init_available_resource: resource[{}] number[{}]", resource, number);
    }

    fn init_task_resource(&mut self, tid: TaskIdentifier, resource: ResourceIdentifier, need: NumberOfResources) {
        self.task_state.entry(tid).or_default()
            .entry(resource).or_default()
            .need += need;
    }

    /// Allocate resources to a task
    pub fn alloc(&mut self, tid: TaskIdentifier, request: NumberOfResources, resource: ResourceIdentifier) {
        //trace!("kernel: banker_algo alloc: tid[{}] resource[{}] request[{}]", tid, resource, request);
        let available = self.available.get_mut(&resource).unwrap();
        let task = self.task_state
            .get_mut(&tid)
            .unwrap()
            .get_mut(&resource)
            .unwrap();
        //trace!("kernel: banker_algo alloc: available[{}] allocation[{}] need[{}] with resource[{}]", available, task.allocation, task.need, resource);
        assert!(request <= *available, "kernel: banker_algo alloc: request[{}] > available[{}]", request, available);
        *available -= request;
        task.allocation += request;
        task.need -= request;
        //trace!("kernel: banker_algo alloc: available[{}] allocation[{}] need[{}] with resource[{}]", available, task.allocation, task.need, resource);
    }

    /// Deallocate resources from a task
    pub fn dealloc(&mut self, tid: TaskIdentifier, request: NumberOfResources, resource: ResourceIdentifier) {
        //trace!("kernel: banker_algo dealloc: tid[{}] resource[{}] request[{}]", tid, resource, request);
        let available = self.available.get_mut(&resource).unwrap();
        let task = self.task_state
            .get_mut(&tid)
            .unwrap()
            .get_mut(&resource)
            .unwrap();
        *available += request;
        task.allocation -= request;
        //trace!("kernel: banker_algo dealloc: available[{}] allocation[{}] need[{}] with resource[{}]", available, task.allocation, task.need, resource);
    }

    /// Try to request resources to detect if the system is in a safe state
    pub fn request(&mut self, tid: TaskIdentifier, resource: ResourceIdentifier, need: NumberOfResources) -> RequestResult {
        self.init_task_resource(tid, resource, need);
        if self.security_check() {
           return RequestResult::Success;
        }
        trace!("kernel: banker_algo request: security_check failed");
        return RequestResult::Error;
    }

    fn security_check(&self) -> bool {
        // 1. 设置两个向量:
        //   工作向量Work，表示操作系统可提供给线程继续运行所需的各类资源数目，它含有m个元素，初始时，Work = Available
        let mut work = self.available.clone();

        //   结束向量Finish，表示系统是否有足够的资源分配给线程，使之运行完成。初始时 Finish[0..n-1] = false，表示所有线程都没结束
        //   当有足够资源分配给线程时，设置Finish[i] = true。
        // TODO(fh): change to BTreeSet
        let mut finish = self
            .task_state
            .keys()
            .map(|&task| (task, false))
            .collect::<BTreeMap<_, _>>();

        loop {
            // 2. 从线程集合中找到一个能满足下述条件的线程
            // Finish[i] == false; Need[i,j] <= Work[j];
            if let Some((task, res_state)) = self.task_state.iter()
                .find(|(task, res_state)| {
                    !finish[task] && 
                    res_state.iter()
                    .all(|(res, state)| state.need <= work[res])
            }) {
                // 若找到，执行步骤3，否则，执行步骤4。
                // 3. 当线程thr[i]获得资源后，可顺利执行，直至完成，并释放出分配给它的资源，故应执行:
                // Work[j] = Work[j] + Allocation[i,j];
                for (res, state) in res_state {
                    *work.get_mut(res).unwrap() += state.allocation;
                }

                // Finish[i] = true;
                *finish.get_mut(task).unwrap() = true;

                // 跳转回步骤2
                continue;
            } else {
                // 4. 如果Finish[0..=n-1] 都为true，则表示系统处于安全状态；否则表示系统处于不安全状态。
                if finish.values().all(|&ok| ok) {
                    return true;
                } else {
                    return false;
                }
            }
        }
    }

}

/// Initialize available resources
pub fn init_available_resource(resource: ResourceIdentifier, number: NumberOfResources) {
    let pid = current_process().getpid();
    if let Some(banker_algo) = BANKER_ALGO.exclusive_access().get_mut(&pid) {
        banker_algo.init_available_resource(resource, number);
    }
}

/// Allocate resources to a task
pub fn alloc(tid: TaskIdentifier, resource: ResourceIdentifier, request: NumberOfResources) {
    let pid = current_process().getpid();
    if let Some(banker_algo) = BANKER_ALGO.exclusive_access().get_mut(&pid) {
        banker_algo.alloc(tid, request, resource);
    }
}

/// Deallocate resources from a task
pub fn dealloc(tid: TaskIdentifier, resource: ResourceIdentifier, request: NumberOfResources) {
    let pid = current_process().getpid();
    if let Some(banker_algo) = BANKER_ALGO.exclusive_access().get_mut(&pid) {
        banker_algo.dealloc(tid, request, resource);
    }
}

/// Try to request resources to detect if the system is in a safe state
pub fn request(tid: TaskIdentifier, resource: ResourceIdentifier, need: NumberOfResources) -> RequestResult {
    let pid = current_process().getpid();
    if let Some(banker_algo) = BANKER_ALGO.exclusive_access().get_mut(&pid) {
        let res = banker_algo.request(tid, resource, need);
        trace!("kernel: banker_algo request: pid[{}] tid[{}] resource[{}] need[{}] result[{:?}]", pid, tid, resource, need, res);
        res
    } else {
        RequestResult::Null
    }
}

/// Enable banker algorithm for the current process
pub fn enable_banker_algo() {
    let pid = current_process().getpid();
    BANKER_ALGO.exclusive_access().insert(pid, BankerAlgorithm::default());
}

/// Disable banker algorithm for the current process
pub fn disable_banker_algo() {
    let pid = current_process().getpid();
    BANKER_ALGO.exclusive_access().remove(&pid);
}