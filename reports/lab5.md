# lab5

实际上认为自己完成得并不算太好。

`BANKER_ALGO` 作为银行家算法的全局实例，映射一组 KV 键值对来从一个 `pid` 映射到一个进程下的银行家算法。`BankerAlgorithm` 下的 `available` 是对整个进程的，而 `task_state` 则是对某个线程的资源管理。

```rust
pub struct BankerAlgorithm {
    /// Available map, (Resource) = available number
    available: BTreeMap<ResourceIdentifier, NumberOfResources>,
    /// (Task, Resource) = Resource {allocation, need}
    task_state: BTreeMap<TaskIdentifier, BTreeMap<ResourceIdentifier, TaskResourceState>>,
}
```

`sys_semaphore_down` 中的 `sem.down()` 必须在 `alloc(tid, sem_id, 1)` 之前，可能是因为 `sem.down()` 会将进程挂起。若 `alloc` 在此之前，可能导致资源并未被实际获取，由此其他进程因为错误的状态而无法获取资源。这个顺序保持着资源分配记录与实际获取资源状态相一致。