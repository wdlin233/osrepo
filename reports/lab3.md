# lab3

本章中实现了 `sys_spawn` 和 Stride 调度算法。

`sys_spawn` 的其实很简单，相比于 `sys_fork` 不直接复制父进程的地址空间，而是基于 ELF 直接新建一个 `TaskControlBlock`，创建之后只要设立 父子进程的关系 即可。

Stride 调度是一种优先级算法，具体的调用接口就是 `Processor` 上的 `run_task` 方法中的 `fetch_task`，修改 `fetch_task` 为我们自己设计的 Stride 调度算法。