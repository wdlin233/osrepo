# lab1

完成的工作：

实现了 `syscall_trace`. 对 syscall 的次数统计是通过调用 `update_syscall_times` 和 `get_syscall_times` 实现的.

在 `TaskManagerInner` 中添加了 `syscall_count: [SyscallTrace; MAX_APP_NUM]`.