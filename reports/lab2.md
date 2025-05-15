# lab2

主要的问题卡在没有检查用户可用的状态，导致一直报错 `[kernel] Panicked at src/mm/heap_allocator.rs:12 Heap allocation error, layout = Layout { size: 16777216, align: 8 (1 << 3) }` 又不知道怎么调。

实际上这意味着用户地址空间存在不合理的分配，也就意味着此时我们该检查 用户地址空间 相关的内容，或者可以说就是我们创建的 `buffer`.

至于 `mmap` 和 `munmap` 都是对地址空间中逻辑段的插入和删除操作，只要正确检查了地址的属性，比如是否对齐就可以。

`trace` 当然也要注意地址是否对齐的问题，不能直接使用 `addr.into()` 转换到 `PhysPageNum`，而是需要先 `VirtAddr::from()` 再取 `floor()`.