# SubsToKernel

![badge](https://img.shields.io/badge/SubsTo-Kernel-blue)

# Problems

- [x] 就现在的需要做的工作来说，是 page_table, memory_set 和 address 适配 rv 和 la 的兼容.
- [x] LA 的 `task""id` 中 `alloc_user_res()` 不同于 RV，涉及的是 `syscall_brk`，希望我写的没错.
- [x] 为了修改 mm 也要修改 LA 的 trap 和 task 等.
- [x] 适配 LA 的 trap 和 task.
- [ ] loader 的 LA 适配
- [ ] FileSystem，如果不对磁盘进行初始化就会导致错误，所以磁盘初始化是无法避免的问题.
- [x] LA 的 kernel 出现 ELF 字段错误. 因为先前修改的文件系统是将一个目录内的所有elf文件载入，所以导致文件系统载入了不该载入的 rust 源文件. 从暴力解决的角度来说，显然条件编译，或者对 elf 进行过滤也可行. 但目前暂且保留 easy-fs-fuse-la.

```
[23, 21, 5b, 6e, 6f, 5f, 73, 74]
Aborting: line 68, file src/mm/memory_set.rs: called `Result::unwrap()` on an `Err` value: "Did not find ELF magic number"

[DEBUG] elf: [7f, 45, 4c, 46, 2, 1, 1, 0]
```

- [x] `block_cache.rs` 的 `BlockCach::new()` 中的 -> `block_device.read_block(block_id, &mut cache);` 一句无法执行，报错如下. 经过排查应该是对 `FRAME_ALLOCATOR` 的再次引用. 这对吗？不是，怎么可能是这个啊

```
[kernel] Panicked at src/sync/up.rs:34 already borrowed: BorrowMutError
```

- [x] 尝试对 `virtio_blk.rs` 进行修改. 实际上就是实现 `virtio-pci`. `virtio-blk` 参考了 `rcore-hal-component/887b4c`，`virtio-pci` 参考了 `Byte-OS/polyhal/examples/src/pci.rs`.
- [ ] 使用 `-kernel $(ELF_KERNEL)` 就会遇到 `PageLoadFault` 的问题，rv 和 la 的问题可能是一致的. 在这一点上我很困惑是什么所导致的，是之前修改的文件系统部分吗？可以确定的是，la 的 `PageLoadFault` 和 `task` module 应该是没有任何关系的. 但是话说回来为甚么 `arch` branch 的 MMIO 修改之后就不能用了呢，所以遇到 `LoadPageFault` 应该是 MMIO 的问题. 但是问题不知在哪. 
    - [x] rv
    - [ ] la

解答：修改 `const VIRTIO0: usize = 0x10001000 | 0x80200000;` 后 报错 `[kernel] Panicked at src/trap/mod.rs:330 a trap Exception(LoadPageFault) from kernel!`. 很明显 `LoadPageFault` 都是 MMIO 地址不对所导致的问题. 经过修改后可以得出在 rv 下的 `PageLoadFault` 是没有对内核地址空间进行映射所导致的问题.

```rust
KERNEL_SPACE
    .exclusive_access()
    .page_table
    .translate_va(VirtAddr::from(buffer.as_ptr() as *const usize as usize))
    .unwrap()
    .0
```

至于 `dma_alloc()` 的先前方法是循环分配单页，而 `alloc_contiguous` 只是对指针进行移动而没有使用 `frame_alloc()` 进行真正的分配.

# Optimization

- [ ] 修改 `extern "C" {fn stext(); ...}`，现在 RV 的部分在 `memory_set.rs` 而 LA 的部分在 `info.rs`.
- [ ] 将差异部分单独用一个模块进行处理，而往上层提供统一的抽象.