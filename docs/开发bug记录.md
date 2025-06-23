# SubsToKernel

![badge](https://img.shields.io/badge/SubsTo-Kernel-blue)

# Problems

- [x] 就现在的需要做的工作来说，是 page_table, memory_set 和 address 适配 rv 和 la 的兼容.
- [x] LA 的 `task""id` 中 `alloc_user_res()` 不同于 RV，涉及的是 `syscall_brk`，希望我写的没错.
- [x] 为了修改 mm 也要修改 LA 的 trap 和 task 等.
- [x] 适配 LA 的 trap 和 task.
- [x] FileSystem，如果不对磁盘进行初始化就会导致错误，所以磁盘初始化是无法避免的问题.
- [x] LA 的 kernel 出现 ELF 字段错误. 因为先前修改的文件系统是将一个目录内的所有elf文件载入，所以导致文件系统载入了不该载入的 rust 源文件. 从暴力解决的角度来说，显然条件编译，或者对 elf 进行过滤也可行. 但目前暂且保留 easy-fs-fuse-la.

```shell
[23, 21, 5b, 6e, 6f, 5f, 73, 74]
Aborting: line 68, file src/mm/memory_set.rs: called `Result::unwrap()` on an `Err` value: "Did not find ELF magic number"

[DEBUG] elf: [7f, 45, 4c, 46, 2, 1, 1, 0]
```

- [x] `block_cache.rs` 的 `BlockCach::new()` 中的 -> `block_device.read_block(block_id, &mut cache);` 一句无法执行，报错如下. 经过排查应该是对 `FRAME_ALLOCATOR` 的再次引用. 这对吗？不是，怎么可能是这个啊

```shell
[kernel] Panicked at src/sync/up.rs:34 already borrowed: BorrowMutError
```

- [x] 尝试对 `virtio_blk.rs` 进行修改. 实际上就是实现 `virtio-pci`. `virtio-blk` 参考了 `rcore-hal-component/887b4c`，`virtio-pci` 参考了 `Byte-OS/polyhal/examples/src/pci.rs`.
- [x] 使用 `-kernel $(ELF_KERNEL)` 就会遇到 `PageLoadFault` 的问题，rv 和 la 的问题可能是一致的. 在这一点上我很困惑是什么所导致的，是之前修改的文件系统部分吗？可以确定的是，la 的 `PageLoadFault` 和 `task` module 应该是没有任何关系的. 但是话说回来为甚么 `arch` branch 的 MMIO 修改之后就不能用了呢，所以遇到 `LoadPageFault` 应该是 MMIO 的问题. 但是问题不知在哪. 
    - [x] rv
    - [x] la

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

`pci` 没有专门一个 `VirtIOHeader` 这让 `pci` 的处理麻烦了很多需要手动处理分配的问题，参考 ByteOS 的 `driver/kvirtio/src/lib.rs` 设计了扫描总线 0 上所有 PCI 块设备的逻辑，然后配置 BARs，这里因为我们没人写过设备驱动所以修改了很久.

- [x] 现在 rv 和 la 都能正常启动了，在 la 里可以读取 `APPS_LIST`，但是会遇到虚地址被映射的问题.

```shell
[DEBUG] Reading all data from inode with id: 25
[DEBUG] start_va: VA:0x10000000, end_va: VA:0x10003534, map_perm: PLVL | PLVH
[DEBUG] map_area: MapArea { vpn_range: SimpleRange { l: VPN:0x4000, r: VPN:0x4001 }, data_frames: {}, map_perm: PLVL | PLVH }
[DEBUG] start_va: VA:0x10004000, end_va: VA:0x10008000, map_perm: NX | PLVL | PLVH
[DEBUG] map_area: MapArea { vpn_range: SimpleRange { l: VPN:0x4001, r: VPN:0x4002 }, data_frames: {}, map_perm: NX | PLVL | PLVH }
[DEBUG] start_va: VA:0x10008000, end_va: VA:0x1000c128, map_perm: NX | W | PLVL | PLVH
[DEBUG] map_area: MapArea { vpn_range: SimpleRange { l: VPN:0x4002, r: VPN:0x4004 }, data_frames: {}, map_perm: NX | W | PLVL | PLVH }
[kernel] Panicked at src/mm/page_table.rs:296 vpn VPN:0x4005 is mapped before mapping
```

因为堆分配的时候地址空间造成了堆叠：

```rust
self.heap_bottom = ustack_top;
self.program_brk = ustack_top;
process_inner.memory_set.insert_framed_area(
    ustack_bottom.into(),
    ustack_top.into(),
    MapPermission::default() | MapPermission::W,
);
process_inner.memory_set.insert_framed_area(
    self.heap_bottom.into(),
    self.program_brk.into(),
    MapPermission::default() | MapPermission::W,
);
```

这两个部分被分到同一页了，增加一个页面对齐就可以保证分配在不同的虚地址了.

- [x] 实现 la 的分时功能.
- [x] 解决地址对齐问题

```shell
[DEBUG] Converting usize to VirtAddr: 10004086
[initproc] Forked child process, executing user_shell
[DEBUG] Converting usize to VirtAddr: 100040a0
[DEBUG] Converting usize to VirtAddr: 100040a1
[DEBUG] Converting usize to VirtAddr: 100040a2
[DEBUG] Converting usize to VirtAddr: 100040a3
[DEBUG] Converting usize to VirtAddr: 100040a4
[DEBUG] Converting usize to VirtAddr: 100040a5
[DEBUG] Converting usize to VirtAddr: 100040a6
[DEBUG] Converting usize to VirtAddr: 100040a7
[DEBUG] Converting usize to VirtAddr: 100040a8
[DEBUG] Converting usize to VirtAddr: 10004098
[DEBUG] Converting usize to VirtAddr: 10014000
[INFO] Converting VirtAddr to VirtPageNum: VA:0x10014000 with offset: 0
[DEBUG] Converting usize to VirtAddr: 10016000
[INFO] Converting VirtAddr to VirtPageNum: VA:0x10016000 with offset: 8192
[kernel] Panicked at src/mm/address.rs:182 assertion `left == right` failed
  left: 8192
 right: 0
```

修改用户栈大小后转变为zombie process. 疑似 `usertests_simple` 中的 `waitpid` 有问题. 并不是. 是因为之前在完成 basic 测例时修改了 `block_current_and_run_next` 的逻辑，将 `add_block_task(task);` 保留就可以正常运行了.

## 2025.6.12

队友实现了 ext4 的文件系统，开始适配对 la 的支持了. 前几天尝试了一下使用更新版本的 `ext4_rs` 对文件系统进行适配，发现难度有一点大，要花费很多时间，于是先这么使用了.

在 la 上遇到的第一个问题，就是会出现地址段的重复映射，经过排查发现是因为 `PAGE_SIZE` 的大小在 rv 和 la 上并不一样，之前也遇到过类似的问题.

```shell
[DEBUG] elf program header count: 5
[DEBUG] start_va: VA:0x0, end_va: VA:0x2da0, map_perm: PLVL | PLVH
[ INFO] MapArea::new: 0x0 - 0x2da0
[ INFO] MapArea::new start floor = 0, end ceil = 1
[DEBUG] map_area: MapArea { vpn_range: SimpleRange { l: VPN:0x0, r: VPN:0x1 }, data_frames: {}, map_perm: PLVL | PLVH }
[ INFO] map vpn VPN:0x0 to ppn PPN:0x81c with flags PLVL | PLVH
[DEBUG] start_va: VA:0x3000, end_va: VA:0x3f30, map_perm: NX | PLVL | PLVH
[ INFO] MapArea::new: 0x3000 - 0x3f30
[ INFO] MapArea::new start floor = 0, end ceil = 1
[DEBUG] map_area: MapArea { vpn_range: SimpleRange { l: VPN:0x0, r: VPN:0x1 }, data_frames: {}, map_perm: NX | PLVL | PLVH }
[ INFO] map vpn VPN:0x0 to ppn PPN:0x81f with flags PLVL | PLVH | NX
[kernel] Panicked at src/mm/page_table.rs:271 vpn VPN:0x0 is mapped before mapping
```

发现是加载成 rv 的镜像了，幽默. 不过更换之后还是遇到了不能打开文件的问题 `[kernel] Panicked at src/task/mod.rs:201 called `Option::unwrap()` on a `None` value`.

用 `ls` 指令查看后发现现在只能打开 `.elf` 尾缀的程序.

考虑更直接的使用 `ext4_rs` 的接口，可以打开文件，但是执行过程中会出现 

```shell
[ERROR] [kernel] trap_handler: Exception(LoadPageFault) in application, bad addr = 0x6000, bad instruction = 0x10a0, kernel killed it.
``` 

的错误 


## 2025.6.13

考虑分别对文件系统进行实现，在此我使用了 `lwext4_rust` 库，并参考了去年队伍的实现。第一步是更改 `VIRTIO0` 的值，然后就可以顺利读取磁盘了. 解决了

```shell
[kernel] Panicked at src/hal/trap/mod.rs:344 a trap Exception(StorePageFault) from kernel!
```

的问题. 调好之后就可以读取文件并执行程序了，但是又遇到了

```shell
[ERROR] [kernel] trap_handler: Exception(LoadPageFault) in application, bad addr = 0x6000, bad instruction = 0x10be, kernel killed it.
```

这应该是内核的问题，在先前的 `ext4_rs` 中也遇到了. 在 `run_tasks()` 执行了一段时间都没什么问题，会是 `__switch(idle_task_cx_ptr, next_task_cx_ptr);` 的问题吗？

猜测是用户栈的问题

```shell
[ INFO] user stack base: 0x3000
[DEBUG] in drop for gid
[DEBUG] kernel: add main thread to scheduler, pid = 0
[ INFO] get_idle_task_cx_ptr: idle task cx ptr: 0x8026f080
[DEBUG] run_tasks: pid: 0, tid: 0
[ INFO] get_idle_task_cx_ptr: idle task cx ptr: 0x8026f080
[DEBUG] in schedule, to switch
[ INFO] get_idle_task_cx_ptr: idle task cx ptr: 0x8026f080
[DEBUG] run_tasks: pid: 0, tid: 0
[ERROR] [kernel] trap_handler: Exception(LoadPageFault) in application, bad addr = 0x6000, bad instruction = 0x10be, kernel killed it.
[kernel] Idle process exit with exit_code -11 ...
```

会在 `user_stack_base` 往上的 `3 * PAGE_SIZE` 的地址段进行访问. 经过在 `ProcessControlBlock::new()` 中各地址段的调试，应该是 `sp` 值的设置有误，在 `set_sp` 中进行更改 `self.x[2] = sp - 8`，因为栈指针要设置在栈顶下方.

然后就开始迁移 `sys_open`，涉及到的 `fd_table` 的结构很不一样.

## 2025.6.20

考完期末周，回来实现了 `sys_open()`，然后开始做 EXT4 对 la 的适配，修改 `VIRTIO0` 后遇到的 

```shell
[kernel] Panicked at src/drivers/virtio/blk.rs:16 VirtIOBlk create failed: InvalidParam
```

问题，做 pci 与 mmio 的兼容.

## 2025.6.21

做好总线驱动，遇到

```rust
impl File for Stdout {
    fn write(&self, user_buf: UserBuffer) -> SyscallRet {
        info!("kernel: write to stdout");
        info!("kernel: write to stdout buffer len: {:?}", user_buf.buffers.len());
        for buffer in user_buf.buffers.iter() {
            info!("kernel: write to stdout buffer: {:?}", *buffer);
            print!("{}", core::str::from_utf8(*buffer).unwrap());
        }
        info!("kernel: write to stdout done");
        Ok(user_buf.len())
    }
}
```

中不能访问 `*buffer` 的问题，具体表现在会出现 `LoadPageFault` 报错和 `[ INFO] kernel: write to stdout buffer: [` 日志.

反汇编

```asm
90000000002641ec:	00150007 	move        	$a3, $zero
90000000002641f0:	00150009 	move        	$a5, $zero
90000000002641f4:	50002000 	b           	32(0x20)	# 9000000000264214 <_ZN40_$LT$str$u20$as$u20$core..fmt..Debug$GT$3fmt17h91ad8e2e5f5954c0E+0x374>
90000000002641f8:	00150009 	move        	$a5, $zero
90000000002641fc:	47ffdcff 	bnez        	$a3, -36(0x7fffdc)	# 90000000002641d8 <_ZN40_$LT$str$u20$as$u20$core..fmt..Debug$GT$3fmt17h91ad8e2e5f5954c0E+0x338>
9000000000264200:	00150007 	move        	$a3, $zero
9000000000264204:	50001000 	b           	16(0x10)	# 9000000000264214 <_ZN40_$LT$str$u20$as$u20$core..fmt..Debug$GT$3fmt17h91ad8e2e5f5954c0E+0x374>
9000000000264208:	5bffcd25 	beq         	$a5, $a1, -52(0x3ffcc)	# 90000000002641d4 <_ZN40_$LT$str$u20$as$u20$core..fmt..Debug$GT$3fmt17h91ad8e2e5f5954c0E+0x334>
900000000026420c:	50007800 	b           	120(0x78)	# 9000000000264284 <_ZN40_$LT$str$u20$as$u20$core..fmt..Debug$GT$3fmt17h91ad8e2e5f5954c0E+0x3e4>
9000000000264210:	5c0074e5 	bne         	$a3, $a1, 116(0x74)	# 9000000000264284 <_ZN40_$LT$str$u20$as$u20$core..fmt..Debug$GT$3fmt17h91ad8e2e5f5954c0E+0x3e4>
9000000000264214:	28c06328 	ld.d        	$a4, $s2, 24(0x18)
9000000000264218:	0011a4e6 	sub.d       	$a2, $a3, $a5
```

在 `9000000000264218:	0011a4e6 	sub.d       	$a2, $a3, $a5` 出错. 

涉及的是关于物理内存到内核虚拟地址的映射问题，于是重新设计了一个 `safe_translated_byte_buffer` 让其传给 `File::write` 的是被处理过后的内核虚地址.

## 2025.6.23

在实现 `sys_mmap` 时遇到了地址不能被访问的问题

```shell
[DEBUG] in memory set, mmap
[ERROR] find_insert_addr: hint = 0x2ffdcd7000, size = 4096
[ERROR] find_insert_addr: start_vpn = 0x2ffdcd6, end_vpn = 0x2ffdcd7, start_va = 0x2ffdcd6000
[DEBUG] [sys_mmap] start_va:0x2ffdcd6000,end_va:0x2ffdcd7000
[DEBUG] [sys_mmap] alloc addr=0x2ffdcd6000
[DEBUG] in sys write
[DEBUG] current pid is :1
[DEBUG] in write,to translated byte buffer
[DEBUG] Getting bytes array for PhysAddr: 0x822ff000
[ INFO] safe_translated_byte_buffer: start_va: VA:0x1f78, end_va: VA:0x1f86, ppn: PPN:0x822ff
[DEBUG] safe trsnslated byte buffer ok
[DEBUG] UserBuffer::new: buffers: [[109, 109, 97, 112, 32, 99, 111, 110, 116, 101, 110, 116, 58, 32]]
[ INFO] kernel: write to stdout
mmap content: [ INFO] kernel: write to stdout done
[DEBUG] in write, to return , ret is :14
[DEBUG] in sys write
[DEBUG] current pid is :1
[DEBUG] in write,to translated byte buffer
[DEBUG] safe trsnslated byte buffer ok
[DEBUG] UserBuffer::new: buffers: []
[ INFO] kernel: write to stdout
[ INFO] kernel: write to stdout done
[DEBUG] in write, to return , ret is :0
[ERROR] [kernel] trap_handler: Exception(LoadPageFault) in application, bad addr = 0x2ffdcd6000, bad instruction = 0x1970, kernel killed it.
```

具体而言是 `MMAP_TOP` 附近的地址不能被正确访问.

如果在 `find_insert_addr` 这个函数中修改映射的地址位置，

```shell
[ERROR] find_insert_addr: hint = 0x2ffdcd7000, size = 4096
[ERROR] find_insert_addr: start_vpn = 0x2ffdcd6, end_vpn = 0x2ffdcd7, start_va = 0x2ffdcd5000
[DEBUG] [sys_mmap] start_va:0x2ffdcd6000,end_va:0x2ffdcd7000
[DEBUG] [sys_mmap] alloc addr=0x2ffdcd6000
[DEBUG] in sys write
[DEBUG] current pid is :1
[DEBUG] in write,to translated byte buffer
[DEBUG] Getting bytes array for PhysAddr: 0x822ff000
[ INFO] safe_translated_byte_buffer: start_va: VA:0x1f78, end_va: VA:0x1f86, ppn: PPN:0x822ff
[DEBUG] safe trsnslated byte buffer ok
[DEBUG] UserBuffer::new: buffers: [[109, 109, 97, 112, 32, 99, 111, 110, 116, 101, 110, 116, 58, 32]]
[ INFO] kernel: write to stdout
mmap content: [ INFO] kernel: write to stdout done
[DEBUG] in write, to return , ret is :14
[DEBUG] in sys write
[DEBUG] current pid is :1
[DEBUG] in write,to translated byte buffer
[DEBUG] safe trsnslated byte buffer ok
[DEBUG] UserBuffer::new: buffers: []
[ INFO] kernel: write to stdout
[ INFO] kernel: write to stdout done
[DEBUG] in write, to return , ret is :0
[ERROR] [kernel] trap_handler: Exception(LoadPageFault) in application, bad addr = 0x2ffdcd6000, bad instruction = 0x1970, kernel killed it.
```

应该是在创建 `MapArea` 时的问题而不是在用户地址空间里插入映射信息的问题. 导致整个映射出现错误了. 我怀疑这整个段都不能访问，`mmap` 和 `munmap` 的区别就在于 `mmap` 对映射的地址进行了访问.

```shell
[DEBUG] [sys_mmap] start_va:0x2ffdcd6000,end_va:0x2ffdcd7000
[DEBUG] [sys_mmap] alloc addr=0x2ffdcd7000
[DEBUG] [sys_mmap] alloc addr=0x2ffdcd7000 as isize
[ERROR] [kernel] trap_handler: Exception(LoadPageFault) in application, bad addr = 0x2ffdcd7000, bad instruction = 0x1970, kernel killed it.
```

当我使用原本的方法

```rust
self.insert_framed_area(VirtAddr::from(addr), VirtAddr::from(addr + len), map_perm, area_type);
```

就不会出现 `LoadPageFault` 的报错，也可能是说，错误是因为没有建立对映的映射而导致的，并不是这个地址的问题，因为缓冲区又一次出现空的情况，所以也有可能是 `sys_write` 的问题，换句话说，对应的地址没有被映射是一回事，对应地址的数据又是一回事. 可能是因为这个地址没有对应的数据. 

是因为没有映射到文件的内容吗？这是有可能的.

```c
array = mmap(NULL, kst.st_size, PROT_WRITE | PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
if (array == MAP_FAILED) {
	printf("mmap error.\n");
} else {
	printf("mmap content: %s\n", array);
}
```

在 `trap_handler` 中对 `LoadPageFault` 做了处理，实现了 `cow`. 然后一个错误是在 `OSInode::write` 中的 `for slice in buf.buffers.iter()` 不能访问 `slice`. 或者说 `munmap` 中 `buf` 的地址有问题.

确实是 `buf` 在内核态访问了用户态的内容，一直尝试使用 `safe_translated_byte_buffer` 来解决问题，和引用问题斗争了很久. 经过指点发现完全可以使用 `translated_byte_buffer` 这个更基础的函数来解决，惭愧.

# Optimization

- [x] 修改 `extern "C" {fn stext(); ...}`，现在 RV 的部分在 `memory_set.rs` 而 LA 的部分在 `info.rs`.
- [x] 将差异部分单独用一个模块进行处理，而往上层提供统一的抽象.

注意在 LoongArch 中有 `pwcl::set_ptwidth(0xb); //16KiB的页大小` 对寄存器设置页大小等操作，配置页大小并不是 `config` 修改一个常量这么简单，为了保险起见这里就不对两个架构的基本参数进行改动了.

la 和 rv 的主要区别除了一些参数外，就在于 la 因为有窗口映射就没有设置内核地址空间，以及需要手动处理 TLB 的一些操作.

