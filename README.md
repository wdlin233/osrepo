# SubsToKernel

![badge](https://img.shields.io/badge/SubsTo-Kernel-blue)

# Problems

现在的问题是当在用户链接脚本中选择删除.comment段就会出现程序找不到.text段的报错，而在内核的链接脚本中删除.comment段不能根本解决问题，其他段仍然会与其重叠，将其全部删除后.shstrtab始终会重叠，rust-lld不能被删除。也就是始终存在链接脚本地址段重叠的问题。

前四句是不必要的：

```asm
0x9000000000200940:  02ffc063   addi_d   	r3, r3, -16
0x9000000000200944:  29c02061   st_d     	r1, r3, 8
0x9000000000200948:  29c00076   st_d     	r22, r3, 0
0x900000000020094c:  02c04076   addi_d   	r22, r3, 16
0x9000000000200950:  0380040c   ori      	r12, r0, 1
0x9000000000200954:  0320018c   lu52i_d  	r12, r12, -2048
0x9000000000200958:  0406002c   csrwr    	r12, 384 # DMW(0)
0x900000000020095c:  0380440c   ori      	r12, r0, 17
0x9000000000200960:  0324018c   lu52i_d  	r12, r12, -1792
0x9000000000200964:  0406042c   csrwr    	r12, 385 # DMW(1)
0x9000000000200968:  0382c00c   ori      	r12, r0, 176
0x900000000020096c:  0400002c   csrwr    	r12, 0 # CRMD
```

要做的工作：

- [x]从此开始
```rust
// mm/mod.rs
#[cfg(target_arch = "riscv64")]
KERNEL_SPACE.exclusive_access().activate();
```

- []修改 `init_heap()`.