# SubsToKernel

![USTB](./docs/img/USTB.jpg)

`Substium` 是两位参赛队员在参与 [2025春秋季开源操作系统训练营](https://opencamp.cn/os2edu/camp/2025spring) 专业阶段OS设计实现后基于 rCore-Tutorial-v3 的 ch8 分支实现的操作系统内核。
 
## 参赛文档

系统介绍文档在 [docs](./docs/) 文件夹。初赛参赛文档为[此文档](./docs/prel/初赛文档.md)，决赛文档为[此文档](./docs/final/决赛文档.md)。

[GitLab 仓库](https://gitlab.eduxiji.net/T202510008995695/oskernel2025-osrepo) 与 [GitHub 仓库](https://github.com/wdlin233/osrepo) 保持同步。

## 参赛信息

- 参赛队名：SubsToKernel
- 参赛学校：北京科技大学
- 队伍成员：
    - 吴函霖：[858459615@qq.com](mailto:858459615@qq.com)
    - 刘畅：[wdlin233@163.com](mailto:wdlin233@163.com)

## 使用说明

克隆项目后，在项目根目录下运行 `make run [LOG=<日志级别>] [ARCH=<目标架构>]` 即可启动 QEMU 运行内核，需要在根目录准备 `sdcard-rv.img` 和 `sdcard-la.img` 两个镜像文件，可以选择 `riscv64` 和 `loongarch64` 两个架构，例如：

```shell
make run LOG=DEBUG ARCH=riscv64
```

`make all` 可以在根目录下构建 `kernel-rv` 和 `kernel-la` 两个 ELF 文件。

初始进程的链接设置位于 `os/src/task/initproc_*.S` 中，通过将初始进程的 ELF 文件链接到内核镜像中，从而在系统启动后运行，可以修改 `.incbin` 来链接不同的应用程序作为初始进程。链接的文件必须要是 ELF 格式文件。