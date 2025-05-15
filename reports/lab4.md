# lab4

为了实现 `sys_fstat` 我在 `DiskInode` 中增加 `links_count` 用于指示有多少个 `DirEntry` 指向此磁盘位置上的数据，在 `Inode` 中添加 `inode_id` 用于明显注出当前文件索引的 inode 号。这个系统调用就是把各种信息状态收集起来，比较简单。

`sys_link_at` 比起 `unlink_at` 实现起来简单一点。就是将当前的 `new_name` 和 `old_inode_id` 组成一个新的 `DirEntry`.

`unlink_at` 要

(1) 对当前 `path` 指向的 `DiskInode` 块对应的 `links_count` 进行自减，

(2) 然后 `swap_remove_dirent` 当前的 `DirEntry` 以删除 `path` 对应的目录项。

(3) 最后检查是否 `links_count == 0` 以决定是否回收 `DiskInode`.
