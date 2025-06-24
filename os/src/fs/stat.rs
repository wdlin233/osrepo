use crate::timer::TimeSpec;

bitflags! {
    pub struct StMode: u32 {
        const FIFO= 0x1000; //管道设备文件
        const FCHR = 0x2000; //字符设备文件
        const FDIR = 0x4000; //目录文件
        const FBLK = 0x6000; //块设备文件
        const FREG = 0x8000; //普通文件
        const FLINK = 0xA000; //符号链接文件
        const FSOCK = 0xC000; //套接字设备文件
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct Kstat {
    pub st_dev: usize,  // 包含文件的设备 ID
    pub st_ino: usize,  // 索引节点号
    pub st_mode: u32,   // 文件类型和模式
    pub st_nlink: u32,  // 硬链接数
    pub st_uid: u32,    // 所有者的用户 ID
    pub st_gid: u32,    // 所有者的组 ID
    pub st_rdev: usize, // 设备 ID（如果是特殊文件）
    pub __pad: usize,
    pub st_size: isize,  // 总大小，以字节为单位
    pub st_blksize: i32, // 文件系统 I/O 的块大小
    pub __pad2: u32,
    pub st_blocks: isize,     // 分配的 512B 块数
    pub st_atime: isize,      // 上次访问时间
    pub st_atime_nsec: usize, // 上次访问时间（纳秒精度）
    pub st_mtime: isize,      // 上次修改时间
    pub st_mtime_nsec: usize, // 上次修改时间（纳秒精度）
    pub st_ctime: isize,      // 上次状态变化的时间
    pub st_ctime_nsec: usize, // 上次状态变化的时间（纳秒精度）
    pub __unused: [u32; 2],
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct Statfs {
    pub f_type: i64,       // Type of filesystem
    pub f_bsize: i64,      // Optimal transfer block size
    pub f_blocks: i64,     // Total data blocks in filesystem
    pub f_bfree: i64,      // Free blocks in filesystem
    pub f_bavail: i64,     // Free blocks available to unprivileged user
    pub f_files: i64,      // Total inodes in filesystem
    pub f_ffree: i64,      // Free inodes in filesystem
    pub f_fsid: i64,       // Filesystem ID
    pub f_name_len: i64,   // Maximum length of filenames
    pub f_frsize: i64,     // Fragment size
    pub f_flags: i64,      // Mount flags of filesystem
    pub f_spare: [i64; 4], // Padding bytes
}

bitflags! {
    pub struct StatxMask: u32 {
        const STATX_TYPE = 0x00000001; // 文件类型
        const STATX_MODE = 0x00000002; // 文件模式
        const STATX_NLINK = 0x00000004; // 硬链接数
        const STATX_UID = 0x00000008; // 所有者的用户 ID
        const STATX_GID = 0x00000010; // 所有者的组 ID
        const STATX_ATIME = 0x00000020; // 上次访问时间
        const STATX_MTIME = 0x00000040; // 上次修改时间
        const STATX_CTIME = 0x00000080; // 上次状态变化时间
        const STATX_INO = 0x00000100; // 索引节点号
        const STATX_SIZE = 0x00000200; // 文件大小
        const STATX_BLOCKS = 0x00000400; // 分配的块数
        const STATX_BASIC_STATS = 0x7FFF8000; // 基本统计信息
        const STATX_BTIME = 0x00000800; // 创建时间
        const STATX_ALL = 0x00000fff;
    }
}

bitflags! {
    pub struct StatxFlags: u32 {
        const AT_EMPTY_PATH = 0x1000;
        const AT_NO_AUTOMOUNT = 0x800;
        const AT_SYMLINK_NOFOLLOW = 0x100;
    }
}

#[repr(C)]
pub struct Statx {
    stx_mask: u32,          // Mask of bits indicating filled fields
    stx_blksize: u32,       // Block size for filesystem I/O
    stx_attributes: u64,    // Extra file attribute indicators
    stx_nlink: u32,         // Number of hard links
    stx_uid: u32,           // User ID of owner
    stx_gid: u32,           // Group ID of owner
    stx_mode: u16,          // File type and mode
    __spare0: [u16; 1],     // Padding
    stx_ino: u64,           // Inode number
    stx_size: u64,          // Total size in bytes
    stx_blocks: u64,        // Number of 512B blocks allocated
    stx_attributes_mask: u64, // Mask to show supported attributes
    stx_atime: TimeSpec, // Last access
    stx_btime: TimeSpec, // Creation
    stx_ctime: TimeSpec, // Last status change
    stx_mtime: TimeSpec, // Last modification
    stx_rdev_major: u32,    // Major ID for device file
    stx_rdev_minor: u32,    // Minor ID for device file
    stx_dev_major: u32,     // Major ID of containing device
    stx_dev_minor: u32,     // Minor ID of containing device
    stx_mnt_id: u64,        // Mount ID
    stx_dio_mem_align: u32, // DIO memory alignment
    stx_dio_offset_align: u32, // DIO offset alignment
    stx_subvol: u64,        // Subvolume identifier
    stx_atomic_write_unit_min: u32,
    stx_atomic_write_unit_max: u32,
    stx_atomic_write_segments_max: u32,
    stx_dio_read_offset_align: u32,
    __spare3: [u64; 14],    // Future expansion
}

impl Default for Statx {
    fn default() -> Self {
        Self {
            stx_mask: 0,
            stx_blksize: 0,
            stx_attributes: 0,
            stx_nlink: 0,
            stx_uid: 0,
            stx_gid: 0,
            stx_mode: 0,
            __spare0: [0; 1],
            stx_ino: 0,
            stx_size: 0,
            stx_blocks: 0,
            stx_attributes_mask: 0,
            stx_atime: TimeSpec::default(),
            stx_btime: TimeSpec::default(),
            stx_ctime: TimeSpec::default(),
            stx_mtime: TimeSpec::default(),
            stx_rdev_major: 0,
            stx_rdev_minor: 0,
            stx_dev_major: 0,
            stx_dev_minor: 0,
            stx_mnt_id: 0,
            stx_dio_mem_align: 0,
            stx_dio_offset_align: 0,
            stx_subvol: 0,
            stx_atomic_write_unit_min: 0,
            stx_atomic_write_unit_max: 0,
            stx_atomic_write_segments_max: 0,
            stx_dio_read_offset_align: 0,
            __spare3: [0; 14],
        }
    }
}

/// 将 Kstat 转换为 Statx 结构
pub fn convert_kstat_to_statx(kstat: &Kstat, mask: u32) -> Statx {
    let mut statx = Statx::default();
    
    // 设置基本字段
    statx.stx_mask = mask;
    statx.stx_blksize = kstat.st_blksize as u32;
    statx.stx_nlink = kstat.st_nlink as u32;
    statx.stx_uid = kstat.st_uid;
    statx.stx_gid = kstat.st_gid;
    statx.stx_mode = kstat.st_mode as u16;
    statx.stx_ino = kstat.st_ino as u64;
    statx.stx_size = kstat.st_size as u64;
    statx.stx_blocks = kstat.st_blocks as u64;
    statx.stx_rdev_major = kstat.st_rdev as u32;
    statx.stx_dev_major = kstat.st_dev as u32;

    // 设置时间戳
    statx.stx_atime = TimeSpec {
        tv_sec: kstat.st_atime as usize,
        tv_nsec: kstat.st_atime_nsec,
    };
    statx.stx_mtime = TimeSpec {
        tv_sec: kstat.st_mtime as usize,
        tv_nsec: kstat.st_mtime_nsec,
    };
    statx.stx_ctime = TimeSpec {
        tv_sec: kstat.st_ctime as usize,
        tv_nsec: kstat.st_ctime_nsec,
    };
    
    // 设置设备信息
    statx.stx_dev_major = (kstat.st_dev >> 32) as u32;
    statx.stx_dev_minor = (kstat.st_dev & 0xFFFFFFFF) as u32;
    statx.stx_rdev_major = (kstat.st_rdev >> 32) as u32;
    statx.stx_rdev_minor = (kstat.st_rdev & 0xFFFFFFFF) as u32;

    // 其他字段保持默认值
    statx
}