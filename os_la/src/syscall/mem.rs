use log::debug;

use super::{MmapFlags, MmapProt};
use crate::{
    config::PAGE_SIZE,
    fs::{File, OpenFlags},
    mm::{
        insert_bad_address, is_bad_address, remove_bad_address, translated_refmut, MapPermission,
        VirtAddr,
    },
    task::{current_process, current_task},
    utils::{page_round_up, SysErrNo, SyscallRet},
};

pub fn sys_mprotect(addr: usize, len: usize, prot: u32) -> isize {
    if addr == 0 {
        return SysErrNo::ENOMEM as isize;
    }

    if (addr % PAGE_SIZE != 0) || (len % PAGE_SIZE != 0) {
        log::warn!("sys_mprotect: not align");
        return SysErrNo::EINVAL as isize;
    }
    let map_perm: MapPermission = MmapProt::from_bits(prot).unwrap().into();

    debug!(
        "[sys_mprotect] addr is {:x}, len is {:#x}, map_perm is {:?}",
        addr, len, map_perm
    );

    let process = current_process();
    let inner = process.inner_exclusive_access();
    let memory_set = inner.memory_set.get_mut();
    let start_vpn = VirtAddr::from(addr).floor();
    let end_vpn = VirtAddr::from(addr + len).ceil();
    //修改各段的mappermission
    memory_set.mprotect(start_vpn, end_vpn, map_perm);
    return 0;
}
