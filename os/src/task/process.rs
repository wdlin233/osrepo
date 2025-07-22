//! Implementation of  [`ProcessControlBlock`]

use super::add_task;
use super::alloc::{heap_id_alloc, tid_alloc, HeapidHandle, RecycleAllocator, TidHandle};
use super::aux::{Aux, AuxType};
use super::manager::insert_into_tid2task;
use super::stride::Stride;
use super::{pid_alloc, PidHandle};

use crate::config::{
    PRE_ALLOC_PAGES, USER_HEAP_BOTTOM, USER_HEAP_SIZE, USER_STACK_SIZE, USER_STACK_TOP,
    USER_TRAP_CONTEXT_TOP,
};
use crate::fs::File;
use crate::fs::{FdTable, FsInfo, Stdin, Stdout};
use crate::mm::{
    translated_refmut, MapAreaType, MapPermission, MapType, MemorySet, MemorySetInner, VAddrRange,
};
use crate::signal::{SigTable, SignalFlags};
use crate::sync::UPSafeCell;
use crate::syscall::CloneFlags;
use crate::task::alloc::kernel_stack_position;
use crate::task::manager::insert_into_thread_group;
use crate::task::{insert_into_process_group, KernelStack};
use crate::timer::get_time;
use crate::trap::trap_entry;
use crate::users::{current_user, User};
use crate::utils::{get_abs_path, is_abs_path};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::cell::RefMut;
use polyhal::pagetable::{PAGE_SIZE, TLB};
use polyhal::{MappingFlags, PhysAddr, VirtAddr};
use polyhal_trap::trap;

use polyhal::kcontext::{read_current_tp, KContext, KContextArgs};
use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};

/// Process Control Block
pub struct ProcessControlBlock {
    /// ppid
    ppid: usize,
    /// pid
    pid: usize,
    /// tid
    tid: TidHandle,
    /// immutable default user
    user: Arc<User>,
    ///
    pub kernel_stack: KernelStack,
    /// mutable
    inner: UPSafeCell<ProcessControlBlockInner>,
}

/// Inner of Process Control Block
pub struct ProcessControlBlockInner {
    pub trap_cx: TrapFrame,
    pub trap_cx_ppn: PhysAddr,
    pub trap_cx_base: usize,
    pub user_stack_top: usize,
    pub task_cx: KContext,
    pub task_status: TaskStatus,
    pub memory_set: Arc<MemorySet>,
    pub fd_table: Arc<FdTable>,
    pub fs_info: Arc<FsInfo>,
    pub priority: usize,
    pub stride: Stride,
    pub tms: Tms,
    pub sig_table: Arc<SigTable>,
    pub sig_mask: SignalFlags,
    pub sig_pending: SignalFlags,
    pub clear_child_tid: usize,
    pub heap_bottom: usize,
    pub heap_top: usize,
    pub robust_list: RobustList,
    pub trap_ctx_backup: Option<TrapFrame>,
}

#[derive(Clone, Copy, Debug)]
pub struct RobustList {
    pub head: usize,
    pub len: usize,
}

impl RobustList {
    // from strace
    pub const HEAD_SIZE: usize = 24;
    pub fn default() -> Self {
        RobustList { head: 0, len: 24 }
    }
}

///record process times
#[derive(Debug, Copy, Clone)]
pub struct Tms {
    /// when a process run in user
    pub begin_urun_time: usize,
    /// syscall in one time
    pub one_stime: usize,
    /// inner
    pub inner: TmsInner,
}

/// tms interface
#[derive(Debug, Copy, Clone)]
pub struct TmsInner {
    /// this process user time
    pub tms_utime: usize,
    /// this process syscall time
    pub tms_stime: usize,
    /// this process child user time
    pub tms_cutime: usize,
    /// this process child user time
    pub tms_cstime: usize,
}

impl Tms {
    /// new a Tms
    pub fn new() -> Self {
        Tms {
            begin_urun_time: 0,
            one_stime: 0,
            inner: TmsInner {
                tms_utime: 0,
                tms_stime: 0,
                tms_cutime: 0,
                tms_cstime: 0,
            },
        }
    }
    /// when a process was scheduled,record the time
    pub fn set_begin(&mut self) {
        self.begin_urun_time = get_time();
    }
    /// cutime
    pub fn set_cutime(&mut self, cutime: usize) {
        self.inner.tms_cutime += cutime;
    }
    /// cstime
    pub fn set_cstime(&mut self, cstime: usize) {
        self.inner.tms_cstime += cstime;
    }
}

impl ProcessControlBlockInner {
    pub fn get_trap_cx(&self) -> &'static mut TrapFrame {
        // let kernel_va = self.trap_cx_ppn.get_mut_ptr::<TrapFrame>();
        // unsafe { kernel_va.as_mut().unwrap() }
        let paddr = &self.trap_cx as *const TrapFrame as usize as *mut TrapFrame;
        // let paddr: PhysAddr = self.trap_cx.into();
        // unsafe { paddr.get_mut_ptr::<TrapFrame>().as_mut().unwrap() }
        unsafe { paddr.as_mut().unwrap() }
    }
    // pub fn trap_cx(&self) -> &'static mut TrapFrame {
    //     let paddr = &self.trap_cx as *const TrapFrame as usize as *mut TrapFrame;
    //     // let paddr: PhysAddr = self.trap_cx.into();
    //     // unsafe { paddr.get_mut_ptr::<TrapFrame>().as_mut().unwrap() }
    //     unsafe { paddr.as_mut().unwrap() }
    // }
    pub fn is_zombie(&self) -> bool {
        self.task_status == TaskStatus::Zombie
    }
    /// set utime
    pub fn set_utime(&mut self, in_kernel_time: usize) {
        self.tms.inner.tms_utime = in_kernel_time - self.tms.begin_urun_time;
        self.tms.set_cutime(self.tms.inner.tms_utime);
        self.tms.set_cstime(self.tms.one_stime);
        self.tms.one_stime = 0;
    }

    /// stime is this out_kernel_time - this in_kernel_time
    pub fn set_stime(&mut self, in_kernel_time: usize, out_kernel_time: usize) {
        self.tms.inner.tms_stime += out_kernel_time - in_kernel_time;
        self.tms.begin_urun_time = out_kernel_time;
        //debug!("in pcb,tms_stime is :{}",tms.inner.tms_stime);
        self.tms.one_stime += out_kernel_time - in_kernel_time;
    }

    ///get abs path
    pub fn get_abs_path(&self, dirfd: isize, path: &str) -> String {
        if is_abs_path(path) {
            get_abs_path("/", path)
        } else if dirfd != -100 {
            let dirfd = dirfd as usize;
            if let Some(file) = self.fd_table.try_get(dirfd) {
                let base_path = file.file().unwrap().inode.path();
                if path.is_empty() {
                    base_path
                } else {
                    get_abs_path(&base_path, path)
                }
            } else {
                String::from("")
            }
        } else {
            get_abs_path(self.fs_info.cwd(), path)
        }
    }
    /// 创建用户栈、上下文
    pub fn alloc_user_res(&mut self, tid: usize) {
        // let (trap_cx_base, trap_top) = trap_cx_space(tid);
        // // self.memory_set.get_mut().insert_framed_area_with_hint(
        // //     USER_TRAP_CONTEXT_TOP,
        // //     PAGE_SIZE,
        // //     MapPermission::R | MapPermission::W,
        // //     MapAreaType::Trap,
        // // );
        // self.memory_set.get_mut().insert_framed_area(
        //     VirtAddr::from(trap_cx_base),
        //     VirtAddr::from(trap_top),
        //     MapType::Framed,
        //     MapPermission::R | MapPermission::W,
        //     MapAreaType::Trap,
        // );
        let (ustack_base, ustack_top) = ustack_space(tid);
        // self.memory_set.get_mut().lazy_insert_framed_area_with_hint(
        //     USER_STACK_TOP,
        //     USER_STACK_SIZE,
        //     MapPermission::R | MapPermission::W | MapPermission::U,
        //     MapAreaType::Stack,
        // );
        self.memory_set.get_mut().insert_framed_area(
            VirtAddr::from(ustack_base),
            VirtAddr::from(ustack_top),
            MapType::Framed,
            MapPermission::R | MapPermission::W | MapPermission::U,
            MapAreaType::Stack,
        );
        // if tid == 1 {
        //     let trap_cx_ppn = self
        //         .memory_set
        //         .translate(VirtAddr::from(trap_cx_base).floor())
        //         .unwrap()
        //         .0;
        //     self.trap_cx_ppn = trap_cx_ppn;
        // }

        self.user_stack_top = ustack_top;
        //self.trap_cx_base = trap_cx_base;

        // let user_stack_range = VAddrRange::new(
        //     VirtAddr::from(ustack_base).floor(),
        //     VirtAddr::from(ustack_top).floor(),
        // );
        // // 预分配用于环境变量
        // let page_table = self.memory_set.token();
        // let area = self
        //     .memory_set
        //     .get_mut()
        //     .areas
        //     .iter_mut()
        //     .find(|area| {
        //         area.vaddr_range.range() == user_stack_range.range()
        //         //&& area.area_type == MapAreaType::Stack
        //     })
        //     .unwrap();
        // for i in 1..=PRE_ALLOC_PAGES {
        //     let vaddr: VirtAddr = (area.vaddr_range.get_end().raw() - i * PAGE_SIZE).into();
        //     let res = page_table.translate(vaddr);
        //     if res.is_none() || !res.unwrap().1.contains(MappingFlags::P) {
        //         area.map_one(&mut self.memory_set.get_mut().page_table, vaddr)
        //     }
        // }
        // debug!(
        //     "(ProcessControlBlockInner, alloc_user_res) user stack area: {:#x} - {:#x}",
        //     ustack_base, ustack_top
        // );
    }
    pub fn clone_user_res(&mut self, another: &ProcessControlBlockInner, tid: usize) {
        self.alloc_user_res(tid);

        let another_memory_set = another.memory_set.get_ref();
        self.memory_set.lazy_clone_area(
            VirtAddr::from(self.user_stack_top - USER_STACK_SIZE).floor(),
            another_memory_set,
        );
        self.memory_set.clone_area(
            VirtAddr::from(self.trap_cx_base).floor(),
            another_memory_set,
        );
    }
    pub fn dealloc_user_res(&mut self) {
        if self.user_stack_top != 0 {
            self.memory_set.remove_area_with_start_vpn(
                VirtAddr::from(self.user_stack_top - USER_STACK_SIZE).floor(),
            )
        }
        self.memory_set
            .remove_area_with_start_vpn(VirtAddr::from(self.trap_cx_base).floor());
        TLB::flush_all();
    }
    pub fn recycle(&mut self) {
        self.memory_set.recycle_data_pages();
        self.fd_table.clear();
        self.fs_info.clear();
    }
    pub fn is_group_exit(&self) -> bool {
        self.sig_table.is_exited()
    }
}

impl ProcessControlBlock {
    /// inner_exclusive_access
    pub fn inner_exclusive_access(&self) -> RefMut<'_, ProcessControlBlockInner> {
        self.inner.exclusive_access()
    }
    /// change the location of the program break. return None if failed.
    pub fn change_program_brk(&self, grow: isize) -> usize {
        debug!("in change brk,grow = {}", grow);

        let mut inner = self.inner_exclusive_access();

        debug!(
            "self.brk = {},self.bottom = {}",
            inner.heap_top, inner.heap_bottom
        );
        if grow == 0 {
            return inner.heap_top;
        }

        let area = inner
            .memory_set
            .get_mut()
            .areas
            .iter_mut()
            .find(|area| area.area_type == MapAreaType::Brk)
            .unwrap();

        if grow < 0 {
            let shrink = (inner.heap_top as isize + grow) as usize;
            if shrink < inner.heap_bottom {
                debug!("user heap downflow at : {}", shrink);
                return 2;
            }
            let shrink_vpn = VirtAddr::from(shrink + PAGE_SIZE);
            area.shrink_to(&mut inner.memory_set.get_mut().page_table, shrink_vpn);
            inner.heap_top = shrink;
        } else {
            let append = inner.heap_top + grow as usize;
            debug!("in pcb brk, append is : {}", append);
            let append_vpn = VirtAddr::from(append + PAGE_SIZE);
            debug!("in pcb brk, append vpn is : {}", append_vpn);
            let hp_top_vpn = VirtAddr::from(inner.heap_bottom + USER_HEAP_SIZE);
            if append_vpn >= hp_top_vpn {
                debug!("user heap overflow at : {}", append);
                return 2;
            }
            debug!("in pcb brk, to append to");
            area.append_to(&mut inner.memory_set.get_mut().page_table, append_vpn);
            inner.heap_top = append;
        }
        inner.heap_top
    }
    /// new process from elf file
    pub fn new(elf_data: &[u8]) -> Arc<Self> {
        // debug!("kernel: create process from elf data, size = {}", elf_data.len());
        let (memory_set, heap_bottom, entry_point, _) = MemorySet::from_elf(elf_data);
        debug!("(ProcessControlBlock, new), from_elf passed");
        let tid_handle = tid_alloc();
        let kernel_stack = KernelStack::new(&tid_handle);
        let (_kernel_stack_bottom, kernel_stack_top) = kernel_stack.get_position();
        let user = current_user().unwrap();

        let process = Arc::new(Self {
            tid: tid_handle,
            ppid: 1,
            pid: 1,
            user,
            kernel_stack,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    trap_cx: TrapFrame::new(),
                    trap_cx_ppn: PhysAddr::new(0),
                    trap_cx_base: 0,
                    user_stack_top: 0,
                    task_cx: blank_kcontext(kernel_stack_top),
                    task_status: TaskStatus::Ready,
                    memory_set: Arc::new(memory_set),
                    fd_table: Arc::new(FdTable::new_with_stdio()),
                    fs_info: Arc::new(FsInfo::new(String::from("/"))),
                    priority: 16,
                    clear_child_tid: 0,
                    stride: Stride::default(),
                    tms: Tms::new(),
                    sig_table: Arc::new(SigTable::new()),
                    sig_mask: SignalFlags::empty(),
                    sig_pending: SignalFlags::empty(),
                    heap_bottom,
                    heap_top: heap_bottom,
                    robust_list: RobustList::default(),
                    trap_ctx_backup: None,
                })
            },
        });
        info!(
            "(ProcessControlBlock, new), the heap bottom is : {:#x}",
            heap_bottom
        );

        // 只映射用户地址空间，由于只有在新建 initproc 时使用，写死 app_id 为 1.
        // let (kstack_bottom, kstack_top) = kernel_stack_position(1);
        // let memory_set = process.inner_exclusive_access().memory_set.clone();
        // memory_set.insert_framed_area(
        //     kstack_bottom.into(),
        //     kstack_top.into(),
        //     MapType::Framed,
        //     MapPermission::R | MapPermission::W,
        //     MapAreaType::Stack,
        // );

        let mut inner = process.inner_exclusive_access();
        inner.alloc_user_res(process.tid.0);
        let trap_cx = inner.get_trap_cx();
        //*trap_cx = TrapFrame::new();
        trap_cx[TrapFrameArgs::SEPC] = entry_point;
        trap_cx[TrapFrameArgs::SP] = inner.user_stack_top;
        drop(inner);
        process
    }

    /// Only support processes with a single thread.
    pub fn exec(self: &Arc<Self>, elf_data: &[u8], args: Vec<String>, env: &mut Vec<String>) {
        debug!("kernel: exec, pid = {}", self.getpid());
        let mut inner = self.inner_exclusive_access();
        let (memory_set, user_heap_bottom, entry_point, mut aux) = MemorySet::from_elf(elf_data);

        inner.memory_set = Arc::new(memory_set);
        inner.memory_set.activate();
        //debug!("activate ok");

        if inner.clear_child_tid != 0 {
            *translated_refmut(inner.clear_child_tid as *mut u32) = 0;
            //data_flow!({ *(task_inner.clear_child_tid as *mut u32) = 0 });
        }

        inner.alloc_user_res(self.tid.0);
        inner.sig_table = Arc::new(SigTable::new());
        let fd_table = Arc::new(FdTable::from_another(&inner.fd_table));
        inner.fd_table = fd_table;
        inner.fd_table.close_on_exec();
        inner.sig_mask = SignalFlags::empty();
        inner.sig_pending = SignalFlags::empty();

        let mut user_sp = inner.user_stack_top;
        info!("(ProcessControlBlock, exec), initial user_sp = {}", user_sp);

        /*
        -----------------------ustack top == sp(init)
                .
                .
                .
            ------------
            env string 2
            ------------
            env string 1
        ------------------------env_st
            地址对齐
        --------------------------

                .
                .
                .
            -------------
            args string 2
            -------------
            args string 1
        ---------------------------args_st
            地址对齐
        ----------------------------
            aux空间
            以两个0为结束标志
        ----------------------------
                0(envp 结束)
            ---------------------
                .
                .
                .
            ---------------------
            envp2 -> env string 2
            ---------------------
            envp1 -> env string 1
        -----------------------------env_base
                0(argv 结束)
            --------------------------
                .
                .
                .
            --------------------------
                argv2 -> args string 2
            --------------------------
                argv1 -> args string 1
        --------------------------------argv_base
            argc
        ---------------------------------sp(final)
        */

        //usize大小
        let size = core::mem::size_of::<usize>();

        //环境变量内容入栈
        let mut envp = Vec::new();
        for env in env.iter() {
            user_sp -= env.len() + 1;
            envp.push(user_sp);
            let mut p = user_sp;
            //设置env字符串
            for c in env.as_bytes() {
                *translated_refmut(p as *mut u8) = *c;
                p += 1;
            }
            *translated_refmut(p as *mut u8) = 0;
        }
        envp.push(0);
        user_sp -= user_sp % size;

        //args
        let mut argv = Vec::new();
        for i in 0..args.len() {
            user_sp -= args[i].len() + 1;
            argv.push(user_sp);
            let mut p = user_sp;
            //讲args字符串内容写到栈空间中
            for c in args[i].as_bytes() {
                *translated_refmut(p as *mut u8) = *c;
                p += 1;
            }
            *translated_refmut(p as *mut u8) = 0;
        }
        argv.push(0);
        user_sp -= user_sp % size;

        //aux 16字节随机变量
        user_sp -= 16;
        aux.push(Aux::new(AuxType::RANDOM, user_sp));
        for i in 0..0xf {
            let p = user_sp + i;
            *translated_refmut(p as *mut u8) = (i * 2) as u8;
        }
        user_sp -= user_sp % 16;
        //aux
        aux.push(Aux::new(AuxType::EXECFN, argv[0]));
        aux.push(Aux::new(AuxType::NULL, 0));
        for aux in aux.iter().rev() {
            user_sp -= core::mem::size_of::<Aux>();
            let p = user_sp;
            let pp = user_sp + size;
            *translated_refmut(p as *mut usize) = aux.aux_type as usize;
            *translated_refmut(pp as *mut usize) = aux.value;
        }
        let _aux_base = user_sp;

        //env指针
        //env指针空间
        user_sp -= envp.len() * size;
        let env_base = user_sp;
        for i in 0..envp.len() {
            let p = user_sp + i * size;
            *translated_refmut(p as *mut usize) = envp[i];
        }

        //args 指针
        //args指针空间
        user_sp -= argv.len() * size;
        let argv_base = user_sp;
        for i in 0..argv.len() {
            let p = user_sp + i * size;
            *translated_refmut(p as *mut usize) = argv[i];
        }

        //获取argc
        let args_len = args.len();
        //debug!("the args len is :{}", args_len);
        //设置argc
        *translated_refmut((user_sp - size) as *mut usize) = args.len().into();
        //对齐地址
        user_sp -= user_sp % size;
        inner.fd_table.close_on_exec();

        // initialize trap_cx
        debug!("(ProcessControlBlock, exec) init context");
        let mut trap_cx = TrapFrame::new();
        trap_cx[TrapFrameArgs::SEPC] = entry_point;
        trap_cx[TrapFrameArgs::SP] = user_sp;
        trap_cx[TrapFrameArgs::ARG0] = args_len; // a0, argc
        trap_cx[TrapFrameArgs::ARG1] = argv_base; // a1
        trap_cx[TrapFrameArgs::ARG2] = env_base; // a2
        *inner.get_trap_cx() = trap_cx;
        inner.heap_bottom = user_heap_bottom;
        inner.heap_top = user_heap_bottom;
        // #[cfg(target_arch = "loongarch64")]
        // {
        //     //由于切换了地址空间，因此之前的ASID对应的地址空间将不会再有用，
        //     // 因此这里需要将TLB中的内容无效掉
        //     let pid = self.getpid();
        //     unsafe {
        //         asm!("invtlb 0x4,{},$r0",in(reg) pid);
        //     }
        //     // 设置新的pgdl
        //     let pgd = new_token << PAGE_SIZE_BITS;
        //     // Pgdl::read().set_val(pgd).write(); //设置新的页基址
        //     pgdl::set_base(pgd); //设置新的页基址
        // }
        debug!("(ProecessControlBlock, exec) return, ok");
    }

    /// Only support processes with a single thread.
    pub fn fork(
        self: &Arc<Self>,
        flags: CloneFlags,
        stack: usize,
        _parent_tid: *mut u32,
        tls: usize,
        child_tid: *mut u32,
    ) -> Arc<Self> {
        let user = self.user.clone();
        let parent = self.inner_exclusive_access();

        let tid_handle = tid_alloc();
        let kernel_stack = KernelStack::new(&tid_handle);
        let (kstack_bottom, kernel_stack_top) = kernel_stack.get_position();

        // 检查是否共享虚拟内存
        let memory_set = if flags.contains(CloneFlags::CLONE_VM) {
            Arc::clone(&parent.memory_set)
        } else {
            Arc::new(MemorySetInner::from_existed_user(&parent.memory_set))
        };
        // 检查是否共享文件系统信息
        //filesystem information.  This includes the root
        //of the filesystem, the current working directory, and the umask
        let fs_info = if flags.contains(CloneFlags::CLONE_FS) {
            Arc::clone(&parent.fs_info)
        } else {
            Arc::new(FsInfo::from_another(&parent.fs_info))
        };
        // 检查是否共享打开文件表
        let new_fd_table = if flags.contains(CloneFlags::CLONE_FILES) {
            Arc::clone(&parent.fd_table)
        } else {
            Arc::new(FdTable::from_another(&parent.fd_table))
        };

        let sig_table = if flags.contains(CloneFlags::CLONE_SIGHAND) {
            Arc::clone(&parent.sig_table)
        } else {
            Arc::new(SigTable::from_another(&parent.sig_table))
        };
        // if flags.contains(CloneFlags::CLONE_PARENT_SETTID) {
        //     put_data(parent_inner.user_token(), parent_tid, tid_handle.0 as u32);
        // }
        // 检查是否需要设置子进程的 set_child_tid,clear_child_tid
        let _set_child_tid = if flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
            child_tid as usize
        } else {
            0
        };
        let clear_child_tid = if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
            child_tid as usize
        } else {
            0
        };

        let (pid, mut ppid, sig_mask, sig_pending);
        sig_pending = SignalFlags::empty();

        let creat_thread = flags.contains(CloneFlags::CLONE_THREAD);
        if creat_thread {
            debug!(
                "(ProcessControlBlock, fork) creat thread, need tcb, not need pcb, to implement"
            );
            pid = self.pid;
            ppid = self.ppid;
            sig_mask = SignalFlags::empty();
        } else {
            pid = tid_handle.0;
            ppid = self.pid;
            sig_mask = parent.sig_mask.clone();
        }
        if flags.contains(CloneFlags::CLONE_PARENT) {
            ppid = self.ppid;
        }
        debug!(
            "(ProcessControlBlock, fork) create child, pid: {}, ppid: {}, tid: {}",
            pid, ppid, tid_handle.0
        );
        let tid = tid_handle.0;
        let child = Arc::new(Self {
            tid: tid_handle,
            ppid,
            pid,
            user,
            kernel_stack,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    trap_cx: parent.trap_cx.clone(),
                    trap_cx_ppn: PhysAddr::new(0),
                    trap_cx_base: 0,
                    user_stack_top: 0,
                    task_cx: blank_kcontext(kernel_stack_top), // maybe
                    task_status: TaskStatus::Ready,
                    clear_child_tid,
                    memory_set,
                    fs_info,
                    fd_table: new_fd_table,
                    priority: 16,
                    stride: Stride::default(),
                    tms: Tms::new(),
                    sig_mask,
                    sig_pending,
                    sig_table,
                    heap_bottom: parent.heap_bottom,
                    heap_top: parent.heap_top,
                    robust_list: RobustList::default(),
                    trap_ctx_backup: None,
                })
            },
        });
        let mut inner = child.inner_exclusive_access();
        // let memory_set = inner.memory_set.clone();
        // memory_set.insert_framed_area(
        //     kstack_bottom.into(),
        //     kernel_stack_top.into(),
        //     MapType::Framed,
        //     MapPermission::R | MapPermission::W,
        //     MapAreaType::Stack,
        // );
        // if flags.contains(CloneFlags::CLONE_THREAD) {
        //     inner.alloc_user_res(tid);
        //     *inner.get_trap_cx() = parent.get_trap_cx().clone();
        // } else {
        //     inner.clone_user_res(&parent, tid);
        //     info!("(ProcessControlBlock, fork) clone user res ok");
        //     inner.get_trap_cx()[TrapFrameArgs::RET] = 0; // 应该是这么写吧
        // }

        //debug!("(ProcessControlBlock, fork) child trap_cx: {:#?}", inner.get_trap_cx());

        let trap_cx = inner.get_trap_cx();
        trap_cx[TrapFrameArgs::RET] = 0;
        //trap_cx.kernel_sp = kernel_stack_top;
        // 实际上就是 trap_cx.kernel_sp = task.kstack.get_top();
        if stack != 0 {
            unimplemented!("[ProcessControlBlock, fork] stack != 0, not implemented yet");
        }
        if flags.contains(CloneFlags::CLONE_SETTLS) {
            // 这里的 tls 是指线程局部存储
            trap_cx[TrapFrameArgs::TLS] = tls;
        }
        if flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
            unimplemented!("[ProcessControlBlock, fork] CLONE_CHILD_SETTID not implemented yet");
        }
        drop(inner);
        drop(parent);
        insert_into_tid2task(child.gettid(), &child);
        insert_into_thread_group(child.pid, &child);
        if !flags.contains(CloneFlags::CLONE_THREAD) {
            insert_into_process_group(child.getppid(), &child);
        }
        child
    }
    pub fn gettid(&self) -> usize {
        self.tid.0
    }
    /// get pid
    pub fn getpid(&self) -> usize {
        self.pid
    }
    /// get parent pid
    pub fn getppid(&self) -> usize {
        self.ppid
    }
    /// get default uid
    pub fn getuid(&self) -> usize {
        self.user.getuid()
    }
    /// get default gid
    pub fn getgid(&self) -> usize {
        self.user.getgid()
    }
    /// set clear child tid
    pub fn set_clear_child_tid(&self, new: usize) {
        self.inner_exclusive_access().clear_child_tid = new;
    }
}

#[derive(Copy, Clone, PartialEq)]
/// The execution status of the current process
pub enum TaskStatus {
    /// ready to run
    Ready,
    /// running
    Running,
    /// blocked
    Blocked,
    /// zombie, waiting for parent to collect
    Zombie,
    /// stopped, waiting for signal
    Stopped,
}

fn blank_kcontext(ksp: usize) -> KContext {
    let mut kcx = KContext::blank(); // 包括 s 寄存器
    kcx[KContextArgs::KPC] = trap_entry as usize; // ra
    kcx[KContextArgs::KSP] = ksp; // sp: kstack_ptr, 存放了trap上下文后的栈地址, 内核栈地址
    kcx[KContextArgs::KTP] = read_current_tp(); // tp
    kcx
}

fn trap_cx_space(tid: usize) -> (usize, usize) {
    let trap_bottom = USER_TRAP_CONTEXT_TOP - tid * 2 * PAGE_SIZE;
    let trap_top = trap_bottom + PAGE_SIZE;
    (trap_bottom, trap_top)
}

fn ustack_space(tid: usize) -> (usize, usize) {
    let ustack_bottom = USER_STACK_TOP - tid * (USER_STACK_SIZE + PAGE_SIZE);
    let ustack_top = ustack_bottom + USER_STACK_SIZE;
    (ustack_bottom, ustack_top)
}
