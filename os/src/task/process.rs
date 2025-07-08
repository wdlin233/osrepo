//! Implementation of  [`ProcessControlBlock`]

use super::add_task;
use super::aux::{Aux, AuxType};
use super::alloc::{heap_id_alloc, tid_alloc, HeapidHandle, RecycleAllocator, TidHandle};
use super::manager::insert_into_pid2process;
use super::stride::Stride;
use super::TaskControlBlock;
use super::{pid_alloc, PidHandle};
#[cfg(target_arch = "loongarch64")]
use crate::config::PAGE_SIZE_BITS;

use crate::config::{PAGE_SIZE, PRE_ALLOC_PAGES, USER_HEAP_BOTTOM, USER_HEAP_SIZE, USER_STACK_TOP, USER_TRAP_CONTEXT_TOP};
use crate::fs::File;
use crate::fs::{FdTable, FsInfo, Stdin, Stdout};
use crate::hal::trap::{self, trap_handler, TrapContext};
#[cfg(target_arch = "riscv64")]
use crate::mm::KERNEL_SPACE;
use crate::mm::{
    flush_tlb, translated_refmut, MapAreaType, MemorySet, MemorySetInner, PageTable, PageTableEntry, VPNRange, VirtAddr, VirtPageNum
};
use crate::signal::{SigTable, SignalFlags};
use crate::sync::{Condvar, Mutex, Semaphore, UPSafeCell};
use crate::task::manager::insert_into_thread_group;
use crate::task::{KernelStack, TaskContext, TaskStatus};
use crate::timer::get_time;
use crate::users::{current_user, User};
use crate::utils::{get_abs_path, is_abs_path};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::cell::RefMut;
#[cfg(target_arch = "loongarch64")]
use loongarch64::register::pgdl;

use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};
use polyhal::kcontext::{read_current_tp, KContext, KContextArgs};

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
    pub trap_cx_ppn: PhysPageNum,
    pub trap_cx_base: usize,
    pub user_stack_top: usize,
    pub task_cx: KContext,
    pub task_status: TaskStatus,
    pub memory_set: Arc<MemorySet>,
    pub fd_table: Arc<FdTable>,
    pub fs_info: Arc<FsInfo>,
    pub mutex_list: Vec<Option<Arc<dyn Mutex>>>,
    pub semaphore_list: Vec<Option<Arc<Semaphore>>>,
    pub condvar_list: Vec<Option<Arc<Condvar>>>,
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
        self.trap_cx_ppn.as_mut()
        // let paddr = &self.trap_cx as *const TrapFrame as usize as *mut TrapFrame;
        // // let paddr: PhysAddr = self.trap_cx.into();
        // // unsafe { paddr.get_mut_ptr::<TrapFrame>().as_mut().unwrap() }
        // unsafe { paddr.as_mut().unwrap() }
    }
    pub fn is_zombie(&self) -> bool {
        self.task_status == TaskStatus::Zombie
    }
    /// set utime
    pub fn set_utime(&mut self, in_kernel_time: usize) {
        self.tms.inner.tms_utime = in_kernel_time - self.tms.begin_urun_time;
        if let Some(parent) = self.parent.as_mut() {
            parent
                .upgrade()
                .unwrap()
                .inner_exclusive_access()
                .tms
                .set_cutime(self.tms.inner.tms_utime);
            parent
                .upgrade()
                .unwrap()
                .inner_exclusive_access()
                .tms
                .set_cstime(self.tms.one_stime);
        }
        self.tms.one_stime = 0;
    }

    /// stime is this out_kernel_time - this in_kernel_time
    pub fn set_stime(&mut self, in_kernel_time: usize, out_kernel_time: usize) {
        self.tms.inner.tms_stime += out_kernel_time - in_kernel_time;
        self.tms.begin_urun_time = out_kernel_time;
        //debug!("in pcb,tms_stime is :{}",tms.inner.tms_stime);
        self.tms.one_stime += out_kernel_time - in_kernel_time;
    }

    #[allow(unused)]
    /// get the address of app's page table
    pub fn get_user_token(&self) -> usize {
        self.memory_set.token()
    }
    // /// allocate a new file descriptor
    // pub fn alloc_fd(&mut self) -> usize {
    //     let fd_table = &mut self
    //         .fd_table
    //         .get().files;
    // } use fstruct.rs instead
    /// allocate a new task id
    pub fn alloc_tid(&mut self) -> usize {
        self.task_res_allocator.alloc()
        //tid_alloc().0
    }
    /// deallocate a task id
    pub fn dealloc_tid(&mut self, tid: usize) {
        self.task_res_allocator.dealloc(tid)
        //tid_dealloc(tid);
    }
    /// the count of tasks(threads) in this process
    pub fn thread_count(&self) -> usize {
        self.tasks.len()
    }
    /// get a task with tid in this process
    pub fn get_task(&self, tid: usize) -> Arc<TaskControlBlock> {
        self.tasks[tid].as_ref().unwrap().clone()
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
    pub fn alloc_user_res(&mut self) {
        let (trap_cx_base, _) = self.memory_set.insert_framed_area_with_hint(
            USER_TRAP_CONTEXT_TOP,
            PAGE_SIZE,
            MapPermission::rw(),
            MapAreaType::Trap,
        );
        let (ustack_base, ustack_top) = self.memory_set.lazy_insert_framed_area_with_hint(
            USER_STACK_TOP,
            USER_STACK_SIZE,
            MapPermission::rwu(),
            MapAreaType::Stack,
        );
        let trap_cx_ppn = self.memory_set.translate(trap_cx_base).unwrap().ppn();
        self.user_stack_top = stack_top;
        self.trap_cx_ppn = trap_cx_ppn;
        self.trap_cx_base = trap_cx_base;

        let user_stack_range = VPNRange::new(
            VirtPageNum::from(ustack_base).floor(),
            VirtPageNum::from(ustack_top).floor(),
        );
        // 预分配用于环境变量
        let page_table = PageTable::from_token(self.memory_set.token());
        let area = self.memory_set.get_mut().areas.iter_mut().find(|area| {
            area.vpn_range.range() == user_stack_range.range() 
            //&& area.area_type == MapAreaType::Stack
        }).unwrap();
        for i in 1..=PRE_ALLOC_PAGES {
            let vpn = (area.vpn_range.end().0 - i).into();
            let pte: Option<PageTableEntry> = page_table.translate(vpn);
            if pte.is_none() || !pte.unwrap().is_valid() {
                area.map_one(
                    &mut self.memory_set.get_mut().page_table,
                    vpn,
                )
            }
        }
    }
    pub fn clone_user_res(&mut self, another: &ProcessControlBlockInner) {
        self.alloc_user_res();
        self.memory_set.lazy_clone_area(
            VirtAddr::from(self.user_stack_top - USER_HEAP_SIZE).floor(),
            another.memory_set.get_ref(),
        );
        seelf.memory_set.lazy_clone_area(
            VirtAddr::from(self.trap_cx_base).floor(),
            another.memory_set.get_ref(),
        );
    }
    pub fn dealloc_user_res(&mut self) {
        if self.user_stack_top != 0 {
            self.memory_set.remove_area_with_start_vpn(
                VirtAddr::from(self.user_stack_top - USER_STACK_SIZE).floor(),
            )
        }
        self.memory_set.remove_area_with_start_vpn(
            VirtAddr::from(self.trap_cx_base).floor(),
        );
        flush_tlb();
    }
    pub fn trap_cx(&self) -> &'static mut TrapContext {
        self.trap_cx_ppn.get_mut()
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
            let shrink_vpn: VirtPageNum = (shrink / PAGE_SIZE + 1).into();
            area.shrink_to(&mut inner.memory_set.get_mut().page_table, shrink_vpn);
            #[cfg(target_arch = "loongarch64")]
            flush_tlb();
            inner.heap_top = shrink;
        } else {
            let append = inner.heap_top + grow as usize;
            debug!("in pcb brk, append is : {}", append);
            let append_vpn: VirtPageNum = (append / PAGE_SIZE + 1).into();
            debug!("in pcb brk, append vpn is : {}", append_vpn.0);
            let hp_top_vpn: VirtPageNum = ((inner.heap_bottom + USER_HEAP_SIZE) / PAGE_SIZE).into();
            if append_vpn >= hp_top_vpn {
                debug!("user heap overflow at : {}", append);
                return 2;
            }
            debug!("in pcb brk, to append to");
            area.append_to(&mut inner.memory_set.get_mut().page_table, append_vpn);
            #[cfg(target_arch = "loongarch64")]
            flush_tlb();
            inner.heap_top = append;
        }
        inner.heap_top
    }
    /// new process from elf file
    pub fn new(elf_data: &[u8]) -> Arc<Self> {
        // debug!("kernel: create process from elf data, size = {}", elf_data.len());
        let (memory_set, heap_bottom, entry_point, _) = MemorySet::from_elf(elf_data);
        debug!("in pcb new, from elf ok");
        let tid_handle = tid_alloc();
        let kernel_stack = KernelStack::new(&tid_handle);
        let (kernel_stack_bottom, kernel_stack_top) = kernel_stack.pos();
        memory_set.insert_framed_area(
            kernel_stack_bottom.into(), 
            kernel_stack_top.into(), 
            MapPermission::R | MapPermission::W, 
            MapAreaType::Stack,
        );
        let user = current_user().unwrap();        

        let process = Arc::new(Self {
            tid: tid_handle,
            ppid: 1,
            pid: 1,
            user,
            kernel_stack,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    trap_cx_ppn: 0.into(),
                    trap_cx_base: 0,
                    user_stack_top: 0,
                    task_cx: blank_kcontext(kernel_stack_top),
                    task_status: TaskStatus::Ready,
                    memory_set: Arc::new(memory_set),
                    fd_table: Arc::new(FdTable::new_with_stdio()),
                    fs_info: Arc::new(FsInfo::new(String::from("/"))),
                    mutex_list: Vec::new(),
                    semaphore_list: Vec::new(),
                    condvar_list: Vec::new(),
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
        info!("in pcb new, the heap bottom is : {}", heap_bottom);
        
        let mut inner = process.inner_exclusive_access();
        inner.alloc_user_res();
        let mut trap_cx = inner.get_trap_cx();
        // *trap_cx = TrapContext::app_init_context(
        //     entry_point,
        //     inner.user_stack_top,
        //     kernel_stack_top
        // );
        *trap_cx = TrapFrame::new();
        *trap_cx[TrapFrameArgs::SEPC] = entry_point;
        *trap_cx[TrapFrameArgs::SP] = inner.user_stack_top;
        drop(inner);
        process
    }

    /// Only support processes with a single thread.
    pub fn exec(self: &Arc<Self>, elf_data: &[u8], args: Vec<String>, env: &mut Vec<String>) {
        debug!("kernel: exec, pid = {}", self.getpid());
        let (memory_set, user_heap_bottom, entry_point, mut aux) =
            MemorySet::from_elf(elf_data);
        memory_set.activate();

        let new_token = memory_set.token();
        let mut inner = self.inner_exclusive_access();
        if inner.clear_child_tid != 0 {
            *translated_refmut(new_token, inner.clear_child_tid as *mut u32) = 0;
            //data_flow!({ *(task_inner.clear_child_tid as *mut u32) = 0 });
        }

        inner.alloc_user_res();
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
                *translated_refmut(new_token, p as *mut u8) = *c;
                p += 1;
            }
            *translated_refmut(new_token, p as *mut u8) = 0;
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
                *translated_refmut(new_token, p as *mut u8) = *c;
                p += 1;
            }
            *translated_refmut(new_token, p as *mut u8) = 0;
        }
        argv.push(0);
        user_sp -= user_sp % size;

        //aux 16字节随机变量
        user_sp -= 16;
        aux.push(Aux::new(AuxType::RANDOM, user_sp));
        for i in 0..0xf {
            let mut p = user_sp + i;
            *translated_refmut(new_token, p as *mut u8) = (i * 2) as u8;
        }
        user_sp -= user_sp % 16;
        //aux
        aux.push(Aux::new(AuxType::EXECFN, argv[0]));
        aux.push(Aux::new(AuxType::NULL, 0));
        for aux in aux.iter().rev() {
            user_sp -= core::mem::size_of::<Aux>();
            let mut p = user_sp;
            let mut pp = user_sp + size;
            *translated_refmut(new_token, p as *mut usize) = aux.aux_type as usize;
            *translated_refmut(new_token, pp as *mut usize) = aux.value;
        }
        let aux_base = user_sp;

        //env指针
        //env指针空间
        user_sp -= envp.len() * size;
        let env_base = user_sp;
        for i in 0..envp.len() {
            let mut p = user_sp + i * size;
            *translated_refmut(new_token, p as *mut usize) = envp[i];
        }

        //args 指针
        //args指针空间
        user_sp -= argv.len() * size;
        let argv_base = user_sp;
        for i in 0..argv.len() {
            let mut p = user_sp + i * size;
            *translated_refmut(new_token, p as *mut usize) = argv[i];
        }

        //获取argc
        let args_len = args.len();
        //debug!("the args len is :{}", args_len);
        //设置argc
        *translated_refmut(new_token, (user_sp - size) as *mut usize) = args.len().into();
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
        parent_tid: *mut u32,
        _tls: usize,
        child_tid: *mut u32,
    ) -> Arc<Self> {
        let user = self.user.clone();
        let mut parent = self.inner_exclusive_access();
        
        let tid_handle = tid_alloc();
        let kernel_stack = KernelStack::new(&tid_handle);
        let kernel_stack_top = kernel_stack.get_top();

        // 检查是否共享虚拟内存
        let memory_set = if flags.contains(CloneFlags::CLONE_VM) {
            Arc::clone(&parent.memory_set)
        } else {
            Arc::new(MemorySet::from_existed_user(&parent.memory_set))
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
        let set_child_tid = if flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
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
        let child = Arc::new(Self {
            tid: tid_handle,
            ppid,
            pid,
            user,
            kernel_stack,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    trap_cx_ppn: 0.into(), 
                    trap_cx_base: 0,
                    user_stack_top: 0,
                    task_cx: blank_kcontext(kernel_stack_top), // maybe
                    task_status: TaskStatus::Ready,
                    clear_child_tid,
                    memory_set,
                    fs_info,
                    fd_table: new_fd_table,
                    mutex_list: Vec::new(),
                    semaphore_list: Vec::new(),
                    condvar_list: Vec::new(),
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
        if flags.contains(CloneFlags::CLONE_THREAD) {
            inner.alloc_user_res();
            *inner.get_trap_cx() = *parent.get_trap_cx();
        } else {
            inner.clone_user_res(&parent);
            *inner.get_trap_cx()[TrapFrameArgs::ARG0] = 0; // 应该是这么写吧
        }
        // let trap_cx = inner.get_trap_cx();
        // trap_cx.kernel_sp = kernel_stack_top;
        // 实际上就是 trap_cx.kernel_sp = task.kstack.get_top();
        if stack != 0 {
            implemented!("[ProcessControlBlock, fork] stack != 0, not implemented yet");
        }
        if flags.contains(CloneFlags::CLONE_SETTLS) {
            // 这里的 tls 是指线程局部存储
            implemented!("[ProcessControlBlock, fork] CLONE_SETTLS not implemented yet");
        }
        if flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
            unimplemented!("[ProcessControlBlock, fork] CLONE_CHILD_SETTID not implemented yet");
        }
        drop(inner);
        drop(parent);
        insert_into_pid2process(inner.gettid(), &child);
        insert_into_thread_group(child.pid, &child);
        if !flags.contains(CloneFlags::CLONE_THREAD) {
            unimplemented!("[ProcessControlBlock, fork] CLONE_THREAD not implemented yet");
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
    pub fn get_task_len(&self) -> usize {
        self.inner_exclusive_access().tasks.len()
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
    use crate::hal::trap::trap_return;
    let mut kcx = KContext::blank(); // 包括 s 寄存器
    kcx[KContextArgs::KPC] = trap_return as usize; // ra
    kcx[KContextArgs::KSP] = ksp; // sp: kstack_ptr, 存放了trap上下文后的栈地址, 内核栈地址
    kcx[KContextArgs::KTP] = read_current_tp(); // tp
    kcx
}