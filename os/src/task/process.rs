//! Implementation of  [`ProcessControlBlock`]

use super::add_task;
use super::aux::{Aux, AuxType};
use super::id::{heap_id_alloc, tid_alloc, HeapidHandle, RecycleAllocator, TidHandle};
use super::manager::insert_into_pid2process;
use super::stride::Stride;
use super::TaskControlBlock;
use super::{pid_alloc, PidHandle};
#[cfg(target_arch = "loongarch64")]
use crate::config::PAGE_SIZE_BITS;
use crate::mm::MapPermission;

use crate::config::{PAGE_SIZE, USER_HEAP_BOTTOM, USER_HEAP_SIZE};
use crate::fs::File;
use crate::fs::{FdTable, FsInfo, Stdin, Stdout};
use crate::hal::trap::{trap_handler, TrapContext};
use crate::mm::VPNRange;
#[cfg(target_arch = "riscv64")]
use crate::mm::KERNEL_SPACE;
use crate::mm::{
    flush_tlb, put_data, translated_refmut, MapAreaType, MemorySet, MemorySetInner, VirtAddr,
    VirtPageNum,
};
use crate::signal::{SigTable, SignalFlags};
use crate::sync::{Condvar, Mutex, Semaphore, UPSafeCell};
use crate::task::heap_bottom_from_id;
use crate::task::id::tid_dealloc;
use crate::timer::get_time;
use crate::users::{current_user, User};
use crate::utils::{get_abs_path, is_abs_path, SysErrNo};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::cell::RefMut;
#[cfg(target_arch = "loongarch64")]
use loongarch64::register::pgdl;

/// Process Control Block
pub struct ProcessControlBlock {
    ///ppid
    pub ppid: usize,
    /// immutable
    pub pid: usize,
    /// immutable default user
    pub user: Arc<User>,
    /// mutable
    inner: UPSafeCell<ProcessControlBlockInner>,
}

/// Inner of Process Control Block
pub struct ProcessControlBlockInner {
    /// is zombie?
    pub is_zombie: bool,
    /// memory set(address space)
    pub memory_set: Arc<MemorySet>,
    /// parent process
    pub parent: Option<Weak<ProcessControlBlock>>,
    /// children process
    pub children: Vec<Arc<ProcessControlBlock>>,
    /// exit code
    pub exit_code: i32,
    /// file descriptor table
    pub fd_table: Arc<FdTable>,
    ///
    pub fs_info: Arc<FsInfo>,
    /// signal flags
    pub signals: SignalFlags,
    /// tasks(also known as threads)
    pub tasks: Vec<Option<Arc<TaskControlBlock>>>,
    /// task resource allocator
    pub task_res_allocator: RecycleAllocator,
    /// mutex list
    pub mutex_list: Vec<Option<Arc<dyn Mutex>>>,
    /// semaphore list
    pub semaphore_list: Vec<Option<Arc<Semaphore>>>,
    /// condvar list
    pub condvar_list: Vec<Option<Arc<Condvar>>>,
    /// priority
    pub priority: usize,
    /// stride
    pub stride: Stride,
    /// process tms
    pub tms: Tms,
    /// signal table
    pub sig_table: Arc<SigTable>,
    /// signal mask
    pub sig_mask: SignalFlags,
    /// signal pending
    pub sig_pending: SignalFlags,
    /// clear child tid
    pub clear_child_tid: usize,
    //heap id
    pub heap_id: usize,
    //heap bottom
    pub heap_bottom: usize,
    //heap top
    pub heap_top: usize,
    //
    pub robust_list: RobustList,
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
    /// set utime
    pub fn set_utime(&mut self, in_kernel_time: usize) {
        self.tms.inner.tms_utime = in_kernel_time - self.tms.begin_urun_time;
        if let Some(parent) = self.parent.as_mut() {
            if let Some(p) = parent.upgrade() {
                p.inner_exclusive_access()
                    .tms
                    .set_cutime(self.tms.inner.tms_utime);
                p.inner_exclusive_access()
                    .tms
                    .set_cstime(self.tms.one_stime);
            }
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
    pub fn get_abs_path(&self, dirfd: isize, path: &str) -> Result<String, SysErrNo> {
        if is_abs_path(path) {
            Ok(get_abs_path("/", path))
        } else if dirfd != -100 {
            let dirfd = dirfd as usize;
            if let Some(file) = self.fd_table.try_get(dirfd) {
                let base_path = file.file()?.inode.path();
                if path.is_empty() {
                    Ok(base_path)
                } else {
                    Ok(get_abs_path(&base_path, path))
                }
            } else {
                Err(SysErrNo::EINVAL)
            }
        } else {
            Ok(get_abs_path(self.fs_info.cwd(), path))
        }
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
            //debug!("in pcb brk, append is : {}", append);
            let append_vpn: VirtPageNum = (append / PAGE_SIZE + 1).into();
            //debug!("in pcb brk, append vpn is : {}", append_vpn.0);
            let hp_top_vpn: VirtPageNum = ((inner.heap_bottom + USER_HEAP_SIZE) / PAGE_SIZE).into();
            if append_vpn >= hp_top_vpn {
                debug!("user heap overflow at : {}", append);
                return 2;
            }
            debug!("in pcb brk, to append to");
            area.append_to(&mut inner.memory_set.get_mut().page_table, append_vpn);
            //area.vpn_range = VPNRange::new((inner.heap_bottom / PAGE_SIZE).into(), append_vpn);
            #[cfg(target_arch = "loongarch64")]
            flush_tlb();
            inner.heap_top = append;
        }
        inner.heap_top
    }
    /// new process from elf file
    pub fn new(elf_data: &[u8]) -> Arc<Self> {
        // memory_set with elf program headers/trampoline/trap context/user stack
        // debug!("kernel: create process from elf data, size = {}", elf_data.len());
        let heap_id = heap_id_alloc();
        let (memory_set, heap_bottom, entry_point, _) = MemorySet::from_elf(elf_data, heap_id);
        //info!("kernel: create process from elf data, size = {}, ustack_base = {:#x}, entry_point = {:#x}",
        //    elf_data.len(), ustack_base, entry_point);
        // allocate a pid
        debug!("in pcb new, from elf ok");
        let user = current_user().unwrap();
        //let pid_handle = pid_alloc().0;

        let process = Arc::new(Self {
            ppid: 0,
            pid: 0,
            user,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    heap_id,
                    is_zombie: false,
                    memory_set: Arc::new(memory_set),
                    parent: None,
                    children: Vec::new(),
                    exit_code: 0,
                    fd_table: Arc::new(FdTable::new_with_stdio()),
                    fs_info: Arc::new(FsInfo::new(String::from("/"))),
                    signals: SignalFlags::empty(),
                    tasks: Vec::new(),
                    task_res_allocator: RecycleAllocator::new(0),
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
                })
            },
        });
        info!("in pcb new, the heap bottom is : {}", heap_bottom);
        // create a main thread, we should allocate ustack and trap_cx here
        let task = Arc::new(TaskControlBlock::new(Arc::clone(&process), true, 0));
        // debug!("kernel: finish create main thread.");
        // prepare trap_cx of main thread
        let task_inner = task.inner_exclusive_access();
        let trap_cx = task_inner.get_trap_cx();
        let ustack_top = task_inner.ustack_top(true);
        #[cfg(target_arch = "riscv64")]
        let kstack_top = task.kstack.get_top();
        drop(task_inner);
        //info!("ustack_top = {:#x}, kstack_top = {:#x}", ustack_top, kstack_top);

        // debug!("kernel: create main thread, pid = {}", process.getpid());
        // la 在内核栈上压入trap上下文，与rcore实现不同
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            ustack_top,
            #[cfg(target_arch = "riscv64")]
            KERNEL_SPACE.exclusive_access().token(),
            #[cfg(target_arch = "riscv64")]
            kstack_top,
            #[cfg(target_arch = "riscv64")]
            (trap_handler as usize),
        );
        // add main thread to the process
        let mut process_inner = process.inner_exclusive_access();
        process_inner.tasks.push(Some(Arc::clone(&task)));
        drop(process_inner);
        insert_into_pid2process(process.getpid(), Arc::clone(&process));
        // add main thread to scheduler
        debug!(
            "kernel: add main thread to scheduler, pid = {}",
            process.getpid()
        );
        add_task(task);
        process
    }

    /// Only support processes with a single thread.
    pub fn exec(self: &Arc<Self>, elf_data: &[u8], args: Vec<String>, env: &mut Vec<String>) {
        //trace!("kernel: exec");
        debug!("kernel: exec, pid = {}", self.getpid());
        assert_eq!(self.inner_exclusive_access().thread_count(), 1);
        let heap_id = heap_id_alloc();
        let (memory_set, user_heap_bottom, entry_point, mut aux) =
            MemorySet::from_elf(elf_data, heap_id);
        let new_token = memory_set.token();
        let mut inner = self.inner_exclusive_access();
        inner.memory_set = Arc::new(memory_set);
        inner.heap_id = heap_id;
        //inner.memory_set.activate();
        debug!("pcb exec, get memory set ok");
        // if inner.clear_child_tid != 0 {
        //     *translated_refmut(new_token, inner.clear_child_tid as *mut u32) = 0;
        //     //data_flow!({ *(task_inner.clear_child_tid as *mut u32) = 0 });
        // }
        //debug!("clear child tid ok");
        inner.sig_table = Arc::new(SigTable::new());
        let fd_table = Arc::new(FdTable::from_another(&inner.fd_table));
        inner.fd_table = fd_table;
        inner.fd_table.close_on_exec();
        inner.sig_mask = SignalFlags::empty();
        inner.sig_pending = SignalFlags::empty();
        inner.tms = Tms::new();

        inner.heap_id = heap_id;
        inner.heap_bottom = user_heap_bottom;
        inner.heap_top = user_heap_bottom;
        drop(inner);
        // then we alloc user resource for main thread again
        // since memory_set has been changed
        //trace!("kernel: exec .. alloc user resource for main thread again");
        let task = self.inner_exclusive_access().get_task(0);
        task.alloc_user_res();
        // #[cfg(target_arch = "riscv64")]
        // task.set_user_trap();
        let trap_cx_ppn = task.trap_cx_ppn(task.tid());
        let mut task_inner = task.inner_exclusive_access();

        debug!(
            "kernel: exec .. alloc user resource for main thread again, pid = {}",
            self.getpid()
        );
        #[cfg(target_arch = "riscv64")]
        {
            task_inner.trap_cx_ppn = trap_cx_ppn;
            debug!("in pcb exec, trap cx ppn is : {}", task_inner.trap_cx_ppn.0);
        }
        // push arguments on user stack
        let mut user_sp = task_inner.ustack_top(true) as usize;
        info!("in pcb exec, initial user_sp = {}", user_sp);

        //      00000000000100b0 <main>:
        //          100b0: 39 71        	addi	sp, sp, -0x40  ; 分配栈空间
        //          100b2: 06 fc        	sd	ra, 0x38(sp)   ; 保存返回地址 ra
        //          100b4: 22 f8        	sd	s0, 0x30(sp)   ; 保存基址指针 fp (previous fp)
        //          100b6: 80 00        	addi	s0, sp, 0x40  ; s0 指向栈空间顶部 fp
        //          100b8: aa 87        	mv	a5, a0          ; a5 = argc
        //          100ba: 23 30 b4 fc  	sd	a1, -0x40(s0)  ; argv[0] 的地址
        //          100be: 23 26 f4 fc  	sw	a5, -0x34(s0)  ; argc 比 argv 处于更高的地址

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
            let p = user_sp + i;
            *translated_refmut(new_token, p as *mut u8) = (i * 2) as u8;
        }
        user_sp -= user_sp % 16;
        //aux
        aux.push(Aux::new(AuxType::EXECFN, argv[0]));
        aux.push(Aux::new(AuxType::NULL, 0));
        for aux in aux.iter().rev() {
            user_sp -= core::mem::size_of::<Aux>();
            let p = user_sp;
            let pp = user_sp + size;
            *translated_refmut(new_token, p as *mut usize) = aux.aux_type as usize;
            *translated_refmut(new_token, pp as *mut usize) = aux.value;
        }
        let aux_base = user_sp;

        //env指针
        //env指针空间
        user_sp -= envp.len() * size;
        let env_base = user_sp;
        for i in 0..envp.len() {
            let p = user_sp + i * size;
            *translated_refmut(new_token, p as *mut usize) = envp[i];
        }

        //args 指针
        //args指针空间
        user_sp -= argv.len() * size;
        let argv_base = user_sp;
        for i in 0..argv.len() {
            let p = user_sp + i * size;
            *translated_refmut(new_token, p as *mut usize) = argv[i];
        }

        //获取argc
        let args_len = args.len();
        //debug!("the args len is :{}", args_len);
        //设置argc
        user_sp -= size;
        *translated_refmut(new_token, user_sp as *mut usize) = args.len().into();
        //对齐地址
        user_sp -= user_sp % size;

        // initialize trap_cx
        debug!("init context");
        let mut trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            #[cfg(target_arch = "riscv64")]
            KERNEL_SPACE.exclusive_access().token(),
            #[cfg(target_arch = "riscv64")]
            task.kstack.get_top(),
            #[cfg(target_arch = "riscv64")]
            (trap_handler as usize),
        );
        #[cfg(target_arch = "riscv64")]
        {
            trap_cx.x[10] = args_len; // a0, the same with previous stack frame
            trap_cx.x[11] = argv_base; // a1
            trap_cx.x[12] = env_base;
            trap_cx.x[13] = aux_base;
        }
        #[cfg(target_arch = "loongarch64")]
        {
            trap_cx.x[4] = args_len;
            trap_cx.x[5] = argv_base;
            trap_cx.x[6] = env_base;
            trap_cx.x[7] = aux_base;
        }
        *task_inner.get_trap_cx() = trap_cx;

        #[cfg(target_arch = "loongarch64")]
        {
            //由于切换了地址空间，因此之前的ASID对应的地址空间将不会再有用，
            // 因此这里需要将TLB中的内容无效掉
            let pid = self.getpid();
            unsafe {
                asm!("invtlb 0x4,{},$r0",in(reg) pid);
            }
            // 设置新的pgdl
            let pgd = new_token << PAGE_SIZE_BITS;
            // Pgdl::read().set_val(pgd).write(); //设置新的页基址
            pgdl::set_base(pgd); //设置新的页基址
        }
        debug!("(ProecessControlBlock, exec) return, ok");
    }

    /// Only support processes with a single thread.
    pub fn fork(
        self: &Arc<Self>,
        flags: CloneFlags,
        _stack: usize,
        _parent_tid: *mut u32,
        _tls: usize,
        child_tid: *mut u32,
    ) -> Arc<Self> {
        //unimplemented!()
        let user = self.user.clone();
        let mut parent = self.inner_exclusive_access();
        let parent_tid = parent.get_task(0).tid();
        assert_eq!(parent.thread_count(), 1);

        // 检查是否共享虚拟内存
        let memory_set = if flags.contains(CloneFlags::CLONE_VM) {
            Arc::clone(&parent.memory_set)
        } else {
            Arc::new(MemorySet::from_existed_user(&parent.memory_set))
        };
        debug!("get memory set ok");
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
        let sig_pending = SignalFlags::empty();

        let clear_child_tid = if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
            child_tid as usize
        } else {
            0
        };
        // alloc a pid
        let pid: usize;
        let sig_mask: SignalFlags;

        let creat_thread = flags.contains(CloneFlags::CLONE_THREAD);

        if creat_thread {
            debug!(
                "(ProcessControlBlock, fork) creat thread, need tcb, not need pcb, to implement"
            );
            sig_mask = SignalFlags::empty();

            // let child = Arc::new(Self {
            //     ppid: pid,
            //     pid,
            //     user,
            //     inner: unsafe {
            //         UPSafeCell::new(ProcessControlBlockInner {
            //             heap_id: parent.heap_id,
            //             is_zombie: false,
            //             clear_child_tid,
            //             memory_set: memory_set,
            //             fs_info,
            //             parent: Some(Arc::downgrade(self)),
            //             children: Vec::new(),
            //             exit_code: 0,
            //             fd_table: new_fd_table,
            //             signals: SignalFlags::empty(),
            //             tasks: Vec::new(),
            //             task_res_allocator: RecycleAllocator::new(0),
            //             mutex_list: Vec::new(),
            //             semaphore_list: Vec::new(),
            //             condvar_list: Vec::new(),
            //             priority: 16,
            //             stride: Stride::default(),
            //             tms: Tms::new(),
            //             sig_mask,
            //             sig_pending,
            //             sig_table,
            //             heap_bottom: parent.heap_bottom,
            //             heap_top: parent.heap_top,
            //             robust_list: RobustList::default(),
            //         })
            //     },
            // });
            // child
            let task = Arc::new(TaskControlBlock::new(Arc::clone(self), true, parent_tid));
            parent.tasks.push(Some(Arc::clone(&task)));
            self.clone()
        } else {
            info!("(ProcessControlBlock, fork) forking...");
            pid = pid_alloc().0;
            let heap_id = heap_id_alloc();
            let heap_bottom = heap_bottom_from_id(heap_id);
            //ppid = self.pid;
            //timer = Arc::new(Timer::new());
            sig_mask = parent.sig_mask.clone();
            info!("(ProcessControlBlock, fork) pid = {}", pid);
            // create child process pcb
            let child = Arc::new(Self {
                ppid: self.pid,
                pid,
                user,
                inner: unsafe {
                    UPSafeCell::new(ProcessControlBlockInner {
                        is_zombie: false,
                        clear_child_tid,
                        memory_set: memory_set,
                        fs_info,
                        parent: Some(Arc::downgrade(self)),
                        children: Vec::new(),
                        exit_code: 0,
                        fd_table: new_fd_table,
                        signals: SignalFlags::empty(),
                        tasks: Vec::new(),
                        task_res_allocator: RecycleAllocator::new(0),
                        mutex_list: Vec::new(),
                        semaphore_list: Vec::new(),
                        condvar_list: Vec::new(),
                        priority: 16,
                        stride: Stride::default(),
                        tms: Tms::new(),
                        sig_mask,
                        sig_pending,
                        sig_table,
                        heap_id,
                        heap_bottom: heap_bottom,
                        heap_top: heap_bottom,
                        robust_list: RobustList::default(),
                    })
                },
            });
            // add child
            parent.children.push(Arc::clone(&child));
            // create main thread of child process
            let task = Arc::new(TaskControlBlock::new(Arc::clone(&child), false, parent_tid));
            let mut child_inner = child.inner_exclusive_access();
            child_inner.tasks.push(Some(Arc::clone(&task)));
            //child_inner.memory_set.clone_trap(&parent);

            if flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
                let child_token = child_inner.get_user_token();
                put_data(child_token, child_tid, task.tid() as u32);
            }
            drop(child_inner);

            #[cfg(target_arch = "riscv64")]
            {
                let task_inner = task.inner_exclusive_access();
                let trap_cx = task_inner.get_trap_cx();
                trap_cx.x[10] = 0;
                trap_cx.kernel_sp = task.kstack.get_top();
            }
            // modify kstack_top in trap_cx of this thread
            #[cfg(target_arch = "loongarch64")]
            {
                let mut kstack = &mut task.inner_exclusive_access().kstack;
                // 修改trap_cx的内容，使其保持与父进程相同
                // 这需要拷贝父进程的主线程的内核栈到子进程的内核栈中
                let trap_cx = kstack.get_trap_cx();
                trap_cx.x[4] = 0; // a0, the same with
                kstack.copy_from_other(&parent.get_task(0).inner_exclusive_access().kstack);
            }

            insert_into_pid2process(child.getpid(), Arc::clone(&child));
            // add this thread to scheduler
            add_task(task);
            child
        }
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

bitflags! {
    /// Open file flags
    pub struct CloneFlags: u32 {
        ///
        const SIGCHLD = (1 << 4) | (1 << 0);
        ///set if VM shared between processes
        const CLONE_VM = 1 << 8;
        ///set if fs info shared between processes
        const CLONE_FS = 1 << 9;
        ///set if open files shared between processes
        const CLONE_FILES = 1 << 10;
        ///set if signal handlers and blocked signals shared
        const CLONE_SIGHAND = 1 << 11;
        ///set if a pidfd should be placed in parent
        const CLONE_PIDFD = 1 << 12;
        ///set if we want to let tracing continue on the child too
        const CLONE_PTRACE = 1 << 13;
        ///set if the parent wants the child to wake it up on mm_release
        const CLONE_VFORK = 1 << 14;
        ///set if we want to have the same parent as the cloner
        const CLONE_PARENT = 1 << 15;
        ///Same thread group?
        const CLONE_THREAD = 1 << 16;
        ///New mount namespace group
        const CLONE_NEWNS = 1 << 17;
        ///share system V SEM_UNDO semantics
        const CLONE_SYSVSEM = 1 << 18;
        ///create a new TLS for the child
        const CLONE_SETTLS = 1 << 19;
        ///set the TID in the parent
        const CLONE_PARENT_SETTID = 1 << 20;
        ///clear the TID in the child
        const CLONE_CHILD_CLEARTID = 1 << 21;
        ///Unused, ignored
        const CLONE_DETACHED = 1 << 22;
        ///set if the tracing process can't force CLONE_PTRACE on this clone
        const CLONE_UNTRACED = 1 << 23;
        ///set the TID in the child
        const CLONE_CHILD_SETTID = 1 << 24;
        ///New cgroup namespace
        const CLONE_NEWCGROUP = 1 << 25;
        ///New utsname namespace
        const CLONE_NEWUTS = 1 << 26;
        ///New ipc namespace
        const CLONE_NEWIPC = 1 << 27;
        /// New user namespace
        const CLONE_NEWUSER = 1 << 28;
        ///New pid namespace
        const CLONE_NEWPID = 1 << 29;
        ///New network namespace
        const CLONE_NEWNET = 1 << 30;
        ///Clone io context
        const CLONE_IO = 1 << 31;
    }
}
