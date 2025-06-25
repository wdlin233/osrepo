//! Implementation of  [`ProcessControlBlock`]

use super::add_task;
use super::aux::{Aux, AuxType};
use super::id::RecycleAllocator;
use super::manager::insert_into_pid2process;
use super::stride::Stride;
use super::TaskControlBlock;
use super::{pid_alloc, PidHandle};
#[cfg(target_arch = "loongarch64")]
use crate::config::PAGE_SIZE_BITS;
use crate::config::USER_HEAP_SIZE;
use crate::fs::File;
use crate::fs::{FdTable, FsInfo, Stdin, Stdout};
use crate::hal::trap::{trap_handler, TrapContext};
#[cfg(target_arch = "riscv64")]
use crate::mm::KERNEL_SPACE;
use crate::mm::{flush_tlb, translated_refmut, MapAreaType, MemorySet, MemorySetInner, VPNRange, VirtPageNum};
use crate::signal::{SigTable, SignalFlags};
use crate::sync::{Condvar, Mutex, Semaphore, UPSafeCell};
use crate::task::{self, current_process};
use crate::timer::get_time;
use crate::users::{current_user, User};
use crate::utils::{get_abs_path, is_abs_path};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use virtio_drivers::PAGE_SIZE;
use core::arch::asm;
use core::cell::RefMut;
#[cfg(target_arch = "loongarch64")]
use loongarch64::register::pgdl;

/// Process Control Block
pub struct ProcessControlBlock {
    /// immutable
    pub pid: PidHandle,
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
    ///heap bottom
    pub heap_bottom: usize,
    ///program brk
    pub program_brk: usize,
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
    }
    /// deallocate a task id
    pub fn dealloc_tid(&mut self, tid: usize) {
        self.task_res_allocator.dealloc(tid)
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
}

impl ProcessControlBlock {
    /// inner_exclusive_access
    pub fn inner_exclusive_access(&self) -> RefMut<'_, ProcessControlBlockInner> {
        self.inner.exclusive_access()
    }
    /// new process from elf file
    pub fn new(elf_data: &[u8]) -> Arc<Self> {
        // memory_set with elf program headers/trampoline/trap context/user stack
        // debug!("kernel: create process from elf data, size = {}", elf_data.len());
        let (memory_set, ustack_base, entry_point, _) = MemorySetInner::from_elf(elf_data);
        info!("kernel: create process from elf data, size = {}, ustack_base = {:#x}, entry_point = {:#x}",
            elf_data.len(), ustack_base, entry_point);
        // allocate a pid
        let user = current_user().unwrap();
        let pid_handle = pid_alloc();
        let process = Arc::new(Self {
            pid: pid_handle,
            user,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    is_zombie: false,
                    memory_set: Arc::new(MemorySet::new(memory_set)),
                    parent: None,
                    children: Vec::new(),
                    exit_code: 0,
                    fd_table: Arc::new(FdTable::new_with_stdio()),
                    fs_info: Arc::new(FsInfo::new(String::from("/"))),
                    signals: SignalFlags::empty(),
                    tasks: Vec::new(),
                    task_res_allocator: RecycleAllocator::new(),
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
                    heap_bottom: ustack_base,
                    program_brk: ustack_base,
                })
            },
        });
        // create a main thread, we should allocate ustack and trap_cx here
        let task = Arc::new(TaskControlBlock::new(
            Arc::clone(&process),
            ustack_base,
            true,
        ));
        // debug!("kernel: finish create main thread.");
        // prepare trap_cx of main thread
        let task_inner = task.inner_exclusive_access();
        let trap_cx = task_inner.get_trap_cx();
        let ustack_top = task_inner.res.as_ref().unwrap().ustack_top();
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
    pub fn exec(self: &Arc<Self>, elf_data: &[u8], argv: Vec<String>, env: &mut Vec<String>) {
        //trace!("kernel: exec");
        //debug!("kernel: exec, pid = {}", self.getpid());
        assert_eq!(self.inner_exclusive_access().thread_count(), 1);
        let (memory_set, ustack_base, entry_point, mut auxv) = MemorySetInner::from_elf(elf_data);
        let token = memory_set.token();
        info!("kernel: exec, pid = {}, ustack_base = {:#x}, entry_point = {:#x}",
            self.getpid(), ustack_base, entry_point);
        
        self.inner_exclusive_access().memory_set = Arc::new(MemorySet::new(memory_set));
        // then we alloc user resource for main thread again
        // since memory_set has been changed
        //trace!("kernel: exec .. alloc user resource for main thread again");
        let task = self.inner_exclusive_access().get_task(0);
        let mut task_inner = task.inner_exclusive_access();
        task_inner.res.as_mut().unwrap().ustack_base = ustack_base;
        task_inner.res.as_mut().unwrap().alloc_user_res();
        debug!(
            "kernel: exec .. alloc user resource for main thread again, pid = {}",
            self.getpid()
        );
        #[cfg(target_arch = "riscv64")]
        {
            task_inner.trap_cx_ppn = task_inner.res.as_mut().unwrap().trap_cx_ppn();
        }
        // push arguments on user stack
        //trace!("kernel: exec .. push arguments on user stack");
        let mut user_sp = task_inner.res.as_mut().unwrap().ustack_top() as usize;
        info!("in pcb exec, initial user_sp = {:#x}", user_sp);

        // ref: https://articles.manugarg.com/aboutelfauxiliaryvectors.html
        // build user stack and push arguments.
        /* based on 32 bits, need to modify for 64 bits
    stack pointer ->  [ argc = number of args ]     4
                    [ argv[0] (pointer) ]         4   (program name)
                    [ argv[1] (pointer) ]         4
                    [ argv[..] (pointer) ]        4 * x
                    [ argv[n - 1] (pointer) ]     4
                    [ argv[n] (pointer) ]         4   (= NULL)

                    [ envp[0] (pointer) ]         4
                    [ envp[1] (pointer) ]         4
                    [ envp[..] (pointer) ]        4
                    [ envp[term] (pointer) ]      4   (= NULL)

                    [ auxv[0] (Elf32_auxv_t) ]    8
                    [ auxv[1] (Elf32_auxv_t) ]    8
                    [ auxv[..] (Elf32_auxv_t) ]   8
                    [ auxv[term] (Elf32_auxv_t) ] 8   (= AT_NULL vector)

                    [ padding ]                   0 - 16

                    [ argument ASCIIZ strings ]   >= 0
                    [ environment ASCIIZ str. ]   >= 0

  (0xbffffffc)      [ end marker ]                4   (= NULL)

  (0xc0000000)      < bottom of stack >           0   (virtual)
         */
        
        
        //环境变量内容入栈
        let mut envp = Vec::new();
        for env in env.iter() {
            user_sp -= env.len() + 1;
            envp.push(user_sp);
            for (j, c) in env.as_bytes().iter().enumerate() {
                unsafe {
                    *translated_refmut(token, (user_sp + j) as *mut u8) = *c;
                }
            }
            unsafe {
                *translated_refmut(token, (user_sp + env.len()) as *mut u8) = 0;
            }
        }
        envp.push(0);
        user_sp -= user_sp % size_of::<usize>();
        info!("in pcb exec, user_sp after envp = {:#x}", user_sp);

        //存放字符串首址的数组
        let mut argvp = Vec::new();
        for arg in argv.iter() {
            // 计算字符串在栈上的地址
            user_sp -= arg.len() + 1;
            argvp.push(user_sp);
            for (j, c) in arg.as_bytes().iter().enumerate() {
                unsafe {
                    *translated_refmut(token, (user_sp + j) as *mut u8) = *c;
                }
            }
            // 添加字符串末尾的 null 字符
            unsafe {
                *translated_refmut(token, (user_sp + arg.len()) as *mut u8) = 0;
            }
        }
        user_sp -= user_sp % size_of::<usize>(); //以8字节对齐
        argvp.push(0);
        info!("in pcb exec, user_sp after argvp = {:#x}", user_sp);

        //需要随便放16个字节，不知道干嘛用的。
        user_sp -= 16;
        auxv.push(Aux::new(AuxType::RANDOM, user_sp));
        for i in 0..0xf {
            unsafe {
                *translated_refmut(token, (user_sp + i) as *mut u8) = i as u8;
            }
        }
        user_sp -= user_sp % 16;
        info!("in pcb exec, user_sp after auxv random = {:#x}", user_sp);

        //将auxv放入栈中
        auxv.push(Aux::new(AuxType::EXECFN, argvp[0]));
        auxv.push(Aux::new(AuxType::NULL, 0));
        for aux in auxv.iter().rev() {
            user_sp -= size_of::<Aux>();
            unsafe {
                *translated_refmut(token, user_sp as *mut usize) = aux.aux_type as usize;
                *translated_refmut(token, (user_sp + size_of::<usize>()) as *mut usize) = aux.value;
            }
        }
        info!("in pcb exec, user_sp after auxv = {:#x}", user_sp);

        //将环境变量指针数组放入栈中
        user_sp -= envp.len() * size_of::<usize>();
        let envp_base = user_sp;
        for i in 0..envp.len() {
            unsafe {
                *translated_refmut(token, (user_sp + i * size_of::<usize>()) as *mut usize) = envp[i];
            }
        }

        // println!("arg pointers:");
        user_sp -= argvp.len() * size_of::<usize>();
        let argv_base = user_sp;
        //将参数指针数组放入栈中
        for i in 0..argvp.len() {
            unsafe {
                *translated_refmut(token, (user_sp + i * size_of::<usize>()) as *mut usize) = argvp[i];
            }
        }

        //将argc放入栈中
        user_sp -= size_of::<usize>();
        unsafe {
            *translated_refmut(token, user_sp as *mut usize) = argv.len();
        }

        //以8字节对齐
        user_sp -= user_sp % size_of::<usize>();
        info!("in pcb exec, user_sp after argv = {:#x}", user_sp);

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
            trap_cx.x[10] = argv.len(); // a0, the same with previous stack frame
            trap_cx.x[11] = argv_base; // a1
            trap_cx.x[12] = envp_base;
            //trap_cx.x[13] = aux_base; 应该在栈上传递？
        }
        #[cfg(target_arch = "loongarch64")]
        {
            trap_cx.x[4] = args_len;
            trap_cx.x[5] = argv_base; // maybe, or user_sp + 8
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
        debug!("in pcb, exec ok");
        self.inner_exclusive_access().heap_bottom = ustack_base;
        self.inner_exclusive_access().program_brk = ustack_base;
    }

    /// Only support processes with a single thread.
    pub fn fork(
        self: &Arc<Self>,
        flags: CloneFlags,
        stack: usize,
        _parent_tid: *mut u32,
        _tls: usize,
        child_pid: *mut u32,
    ) -> Arc<Self> {
        let user = self.user.clone();
        let mut parent = self.inner_exclusive_access();
        assert_eq!(parent.thread_count(), 1);

        // alloc a pid
        let pid = pid_alloc();

        // 检查是否共享虚拟内存
        //let memory_set = MemorySet::from_existed_user(&parent.memory_set);
        let memory_set = if flags.contains(CloneFlags::CLONE_VM) {
            Arc::clone(&parent.memory_set)
        } else {
            Arc::new(MemorySet::new(MemorySetInner::from_existed_user(
                &parent.memory_set,
            )))
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
        let sig_pending = SignalFlags::empty();

        let clear_child_tid = if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
            child_pid as usize
        } else {
            0
        };

        // 检查是否创建线程
        let mut sig_mask = SignalFlags::empty();
        if flags.contains(CloneFlags::CLONE_THREAD) {
            // 针对线程也有特定的处理，这里先跳过
            error!("kernel: fork with CLONE_THREAD is not supported yet");
            // pid = self.pid;
            // ppid = self.ppid;
            // timer = Arc::clone(&parent_inner.timer);
            //sig_mask = SignalFlags::empty();
        } else {
            // pid = tid_handle.0;
            // ppid = self.pid;
            // timer = Arc::new(Timer::new());
            sig_mask = parent.sig_mask.clone();
        }
        if flags.contains(CloneFlags::CLONE_PARENT) {
            error!("kernel: fork with CLONE_PARENT is not supported yet");
            //ppid = self.ppid;
        }

        // create child process pcb
        let child = Arc::new(Self {
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
                    task_res_allocator: RecycleAllocator::new(),
                    mutex_list: Vec::new(),
                    semaphore_list: Vec::new(),
                    condvar_list: Vec::new(),
                    priority: 16,
                    stride: Stride::default(),
                    tms: Tms::new(),
                    sig_mask,
                    sig_pending,
                    sig_table,
                    program_brk: parent.program_brk,
                    heap_bottom: parent.heap_bottom,
                })
            },
        });
        // add child
        parent.children.push(Arc::clone(&child));
        // create main thread of child process
        // 如果 CLONE_THREAD 是 true, 需要分配资源.
        let task = Arc::new(TaskControlBlock::new(
            Arc::clone(&child),
            parent
                .get_task(0)
                .inner_exclusive_access()
                .res
                .as_ref()
                .unwrap()
                .ustack_base(),
            // here we do not allocate trap_cx or ustack again
            // but mention that we allocate a new kstack here
            false,
        ));
        // attach task to child process
        let mut child_inner = child.inner_exclusive_access();
        child_inner.tasks.push(Some(Arc::clone(&task)));
        drop(child_inner);
        if stack != 0 {
            unimplemented!()
        }
        if flags.contains(CloneFlags::CLONE_SETTLS) {
            unimplemented!()
            // tp
            //trap_cx.gp.x[4] = tls;
        }
        // CLONE_CHILD_SETTID
        if flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
            unimplemented!()
            //let child_token = child_inner.user_token();
            //put_data(child_token, child_tid, child.tid() as u32);
        }

        // modify kstack_top in trap_cx of this thread
        #[cfg(target_arch = "riscv64")]
        let task_inner = task.inner_exclusive_access();
        #[cfg(target_arch = "loongarch64")]
        let mut task_inner = task.inner_exclusive_access();
        #[cfg(target_arch = "riscv64")]
        {
            let trap_cx = task_inner.get_trap_cx();
            trap_cx.kernel_sp = task.kstack.get_top();
        }
        #[cfg(target_arch = "loongarch64")]
        {
            // 修改trap_cx的内容，使其保持与父进程相同
            // 这需要拷贝父进程的主线程的内核栈到子进程的内核栈中
            task_inner
                .kstack
                .copy_from_other(&parent.get_task(0).inner_exclusive_access().kstack);
        }
        drop(task_inner);
        insert_into_pid2process(child.getpid(), Arc::clone(&child));
        // add this thread to scheduler
        add_task(task);
        child
    }
    /// get pid
    pub fn getpid(&self) -> usize {
        self.pid.0
    }
    /// get parent pid
    pub fn getppid(&self) -> usize {
        error!("kernel: getppid is not implemented yet");
        let inner = self.inner_exclusive_access();
        let parent = inner.parent.clone().unwrap();
        parent.upgrade().unwrap().getpid() + 1
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
    pub fn growproc(self: &mut Arc<Self>, grow_size: isize) -> usize {
        info!("in growproc,grow_size = {}", grow_size);
        let mut inner = self.inner_exclusive_access();
        if grow_size == 0 {
            return inner.program_brk;
        }
       let area = inner
            .memory_set
            .get_mut()
            .areas
            .iter_mut()
            .find(|area| area.area_type == MapAreaType::Brk)
            .unwrap();
        let growed_addr: usize = inner.program_brk + grow_size as usize;
        let shrinked_addr: usize = (inner.program_brk as isize + grow_size) as usize;
        let user_vpn_top: VirtPageNum =
            ((inner.heap_bottom + USER_HEAP_SIZE) / PAGE_SIZE).into();
        let growed_vpn: VirtPageNum = (growed_addr / PAGE_SIZE + 1).into();
        let shrinked_vpn: VirtPageNum = (shrinked_addr / PAGE_SIZE + 1).into();
        if grow_size > 0 {
            if growed_vpn >= user_vpn_top {
                panic!("USER_HEAP overflow as {:#X}!", growed_addr);
            }
            //因为是懒分配，只要改范围就行了
            area.vpn_range = VPNRange::new((inner.heap_bottom / PAGE_SIZE).into(), growed_vpn);
            inner.program_brk = growed_addr;
        } else {
            if shrinked_addr < inner.heap_bottom {
                panic!("USER_HEAP downflow at {:#X}!", shrinked_addr);
            }
            area.vpn_range =
                VPNRange::new((inner.heap_bottom / PAGE_SIZE).into(), shrinked_vpn);
            while !area.data_frames.is_empty() {
                let page = area.data_frames.pop_last().unwrap();
                if page.0 < growed_vpn {
                    area.data_frames.insert(page.0, page.1);
                    break;
                }
                inner.memory_set.get_mut().page_table.unmap(page.0);
            }
            inner.program_brk = shrinked_addr;
        }
        flush_tlb();
        inner.program_brk
    }
}

// impl ProcessControlBlock {
//     /// Create a new child process directly from the parent process
//     pub fn spwan(self: &Arc<Self>, elf_data: &[u8]) -> Arc<Self> {
//         let child = Arc::new(Self::new(elf_data));

//         child.inner_exclusive_access().parent = Some(Arc::downgrade(self));
//         self.inner_exclusive_access().children.push(Arc::clone(&child));

//         child
//     }
//     // seems a unnecessary syscall, tempolarily remove it
// }

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
