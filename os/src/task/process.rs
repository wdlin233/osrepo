//! Implementation of  [`ProcessControlBlock`]

use super::id::RecycleAllocator;
use super::manager::insert_into_pid2process;
use super::TaskControlBlock;
use super::{add_task, SignalFlags};
use super::{pid_alloc, PidHandle};
use super::stride::Stride;
use crate::fs::{File, Stdin, Stdout};
use crate::mm::{MemorySet, KERNEL_SPACE, translated_refmut};
use crate::sync::{Condvar, Mutex, Semaphore, UPSafeCell};
use crate::trap::{trap_handler, TrapContext};
<<<<<<< HEAD
use crate::loaders::ElfLoader;
use crate::timer::get_time;
use crate::users::{User,current_user};
=======
>>>>>>> master
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefMut;
use core::arch::asm;
use crate::timer::get_time;
#[cfg(target_arch = "loongarch64")]
use loongarch64::register::pgdl;
#[cfg(target_arch = "loongarch64")]
use crate::config::PAGE_SIZE_BITS;

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
    pub memory_set: MemorySet,
    /// parent process
    pub parent: Option<Weak<ProcessControlBlock>>,
    /// children process
    pub children: Vec<Arc<ProcessControlBlock>>,
    /// exit code
    pub exit_code: i32,
    /// file descriptor table
    pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
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
}

///record process times
#[derive(Debug,Copy,Clone)]
pub struct Tms {
    /// when a process run in user
    pub begin_urun_time: usize,
    /// syscall in one time
    pub one_stime: usize,
    /// inner
    pub inner: TmsInner,
}

/// tms interface
#[derive(Debug,Copy,Clone)]
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
    pub fn new()->Self {
        Tms {
            begin_urun_time:0,
            one_stime:0,
            inner: TmsInner {
                tms_utime:0,
                tms_stime:0,
                tms_cutime:0,
                tms_cstime:0,
            },
        }
    }
    /// when a process was scheduled,record the time
    pub fn set_begin(&mut self){
        self.begin_urun_time = get_time();
    }
    /// cutime 
    pub fn set_cutime(&mut self,cutime: usize){
        self.inner.tms_cutime += cutime;
    }
    /// cstime
    pub fn set_cstime(&mut self,cstime: usize){
        self.inner.tms_cstime +=cstime;
    }
    
}


impl ProcessControlBlockInner {
    /// set utime
    pub fn set_utime(&mut self,in_kernel_time: usize){
        self.tms.inner.tms_utime = in_kernel_time - self.tms.begin_urun_time;
        if let Some(parent) = self.parent.as_mut() {
            parent.upgrade().unwrap().inner_exclusive_access().tms.set_cutime(self.tms.inner.tms_utime);
            parent.upgrade().unwrap().inner_exclusive_access().tms.set_cstime(self.tms.one_stime);
        }
        self.tms.one_stime = 0;
    }
    
    /// stime is this out_kernel_time - this in_kernel_time
    pub fn set_stime(&mut self,in_kernel_time: usize,out_kernel_time: usize){
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
    /// allocate a new file descriptor
    pub fn alloc_fd(&mut self) -> usize {
        if let Some(fd) = (0..self.fd_table.len()).find(|fd| self.fd_table[*fd].is_none()) {
            fd
        } else {
            self.fd_table.push(None);
            self.fd_table.len() - 1
        }
    }
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
}

impl ProcessControlBlock {
    /// inner_exclusive_access
    pub fn inner_exclusive_access(&self) -> RefMut<'_, ProcessControlBlockInner> {
        self.inner.exclusive_access()
    }
    /// new process from elf file
    pub fn new(elf_data: &[u8]) -> Arc<Self> {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, ustack_base, entry_point) = MemorySet::from_elf(elf_data);
        // allocate a pid
        let user = current_user().unwrap();
        let pid_handle = pid_alloc();
        let process = Arc::new(Self {
            pid: pid_handle,
            user,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    is_zombie: false,
                    memory_set,
                    parent: None,
                    children: Vec::new(),
                    exit_code: 0,
                    fd_table: vec![
                        // 0 -> stdin
                        Some(Arc::new(Stdin)),
                        // 1 -> stdout
                        Some(Arc::new(Stdout)),
                        // 2 -> stderr
                        Some(Arc::new(Stdout)),
                    ],
                    signals: SignalFlags::empty(),
                    tasks: Vec::new(),
                    task_res_allocator: RecycleAllocator::new(),
                    mutex_list: Vec::new(),
                    semaphore_list: Vec::new(),
                    condvar_list: Vec::new(),
                    priority: 16,
                    stride: Stride::default(),
                    tms: Tms::new(),
                })
            },
        });
        // debug!("kernel: create process, pid = {}", process.getpid());
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

        // debug!("kernel: create main thread, pid = {}", process.getpid());
        #[cfg(target_arch = "riscv64")]
        {
            *trap_cx = TrapContext::app_init_context(
                entry_point,
                ustack_top,
                KERNEL_SPACE.exclusive_access().token(),
                kstack_top,
                trap_handler as usize,
            );
        }
        #[cfg(target_arch = "loongarch64")]
        {
            // waring:在内核栈上压入trap上下文，与rcore实现不同
            *trap_cx = TrapContext::app_init_context(entry_point, ustack_top);
        }
        // add main thread to the process
        let mut process_inner = process.inner_exclusive_access();
        process_inner.tasks.push(Some(Arc::clone(&task)));
        drop(process_inner);
        insert_into_pid2process(process.getpid(), Arc::clone(&process));
        // add main thread to scheduler
        debug!("kernel: add main thread to scheduler, pid = {}", process.getpid());
        add_task(task);
        process
    }

    /// Only support processes with a single thread.
    pub fn exec(self: &Arc<Self>, elf_data: &[u8], args: Vec<String>) {
        //trace!("kernel: exec");
        assert_eq!(self.inner_exclusive_access().thread_count(), 1);
        // memory_set with elf program headers/trampoline/trap context/user stack
        //trace!("kernel: exec .. MemorySet::from_elf");
        let (memory_set, ustack_base, entry_point) = MemorySet::from_elf(elf_data);
        let new_token = memory_set.token();
        let args_len = args.len();
        // substitute memory_set
        //trace!("kernel: exec .. substitute memory_set");
        self.inner_exclusive_access().memory_set = memory_set;
        // then we alloc user resource for main thread again
        // since memory_set has been changed
        //trace!("kernel: exec .. alloc user resource for main thread again");
        let task = self.inner_exclusive_access().get_task(0);
        let mut task_inner = task.inner_exclusive_access();
        task_inner.res.as_mut().unwrap().ustack_base = ustack_base;
        task_inner.res.as_mut().unwrap().alloc_user_res();
        #[cfg(target_arch = "riscv64")]
        {
            task_inner.trap_cx_ppn = task_inner.res.as_mut().unwrap().trap_cx_ppn();
        }

        // push arguments on user stack
        //trace!("kernel: exec .. push arguments on user stack");
        let mut user_sp = task_inner.res.as_mut().unwrap().ustack_top() as usize;
        //trace!("initial user_sp = {}", user_sp);
        //      00000000000100b0 <main>:
//          100b0: 39 71        	addi	sp, sp, -0x40  ; 分配栈空间
//          100b2: 06 fc        	sd	ra, 0x38(sp)   ; 保存返回地址 ra
//          100b4: 22 f8        	sd	s0, 0x30(sp)   ; 保存基址指针 fp (previous fp)
//          100b6: 80 00        	addi	s0, sp, 0x40  ; s0 指向栈空间顶部 fp
//          100b8: aa 87        	mv	a5, a0          ; a5 = argc
//          100ba: 23 30 b4 fc  	sd	a1, -0x40(s0)  ; argv[0] 的地址
//          100be: 23 26 f4 fc  	sw	a5, -0x34(s0)  ; argc 比 argv 处于更高的地址

        // Reserve memory space for the stack
        for i in 0..args.len() {
            user_sp -= args[i].len() + 1;
        }
        let argv_st = user_sp;
        // make the user_sp aligned to 8B for k210 platform
        user_sp -= user_sp % core::mem::size_of::<usize>();
        user_sp -= (args.len() + 1) * core::mem::size_of::<usize>();
        let argv_base = user_sp;

        let mut argv: Vec<_> = (0..=args.len())
            .map(|arg| {
                translated_refmut(
                    new_token,
                    (argv_base + arg * core::mem::size_of::<usize>()) as *mut usize,
                )
            })
            .collect();

        // Set stack parameters
        // from low addr to high addr
        // argv content
        user_sp = argv_st;
        for i in 0..args.len() {
            *argv[i] = user_sp;
            let mut p = user_sp;
            for c in args[i].as_bytes() {
                *translated_refmut(new_token, p as *mut u8) = *c;
                p += 1;
            }
            *translated_refmut(new_token, p as *mut u8) = 0;
            user_sp += args[i].len() + 1;
        }        
        *argv[args.len()] = 0;

        // argc
        user_sp = argv_base;
        *translated_refmut(
            new_token,
            (user_sp - core::mem::size_of::<usize>()) as *mut usize,
        ) = args.len().into();
        user_sp -= core::mem::size_of::<usize>(); 

        // initialize trap_cx
        //trace!("kernel: exec .. initialize trap_cx");
        #[cfg(target_arch = "riscv64")]
        let mut trap_cx = TrapContext::app_init_context(
                entry_point,
                user_sp,
                KERNEL_SPACE.exclusive_access().token(),
                task.kstack.get_top(),
                trap_handler as usize,
            );
        #[cfg(target_arch = "riscv64")]
        {
            trap_cx.x[10] = args_len; // a0, the same with previous stack frame
            trap_cx.x[11] = argv_base; // a1
        }
        #[cfg(target_arch = "loongarch64")]
        let mut trap_cx = TrapContext::app_init_context(entry_point, user_sp);
        #[cfg(target_arch = "loongarch64")]
        {
            trap_cx.x[4] = args_len;
            trap_cx.x[5] = user_sp + 8; // maybe
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
    }

    /// Only support processes with a single thread.
    pub fn fork(self: &Arc<Self>) -> Arc<Self> {
<<<<<<< HEAD
        let user = self.user.clone();
=======
        //trace!("kernel: fork");
>>>>>>> master
        let mut parent = self.inner_exclusive_access();
        assert_eq!(parent.thread_count(), 1);
        // clone parent's memory_set completely including trampoline/ustacks/trap_cxs
        let memory_set = MemorySet::from_existed_user(&parent.memory_set);
        // alloc a pid
        let pid = pid_alloc();
        // copy fd table
        let mut new_fd_table: Vec<Option<Arc<dyn File + Send + Sync>>> = Vec::new();
        for fd in parent.fd_table.iter() {
            if let Some(file) = fd {
                new_fd_table.push(Some(file.clone()));
            } else {
                new_fd_table.push(None);
            }
        }
        // create child process pcb
        let child = Arc::new(Self {
            pid,
            user,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    is_zombie: false,
                    memory_set,
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
                })
            },
        });
        // add child
        parent.children.push(Arc::clone(&child));
        // create main thread of child process
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
    pub fn getppid(&self)->usize {
        let inner = self.inner_exclusive_access();
        let parent = inner.parent.clone().unwrap();
        parent.upgrade().unwrap().getpid()
    }
    /// get default uid
    pub fn getuid(&self)->usize {
        self.user.getuid()
    }
    /// get default gid
    pub fn getgid(&self)->usize{
        self.user.getgid()
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