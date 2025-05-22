//! Implementation of  [`ProcessControlBlock`]

use super::id::RecycleAllocator;
use super::manager::insert_into_pid2process;
use super::signal::SignalActions;
use super::TaskControlBlock;
use super::{add_task, SignalFlags};
use super::{pid_alloc, PidHandle};
use super::stride::Stride;
use crate::fs::{File, Stdin, Stdout};
use crate::mm::MemorySet;
use crate::sync::{Condvar, Mutex, Semaphore, UPSafeCell};
use crate::loaders::ElfLoader;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use polyhal::PageTable;
use core::cell::RefMut;
use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};

/// Process Control Block
pub struct ProcessControlBlock {
    /// immutable
    pub pid: PidHandle,
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
    /// signal mask
    pub signal_mask: SignalFlags,
    // the signal which is being handling
    pub handling_sig: isize,
    // Signal actions
    pub signal_actions: SignalActions,
    // if the task is killed
    pub killed: bool,
    // if the task is frozen by a signal
    pub frozen: bool,
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
}

impl ProcessControlBlockInner {
    #[allow(unused)]
    /// get the address of app's page table
    pub fn get_user_token(&self) -> PageTable {
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
        let pid_handle = pid_alloc();
        let process = Arc::new(Self {
            pid: pid_handle,
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
                    signal_mask: SignalFlags::empty(),
                    handling_sig: -1,
                    signal_actions: SignalActions::default(),
                    killed: false,
                    frozen: false,
                    tasks: Vec::new(),
                    task_res_allocator: RecycleAllocator::new(),
                    mutex_list: Vec::new(),
                    semaphore_list: Vec::new(),
                    condvar_list: Vec::new(),
                    priority: 16,
                    stride: Stride::default(),
                })
            },
        });
        debug!("task: new process");
        // create a main thread, we should allocate ustack and trap_cx here
        let task = Arc::new(TaskControlBlock::new(
            Arc::clone(&process),
            ustack_base,
            true,
        ));
        // 这里之前存在一个问题
        debug!("prepare task");
        // prepare trap_cx of main thread
        let task_inner = task.inner_exclusive_access();
        let trap_cx = task_inner.get_trap_cx();
        let ustack_top = task_inner.res.as_ref().unwrap().ustack_top();
        //let kstack_top = task.kstack.get_top();
        drop(task_inner);
        trap_cx[TrapFrameArgs::SEPC] = entry_point;
        trap_cx[TrapFrameArgs::SP] = ustack_top;
        debug!("kernel: exec .. entry_point = {:#x}", entry_point);

        // add main thread to the process
        let mut process_inner = process.inner_exclusive_access();
        process_inner.tasks.push(Some(Arc::clone(&task)));
        drop(process_inner);
        insert_into_pid2process(process.getpid(), Arc::clone(&process));
        // add main thread to scheduler
        add_task(task);
        process
    }

    /// Only support processes with a single thread.
    pub fn exec(self: &Arc<Self>, elf_data: &[u8], args: Vec<String>) {
        trace!("kernel: exec");
        assert_eq!(self.inner_exclusive_access().thread_count(), 1);
        // memory_set with elf program headers/trampoline/trap context/user stack
        trace!("kernel: exec .. MemorySet::from_elf");
        let (memory_set, ustack_base, entry_point) = MemorySet::from_elf(elf_data);
        let new_token = memory_set.token();
        let args_len = args.len();
        // substitute memory_set
        trace!("kernel: exec .. substitute memory_set");
        self.inner_exclusive_access().memory_set = memory_set;
        // then we alloc user resource for main thread again
        // since memory_set has been changed
        trace!("kernel: exec .. alloc user resource for main thread again");
        let task = self.inner_exclusive_access().get_task(0);
        let mut task_inner = task.inner_exclusive_access();
        task_inner.res.as_mut().unwrap().ustack_base = ustack_base;
        task_inner.res.as_mut().unwrap().alloc_user_res();
        
        // FIXME: This is a temporary solution
        task_inner.trap_cx = TrapFrame::new();
        //task_inner.trap_cx = task_inner.res.as_mut().unwrap().trap_cx_ppn();
        
        // push arguments on user stack
        trace!("kernel: exec .. push arguments on user stack");
        let user_sp = task_inner.res.as_mut().unwrap().ustack_top();
        trace!("initial user_sp = {}", user_sp);
        let elf_loader = ElfLoader::new(elf_data).unwrap();
        let user_sp = elf_loader.init_stack(
            new_token,
            user_sp,
            args.clone(),
        ); 

        // initialize trap_cx
        trace!("kernel: exec .. initialize trap_cx");
        // initialize trap_cx
        let mut trap_cx = TrapFrame::new();
        trap_cx[TrapFrameArgs::SEPC] = entry_point;
        trap_cx[TrapFrameArgs::SP] = user_sp;
        trap_cx[TrapFrameArgs::ARG0] = args_len; // a0, the same with previous stack frame
        trap_cx[TrapFrameArgs::ARG1] = user_sp + 8; // a1
        *task_inner.get_trap_cx() = trap_cx;
    }

    /// Only support processes with a single thread.
    pub fn fork(self: &Arc<Self>) -> Arc<Self> {
        trace!("kernel: fork");
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
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    is_zombie: false,
                    memory_set,
                    parent: Some(Arc::downgrade(self)),
                    children: Vec::new(),
                    exit_code: 0,
                    fd_table: new_fd_table,
                    signals: SignalFlags::empty(),
                    signal_mask: parent.signal_mask,
                    handling_sig: -1,
                    signal_actions: parent.signal_actions.clone(),
                    killed: false,
                    frozen: false,
                    tasks: Vec::new(),
                    task_res_allocator: RecycleAllocator::new(),
                    mutex_list: Vec::new(),
                    semaphore_list: Vec::new(),
                    condvar_list: Vec::new(),
                    priority: 16,
                    stride: Stride::default(),
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
        // TEST: delete this part
        // let task_inner = task.inner_exclusive_access();
        // let trap_cx = task_inner.get_trap_cx();
        // trap_cx.kernel_sp = task.kstack.get_top();
        // drop(task_inner);
        insert_into_pid2process(child.getpid(), Arc::clone(&child));
        // add this thread to scheduler
        add_task(task);
        child
    }
    /// get pid
    pub fn getpid(&self) -> usize {
        self.pid.0
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