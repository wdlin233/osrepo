//! Allocator for pid, task user resource, kernel stack using a simple recycle strategy.

use super::ProcessControlBlock;
use crate::config::{KERNEL_STACK_SIZE, PAGE_SIZE, TRAMPOLINE, TRAP_CONTEXT_BASE, USER_STACK_SIZE};
use crate::mm::{MapPermission, PhysPageNum, VirtAddr, KERNEL_SPACE};
use crate::sync::UPSafeCell;
use crate::hal::trap::TrapContext;
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use lazy_static::*;
use crate::phys_to_virt;
use crate::mm::{FrameTracker, frame_alloc, PhysAddr};

/// Allocator with a simple recycle strategy
pub struct RecycleAllocator {
    current: usize,
    recycled: Vec<usize>,
}

impl RecycleAllocator {
    /// Create a new allocator
    pub fn new() -> Self {
        RecycleAllocator {
            current: 0,
            recycled: Vec::new(),
        }
    }
    /// allocate a new item
    pub fn alloc(&mut self) -> usize {
        if let Some(id) = self.recycled.pop() {
            id
        } else {
            self.current += 1;
            self.current - 1
        }
    }
    /// deallocate an item
    pub fn dealloc(&mut self, id: usize) {
        assert!(id < self.current);
        assert!(
            !self.recycled.iter().any(|i| *i == id),
            "id {} has been deallocated!",
            id
        );
        self.recycled.push(id);
    }
}

lazy_static! {
    /// Glocal allocator for pid
    static ref PID_ALLOCATOR: UPSafeCell<RecycleAllocator> =
        unsafe { UPSafeCell::new(RecycleAllocator::new()) };
}
#[cfg(target_arch = "riscv64")]
lazy_static! {
    /// Global allocator for kernel stack
    static ref KSTACK_ALLOCATOR: UPSafeCell<RecycleAllocator> =
        unsafe { UPSafeCell::new(RecycleAllocator::new()) };
}

/// The idle task's pid is 0
pub const IDLE_PID: usize = 0;

/// A handle to a pid
pub struct PidHandle(pub usize);

impl Drop for PidHandle {
    fn drop(&mut self) {
        // trace!("drop pid {}", self.0);
        PID_ALLOCATOR.exclusive_access().dealloc(self.0);
    }
}

/// Allocate a new PID
pub fn pid_alloc() -> PidHandle {
    PidHandle(PID_ALLOCATOR.exclusive_access().alloc())
}

#[cfg(target_arch = "riscv64")]
/// Return (bottom, top) of a kernel stack in kernel space.
pub fn kernel_stack_position(app_id: usize) -> (usize, usize) {
    let top = TRAMPOLINE - app_id * (KERNEL_STACK_SIZE + PAGE_SIZE);
    let bottom = top - KERNEL_STACK_SIZE;
    (bottom, top)
}

#[cfg(target_arch = "riscv64")]
/// Kernel stack for a task
pub struct KernelStack(pub usize);

#[cfg(target_arch = "loongarch64")]
pub struct KernelStack {
    pub frame: FrameTracker,
}

#[cfg(target_arch = "riscv64")]
/// Allocate a kernel stack for a task
pub fn kstack_alloc() -> KernelStack {
    let kstack_id = KSTACK_ALLOCATOR.exclusive_access().alloc();
    let (kstack_bottom, kstack_top) = kernel_stack_position(kstack_id);
    KERNEL_SPACE.exclusive_access().insert_framed_area(
        kstack_bottom.into(),
        kstack_top.into(),
        MapPermission::R | MapPermission::W,
    );
    KernelStack(kstack_id)
}

#[cfg(target_arch = "riscv64")]
impl Drop for KernelStack {
    fn drop(&mut self) {
        let (kernel_stack_bottom, _) = kernel_stack_position(self.0);
        let kernel_stack_bottom_va: VirtAddr = kernel_stack_bottom.into();
        KERNEL_SPACE
            .exclusive_access()
            .remove_area_with_start_vpn(kernel_stack_bottom_va.into());
        KSTACK_ALLOCATOR.exclusive_access().dealloc(self.0);
    }
}

#[cfg(target_arch = "riscv64")]
impl KernelStack {
    /// Push a variable of type T into the top of the KernelStack and return its raw pointer
    #[allow(unused)]
    pub fn push_on_top<T>(&self, value: T) -> *mut T
    where
        T: Sized,
    {
        let kernel_stack_top = self.get_top();
        let ptr_mut = (kernel_stack_top - core::mem::size_of::<T>()) as *mut T;
        unsafe {
            *ptr_mut = value;
        }
        ptr_mut
    }
    /// return the top of the kernel stack
    pub fn get_top(&self) -> usize {
        let (_, kernel_stack_top) = kernel_stack_position(self.0);
        kernel_stack_top
    }
}

#[cfg(target_arch = "loongarch64")]
/// Create a kernelstack
/// 在loongArch平台上，并不需要根据pid在内核空间分配内核栈
/// 内核态并不处于页表翻译模式，而是以类似于直接管理物理内存的方式管理
/// 因此这里会直接申请对应大小的内存空间
/// 但这也会造成内核栈无法被保护的状态
impl KernelStack {
    pub fn new() -> Self {
        frame_alloc().map(|frame| KernelStack { frame }).unwrap()
    }

    pub fn push_on_top<T>(&self, value: T) -> *mut T
    where
        T: Sized,
    {
        let kernel_stack_top = self.get_virt_top();
        let ptr_mut = (kernel_stack_top - core::mem::size_of::<T>()) as *mut T;
        unsafe {
            *ptr_mut = value;
        }
        ptr_mut
    }
    fn get_virt_top(&self) -> usize {
        let top: PhysAddr = self.frame.ppn.into();
        let top = phys_to_virt!(top.0 + PAGE_SIZE);
        top
    }

    pub fn copy_from_other(&mut self, kernel_stack: &KernelStack) -> &mut Self {
        //需要从kernel_stack复制到self
        let trap_context = kernel_stack.get_trap_cx().clone();
        self.push_on_top(trap_context);
        self
    }
    /// 返回trap上下文的可变引用
    /// 用于修改返回值
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        let cx = self.get_virt_top() - core::mem::size_of::<TrapContext>();
        unsafe { &mut *(cx as *mut TrapContext) }
    }

    /// 返回trap上下文的位置，用于初始化trap上下文
    pub fn get_trap_addr(&self) -> usize {
        let addr = self.get_virt_top() - core::mem::size_of::<TrapContext>();
        addr
    }
}

#[cfg(target_arch = "riscv64")]
/// User Resource for a task
pub struct TaskUserRes {
    /// task id
    pub tid: usize,
    /// user stack base
    pub ustack_base: usize,
    /// process belongs to
    pub process: Weak<ProcessControlBlock>,
    ///heap bottom
    pub heap_bottom: usize,
    ///program brk
    pub program_brk: usize,
}
#[cfg(target_arch = "loongarch64")]
pub struct TaskUserRes {
    pub tid: usize,
    pub ustack_base: usize,
    pub process: Weak<ProcessControlBlock>,
    pub heap_bottom: usize,
    pub program_brk: usize,
}

#[cfg(target_arch = "riscv64")]
/// Return the bottom addr (low addr) of the trap context for a task
fn trap_cx_bottom_from_tid(tid: usize) -> usize {
    TRAP_CONTEXT_BASE - tid * PAGE_SIZE
}
#[cfg(target_arch = "riscv64")]
/// Return the bottom addr (high addr) of the user stack for a task
fn ustack_bottom_from_tid(ustack_base: usize, tid: usize) -> usize {
    ustack_base + tid * (2 * PAGE_SIZE + USER_STACK_SIZE)
}
#[cfg(target_arch = "loongarch64")]
fn ustack_bottom_from_tid(ustack_base: usize, tid: usize) -> usize {
    ustack_base + tid * (PAGE_SIZE + USER_STACK_SIZE)
}

impl TaskUserRes {
    /// Create a new TaskUserRes (Task User Resource)
    pub fn new(
        process: Arc<ProcessControlBlock>,
        ustack_base: usize,
        alloc_user_res: bool,
    ) -> Self {
        let tid = process.inner_exclusive_access().alloc_tid();
        //debug!("in taskuserres new, ustack_base:{},tid:{}",ustack_base,tid);
        let user_sp = ustack_bottom_from_tid(ustack_base, tid) + USER_STACK_SIZE;
        //debug!("in taskuserres new,user_sp(brk):{}",user_sp);
        let mut task_user_res = Self {
            tid,
            ustack_base,
            process: Arc::downgrade(&process),
            heap_bottom: user_sp,
            program_brk: user_sp,
        };
        if alloc_user_res {
            task_user_res.alloc_user_res();
        }
        task_user_res
    }
    #[cfg(target_arch = "riscv64")]
    /// Allocate user resource for a task
    pub fn alloc_user_res(&mut self) {
        let process = self.process.upgrade().unwrap();
        let mut process_inner = process.inner_exclusive_access();
        // alloc user stack
        let ustack_bottom = ustack_bottom_from_tid(self.ustack_base, self.tid);
        let ustack_top = ustack_bottom + USER_STACK_SIZE;
        self.heap_bottom = ustack_top + PAGE_SIZE;
        self.program_brk = ustack_top + PAGE_SIZE;
        process_inner.memory_set.insert_framed_area(
            ustack_bottom.into(),
            ustack_top.into(),
            MapPermission::R | MapPermission::W | MapPermission::U,
        );
        // alloc user heap
        process_inner.memory_set.insert_framed_area(
            self.heap_bottom.into(),
            self.program_brk.into(),
            MapPermission::R | MapPermission::W | MapPermission::U,
        );
        // alloc trap_cx
        let trap_cx_bottom = trap_cx_bottom_from_tid(self.tid);
        let trap_cx_top = trap_cx_bottom + PAGE_SIZE;
        process_inner.memory_set.insert_framed_area(
            trap_cx_bottom.into(),
            trap_cx_top.into(),
            MapPermission::R | MapPermission::W,
        );
    }
    #[cfg(target_arch = "loongarch64")]
    /// 申请线程资源
    pub fn alloc_user_res(&mut self) {
        let process = self.process.upgrade().unwrap();
        let mut process_inner = process.inner_exclusive_access();
        // alloc user stack
        let ustack_bottom = ustack_bottom_from_tid(self.ustack_base, self.tid);
        let ustack_top = ustack_bottom + USER_STACK_SIZE;
        self.heap_bottom = ustack_top + PAGE_SIZE;
        self.program_brk = ustack_top + PAGE_SIZE;
        // debug!("ustack_bottom = {},ustack_top = {}",ustack_bottom,ustack_top);
        process_inner.memory_set.insert_framed_area(
            ustack_bottom.into(),
            ustack_top.into(),
            MapPermission::default() | MapPermission::W,
        );
        // debug!("heap_bottom = {},program_brk = {}",self.heap_bottom,self.program_brk);
        process_inner.memory_set.insert_framed_area(
            self.heap_bottom.into(),
            self.program_brk.into(),
            MapPermission::default() | MapPermission::W,
        );
    }
    #[cfg(target_arch = "riscv64")]
    /// Deallocate user resource for a task
    fn dealloc_user_res(&self) {
        // dealloc tid
        let process = self.process.upgrade().unwrap();
        let mut process_inner = process.inner_exclusive_access();
        // dealloc ustack manually
        let ustack_bottom_va: VirtAddr = ustack_bottom_from_tid(self.ustack_base, self.tid).into();
        process_inner
            .memory_set
            .remove_area_with_start_vpn(ustack_bottom_va.into());
        // dealloc user heap manually
        let heap_bottom_va: VirtAddr = self.heap_bottom.into(); 
        process_inner
            .memory_set
            .remove_area_with_start_vpn(heap_bottom_va.into());
        // dealloc trap_cx manually
        let trap_cx_bottom_va: VirtAddr = trap_cx_bottom_from_tid(self.tid).into();
        process_inner
            .memory_set
            .remove_area_with_start_vpn(trap_cx_bottom_va.into());
    }
    #[cfg(target_arch = "loongarch64")]
    fn dealloc_user_res(&self) {
        // dealloc tid
        let process = self.process.upgrade().unwrap();
        let mut process_inner = process.inner_exclusive_access();
        // dealloc ustack manually
        let ustack_bottom_va: VirtAddr = ustack_bottom_from_tid(self.ustack_base, self.tid).into();
        process_inner
            .memory_set
            .remove_area_with_start_vpn(ustack_bottom_va.into());
        // dealloc user heap manually
        let heap_bottom_va: VirtAddr = self.heap_bottom.into(); 
        process_inner
            .memory_set
            .remove_area_with_start_vpn(heap_bottom_va.into());
        // dealloc trap_cx manually
    }

    #[allow(unused)]
    /// alloc task id
    /// Used in RV
    pub fn alloc_tid(&mut self) {
        self.tid = self
            .process
            .upgrade()
            .unwrap()
            .inner_exclusive_access()
            .alloc_tid();
    }
    /// dealloc task id
    pub fn dealloc_tid(&self) {
        let process = self.process.upgrade().unwrap();
        let mut process_inner = process.inner_exclusive_access();
        process_inner.dealloc_tid(self.tid);
    }
    #[cfg(target_arch = "riscv64")]
    /// The bottom usr vaddr (low addr) of the trap context for a task with tid
    pub fn trap_cx_user_va(&self) -> usize {
        trap_cx_bottom_from_tid(self.tid)
    }
    #[cfg(target_arch = "riscv64")]
    /// The physical page number(ppn) of the trap context for a task with tid
    pub fn trap_cx_ppn(&self) -> PhysPageNum {
        let process = self.process.upgrade().unwrap();
        let process_inner = process.inner_exclusive_access();
        let trap_cx_bottom_va: VirtAddr = trap_cx_bottom_from_tid(self.tid).into();
        process_inner
            .memory_set
            .translate(trap_cx_bottom_va.into())
            .unwrap()
            .ppn()
    }
    /// the bottom addr (low addr) of the user stack for a task
    pub fn ustack_base(&self) -> usize {
        self.ustack_base
    }
    /// the top addr (high addr) of the user stack for a task
    pub fn ustack_top(&self) -> usize {
        ustack_bottom_from_tid(self.ustack_base, self.tid) + USER_STACK_SIZE
    }
    /// change the location of the program break. return None if failed.
    pub fn change_program_brk(&mut self,path: i32) -> Option<usize>{
        debug!("in change brk,path = {}",path);
        debug!("self.brk = {},self.bottom = {}",self.program_brk,self.heap_bottom);
        if path == 0{
            return Some(self.program_brk);
        }
        let process = self.process.upgrade().unwrap();
        let mut inner = process.inner_exclusive_access();
        let heap_bottom = self.heap_bottom;
        let new_brk = path as isize;
        let heap_alloc = new_brk - heap_bottom as isize;
        if new_brk < heap_bottom as isize || heap_alloc as usize > PAGE_SIZE {
            return None;
        }
        let result = if new_brk < self.program_brk as isize {
            inner.memory_set.shrink_to(VirtAddr(heap_bottom),VirtAddr(new_brk as usize))
        } else {
            debug!("to append memory set...heap_bottom = {},new_brk = {}",heap_bottom,new_brk);
            inner.memory_set.append_to(VirtAddr(heap_bottom),VirtAddr(new_brk as usize))
        };
        if result {
            debug!("to modify self brk,new brk is :{}",new_brk);
            self.program_brk = new_brk as usize;
            Some(0)
        } else {
            None
        }
    }
}

impl Drop for TaskUserRes {
    fn drop(&mut self) {
        self.dealloc_tid();
        self.dealloc_user_res();
    }
}
