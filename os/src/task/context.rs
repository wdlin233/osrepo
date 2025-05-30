//! Implementation of [`TaskContext`]
use crate::trap::trap_return;

#[cfg(target_arch = "riscv64")]
#[repr(C)]
/// task context structure containing some registers
pub struct TaskContext {
    /// Ret position after task switching
    ra: usize,
    /// Stack pointer
    sp: usize,
    /// s0-11 register, callee saved
    s: [usize; 12],
}

/// 任务上下文
/// 对于一般的函数，编译器会在函数的起始位置自动生成代码保存 被调用者保存寄存器
/// _switch函数不会被编译器特殊处理，因此我们需要手动保存这些寄存器
/// 而其它寄存器不保存时因为属于调用者保存的寄存器是由编译器在高级语言编写
/// 的调用函数中自动生成的代码来完成保存的；还有一些寄存器属于临时寄存器，
/// 不需要保存和恢复。
#[cfg(target_arch = "loongarch64")]
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct TaskContext {
    //ra: 此寄存器存储的是函数返回时跳转的地址
    //在调用函数返回指令时,Pc指针会取出ra里面的地址
    ra: usize,
    sp: usize,
    s: [usize; 10], //loongArch下需要保存10个s寄存器
}

/// 在应用第一次运行时，我们需要为其构造一个任务上下文
/// 将ra设置为_restore的地址，那么在应用执行完__switch后，就会返回到_restore
/// 此时就转变为初始化一个trap上下文的情况了。
impl TaskContext {
    #[cfg(target_arch = "riscv64")]
    /// Create a new empty task context
    pub fn zero_init() -> Self {
        Self {
            ra: 0,
            sp: 0,
            s: [0; 12],
        }
    }
    #[cfg(target_arch = "riscv64")] 
    /// Create a new task context with a trap return addr and a kernel stack pointer
    pub fn goto_trap_return(kstack_ptr: usize) -> Self {
        Self {
            ra: trap_return as usize,
            sp: kstack_ptr,
            s: [0; 12],
        }
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn zero_init() -> Self {
        TaskContext {
            ra: 0,
            sp: 0,
            s: [0; 10],
        }
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn goto_restore(kstack_ptr: usize) -> Self {
        Self {
            ra: trap_return as usize,
            sp: kstack_ptr, //存放了trap上下文后的栈地址,内核栈地址
            s: [0; 10],
        }
    }
}
