//! Implementation of [`TaskContext`]
use crate::hal::trap::trap_return;

/// 任务上下文
/// 对于一般的函数，编译器会在函数的起始位置自动生成代码保存 被调用者保存寄存器
/// _switch函数不会被编译器特殊处理，因此我们需要手动保存这些寄存器
/// 而其它寄存器不保存时因为属于调用者保存的寄存器是由编译器在高级语言编写
/// 的调用函数中自动生成的代码来完成保存的；还有一些寄存器属于临时寄存器，
/// 不需要保存和恢复。
#[repr(C)]
#[derive(Copy, Clone, Debug)]
/// task context structure containing some registers
pub struct TaskContext {
    /// Ret position after task switching
    ra: usize,
    /// Stack pointer
    sp: usize,
    /// s0-11 register, callee saved
    #[cfg(target_arch = "riscv64")] s: [usize; 12],
    /// loongArch下需要保存10个s寄存器
    #[cfg(target_arch = "loongarch64")] s: [usize; 10],
}

/// 在应用第一次运行时，我们需要为其构造一个任务上下文
/// 将ra设置为_restore的地址，那么在应用执行完__switch后，就会返回到_restore
/// 此时就转变为初始化一个trap上下文的情况了。
impl TaskContext {
    /// Create a new empty task context
    pub fn zero_init() -> Self {
        Self {
            ra: 0,
            sp: 0,
            #[cfg(target_arch = "riscv64")] s: [0; 12],
            #[cfg(target_arch = "loongarch64")] s: [0; 10],
        }
    }
    /// Create a new task context with a trap return addr and a kernel stack pointer
    pub fn goto_trap_return(kstack_ptr: usize) -> Self {
        Self {
            ra: trap_return as usize,
            sp: kstack_ptr, //存放了trap上下文后的栈地址,内核栈地址
            #[cfg(target_arch = "riscv64")] s: [0; 12],
            #[cfg(target_arch = "loongarch64")] s: [0; 10],
        }
    }
}
