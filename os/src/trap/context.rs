//! Implementation of [`TrapContext`]
#[cfg(target_arch = "riscv64")]
use riscv::register::sstatus::{self, Sstatus, SPP};
#[cfg(target_arch = "loongarch64")]
use core::fmt::{Debug, Formatter};
#[cfg(target_arch = "loongarch64")]
use loongarch64::register::{prmd, CpuMode};
#[cfg(target_arch = "loongarch64")]
use crate::trap::trap_handler;

#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// trap context structure containing sstatus, sepc and registers
pub struct TrapContext {
    /// General-Purpose Register x0-31
    pub x: [usize; 32],
    /// Supervisor Status Register
    pub sstatus: Sstatus,
    /// Supervisor Exception Program Counter
    pub sepc: usize,
    /// Token of kernel address space
    pub kernel_satp: usize,
    /// Kernel stack pointer of the current application
    pub kernel_sp: usize,
    /// Virtual address of trap handler entry point in kernel
    pub trap_handler: usize,
}

#[cfg(target_arch = "loongarch64")]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TrapContext {
    pub x: [usize; 32], //通用寄存器 ，第4个寄存器是sp
    pub prmd: usize,    //控制状态寄存器---似乎没有用
    pub sepc: usize,    //异常处理返回地址
    pub trap_handler: usize,
}

#[cfg(target_arch = "loongarch64")]
// Debug trait for loongarch64 TrapContext
impl Debug for TrapContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TrapContext {{ x: {:?}, crmd: {:#b}, sepc: {:#x} }}",
            self.x, self.prmd, self.sepc
        )
    }
}

impl TrapContext {
    #[cfg(target_arch = "riscv64")]
    /// put the sp(stack pointer) into x\[2\] field of TrapContext
    pub fn set_sp(&mut self, sp: usize) {
        self.x[2] = sp;
    }
    #[cfg(target_arch = "riscv64")]
    /// init the trap context of an application
    pub fn app_init_context(
        entry: usize,
        sp: usize,
        kernel_satp: usize,
        kernel_sp: usize,
        trap_handler: usize,
    ) -> Self {
        let mut sstatus = sstatus::read();
        // set CPU privilege to User after trapping back
        sstatus.set_spp(SPP::User);
        let mut cx = Self {
            x: [0; 32],
            sstatus,
            sepc: entry,  // entry point of app
            kernel_satp,  // addr of page table
            kernel_sp,    // kernel stack
            trap_handler, // addr of trap_handler function
        };
        cx.set_sp(sp); // app's user stack pointer
        cx // return initial Trap Context of app
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn set_sp(&mut self, sp: usize) {
        self.x[3] = sp;
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn app_init_context(entry: usize, sp: usize) -> Self {
        // 设置为用户模式,trap使用ertn进入用户态时会被加载到crmd寄存器中
        prmd::set_pplv(CpuMode::Ring3);
        let mut cx = Self {
            x: [0; 32],
            prmd: prmd::read().raw(),
            sepc: entry,
            trap_handler: trap_handler as usize,
        };
        cx.set_sp(sp);
        cx
    }
}
