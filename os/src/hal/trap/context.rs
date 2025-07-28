//! Implementation of [`TrapContext`]
#[cfg(target_arch = "loongarch64")]
use crate::hal::trap::trap_handler;
#[cfg(target_arch = "loongarch64")]
use loongarch64::register::{prmd, CpuMode};
#[cfg(target_arch = "riscv64")]
use riscv::register::sstatus::{self, Sstatus, SPP, set_spp};

use core::fmt::{Debug, Formatter};

#[repr(C)]
#[derive(Clone, Copy)]
/// trap context structure containing sstatus, sepc and registers
pub struct TrapContext {
    pub x: [usize; 32], // General-Purpose Register x0-31, x2(sp, rv), x3(sp, la)
    #[cfg(target_arch = "riscv64")]
    pub sstatus: Sstatus, // Supervisor Status Register
    #[cfg(target_arch = "loongarch64")]
    pub prmd: usize, //控制状态寄存器
    pub sepc: usize,    // Supervisor Exception Program Counter，异常处理返回地址
    #[cfg(target_arch = "riscv64")]
    pub kernel_satp: usize, // Token of kernel address space
    #[cfg(target_arch = "riscv64")]
    pub kernel_sp: usize, // Kernel stack pointer of the current application
    pub trap_handler: usize, // Virtual address of trap handler entry point in kernel
}

// Debug trait for loongarch64 TrapContext
impl Debug for TrapContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        #[cfg(target_arch = "riscv64")]
        {
            return write!(
                f,
                "TrapContext {{ x: {:?}, sstatus: {:#?}, sepc: {:#x}, kernel_satp: {:#x}, kernel_sp: {:#x} }}",
                self.x, self.sstatus, self.sepc, self.kernel_satp, self.kernel_sp
            );
        }
        #[cfg(target_arch = "loongarch64")]
        {
            return write!(
                f,
                "TrapContext {{ x: {:?}, prmd: {:#x}, sepc: {:#x}, trap_handler: {:#x} }}",
                self.x, self.prmd, self.sepc, self.trap_handler
            );
        }
    }
}

impl TrapContext {
    /// put the sp(stack pointer) into TrapContext
    pub fn set_sp(&mut self, sp: usize) {
        //info!("set sp to {:#x}", sp);
        #[cfg(target_arch = "riscv64")]
        {
            self.x[2] = sp; // riscv64 uses x2 as stack pointer
        }
        #[cfg(target_arch = "loongarch64")]
        {
            self.x[3] = sp - 8; // loongarch64 uses x3 as stack pointer
        }
    }

    /// init the trap context of an application
    pub fn app_init_context(
        entry: usize,
        sp: usize,
        #[cfg(target_arch = "riscv64")] kernel_satp: usize,
        #[cfg(target_arch = "riscv64")] kernel_sp: usize,
        #[cfg(target_arch = "riscv64")] trap_handler: usize,
    ) -> Self {
        #[cfg(target_arch = "riscv64")]
        let mut sstatus = sstatus::read();
        // set CPU privilege to User after trapping back
        #[cfg(target_arch = "riscv64")]
        unsafe {
            set_spp(SPP::User);
        }
        // 设置为用户模式,trap使用ertn进入用户态时会被加载到crmd寄存器中
        #[cfg(target_arch = "loongarch64")]
        prmd::set_pplv(CpuMode::Ring3);

        let mut cx = Self {
            x: [0; 32],
            #[cfg(target_arch = "riscv64")]
            sstatus,
            #[cfg(target_arch = "loongarch64")]
            prmd: prmd::read().raw(),
            sepc: entry, // entry point of app
            #[cfg(target_arch = "riscv64")]
            kernel_satp, // addr of page table
            #[cfg(target_arch = "riscv64")]
            kernel_sp, // kernel stack
            trap_handler: trap_handler as usize, // addr of trap_handler function
        };
        cx.set_sp(sp); // app's user stack pointer
        cx // return initial Trap Context of app
    }
}
