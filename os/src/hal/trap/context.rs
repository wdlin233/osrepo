//! Implementation of [`TrapContext`]
#[cfg(target_arch = "loongarch64")]
use crate::hal::trap::trap_handler;
#[cfg(target_arch = "loongarch64")]
use loongarch64::register::{prmd::Prmd, prmd, CpuMode};
#[cfg(target_arch = "riscv64")]
use riscv::register::sstatus::{self, Sstatus, SPP, set_spp};

use core::fmt::{Debug, Formatter};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
// General-Purpose Register x0-31, x2(sp, rv), x3(sp, la)
pub struct GeneralRegs {
    pub x: [usize; 32],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FloatRegs {
    pub f: [usize; 32],
    pub fcsr: u32,
    #[cfg(target_arch = "loongarch64")] pub fcc: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// trap context structure containing sstatus, sepc and registers
pub struct TrapContext {
    pub gp: GeneralRegs, // general regs 0-31
    pub fp: FloatRegs, // float regs 32-63, fcsr 64
    #[cfg(target_arch = "riscv64")]
    pub sstatus: Sstatus, // 65, Supervisor Status Register
    #[cfg(target_arch = "loongarch64")]
    pub sstatus: Prmd, //65, 控制状态寄存器
    pub sepc: usize,    // 66, Supervisor Exception Program Counter，also CSR_ERA
    pub kernel_satp: usize, // 67, Token of kernel address space
    pub kernel_sp: usize, // 68, Kernel stack pointer of the current application
    pub kernel_ra: usize, // 69, Virtual address of trap handler entry point in kernel
    pub origin_a0: usize, // 70
}

// Debug trait for loongarch64 TrapContext
impl Debug for TrapContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        #[cfg(target_arch = "riscv64")]
        {
            return write!(
                f,
                "TrapContext {{ x: {:?}, sstatus: {:#?}, sepc: {:#x}, kernel_satp: {:#x}, kernel_sp: {:#x} }}",
                self.gp.x, self.sstatus, self.sepc, self.kernel_satp, self.kernel_sp
            );
        }
        #[cfg(target_arch = "loongarch64")]
        {
            return write!(
                f,
                "TrapContext {{ x: {:?}, sepc: {:#x}, trap_handler: {:#x} }}",
                self.gp.x, self.sepc, self.kernel_ra
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
            self.gp.x[2] = sp; // riscv64 uses x2 as stack pointer
        }
        #[cfg(target_arch = "loongarch64")]
        {
            self.gp.x[3] = sp; // loongarch64 uses x3 as stack pointer
        }
    }

    /// init the trap context of an application
    pub fn app_init_context(
        entry: usize,
        sp: usize,
        kernel_satp: usize,
        kernel_sp: usize,
        trap_handler: usize,
    ) -> Self {
        #[cfg(target_arch = "riscv64")]
        let sstatus = sstatus::read();
        // set CPU privilege to User after trapping back
        #[cfg(target_arch = "riscv64")]
        unsafe {
            set_spp(SPP::User);
        }
        // 设置为用户模式,trap使用ertn进入用户态时会被加载到crmd寄存器中
        #[cfg(target_arch = "loongarch64")]
        prmd::set_pplv(CpuMode::Ring3);
        #[cfg(target_arch = "loongarch64")]
        let sstatus = prmd::read();

        let mut cx = Self {
            gp: GeneralRegs::default(),
            fp: FloatRegs::default(),
            sstatus,
            sepc: entry, // entry point of app
            kernel_satp, // addr of page table
            kernel_sp, // kernel stack
            kernel_ra: trap_handler as usize, // addr of trap_handler function
            origin_a0: 0, // original a0 value
        };
        cx.set_sp(sp); // app's user stack pointer
        cx // return initial Trap Context of app
    }
}
