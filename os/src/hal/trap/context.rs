use polyhal_trap::trapframe::TrapFrame;

use crate::signal::{SignalFlags, SignalStack};

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct MachineContext {
    gp: [usize; 32],
    // fp: FloatRegs,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UserContext {
    pub flags: usize,
    pub link: usize,
    pub stack: SignalStack,
    pub sigmask: SignalFlags,
    pub __pad: [u8; 128],
    pub mcontext: MachineContext,
}

pub trait MachineContextConversion {
    fn as_mctx(&self) -> MachineContext;
    fn copy_from_mctx(&mut self, mctx: MachineContext);
}

impl MachineContextConversion for TrapFrame {
    #[inline]
    fn as_mctx(&self) -> MachineContext {
        let mut x = [0; 32];
        x.copy_from_slice(&self.x);
        x[0] = self.sepc; // x0 寄存器永远为0,暂时借用一下,用于保存sepc
        MachineContext {
            gp: self.x,
        }
    }
    
    #[inline]
    fn copy_from_mctx(&mut self, mctx: MachineContext) {
        self.x.copy_from_slice(&mctx.gp);
        self.sepc = self.x[0];
        self.x[0] = 0; // x0 寄存器永远为0,清除 sepc
    }
}