//!provides __switch asm function to switch between two task contexts  [`TaskContext`]
use super::TaskContext;
use core::arch::global_asm;

#[cfg(target_arch = "riscv64")]
global_asm!(include_str!("switch_rv.s"));
#[cfg(target_arch = "loongarch64")]
global_asm!(include_str!("switch_la.s"));

extern "C" {
    /// Switch to the context of `next_task_cx_ptr`, saving the current context
    /// in `current_task_cx_ptr`.
    pub fn __switch(current_task_cx_ptr: *mut TaskContext, next_task_cx_ptr: *const TaskContext);
}
