pub mod arch;
pub mod trap;
pub mod utils;

extern "C" {
    pub fn stext();
    pub fn etext();
    pub fn srodata();
    pub fn erodata();
    pub fn sdata();
    pub fn edata();
    pub fn sbss_with_stack();
    pub fn ebss();
    pub fn ekernel();
    pub fn strampoline();
    pub fn sigreturn();
}
