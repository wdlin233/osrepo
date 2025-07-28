pub mod utils;
pub mod arch; 
pub mod trap;

extern "C" {
    pub fn stext();
    pub fn etext();
    pub fn srodata();
    pub fn erodata();
    pub fn sdata();
    pub fn edata();
    #[cfg(target_arch = "riscv64")] pub fn sbss_with_stack();
    #[cfg(target_arch = "loongarch64")] pub fn sbss();
    pub fn ebss();
    pub fn ekernel();
   #[cfg(target_arch = "riscv64")] pub fn strampoline();
}