pub mod uart;
pub mod utils;
#[cfg(target_arch = "loongarch64")]
pub mod info;

pub fn clear_bss() {
    extern "C" {
        fn sbss();
        fn ebss();
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::slice::from_raw_parts_mut(sbss as usize as *mut u8, ebss as usize - sbss as usize)
            .fill(0);
    }
    #[cfg(target_arch = "loongarch64")]
    {
        (sbss as usize..ebss as usize).for_each(|addr| unsafe {
            (addr as *mut u8).write_volatile(0);
        });
    }
}

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