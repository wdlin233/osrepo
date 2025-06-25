//! Trap handling functionality
//!
//! For rCore, we have a single trap entry point, namely `__alltraps`. At
//! initialization in [`init()`], we set the `stvec` CSR to point to it.
//!
//! All traps go through `__alltraps`, which is defined in `trap.S`. The
//! assembly language code does just enough work restore the kernel space
//! context, ensuring that Rust code safely runs, and transfers control to
//! [`trap_handler()`].
//!
//! It then calls different functionality based on what exactly the exception
//! was. For example, timer interrupts trigger task preemption, and syscalls go
//! to [`syscall()`].

mod context;
#[cfg(target_arch = "loongarch64")]
mod trap;

use crate::config::{MSEC_PER_SEC, TICKS_PER_SEC};
use crate::mm::VirtAddr;
use crate::println;
pub use crate::signal::SignalFlags;
use crate::syscall::syscall;
use crate::task::{
    check_signals_of_current, current_add_signal, current_process, current_trap_cx,
    current_user_token, exit_current_and_run_next, suspend_current_and_run_next,
};
use crate::timer::check_timer;

#[cfg(target_arch = "riscv64")]
use crate::{
    config::TRAMPOLINE,
    task::current_trap_cx_user_va,
    timer::{get_time, set_next_trigger},
};
#[cfg(target_arch = "loongarch64")]
use crate::{
    mm::{PageTable, VirtPageNum},
    task::current_trap_addr,
    timer::get_time,
};

use core::arch::{asm, global_asm};

#[cfg(target_arch = "loongarch64")]
use loongarch64::{
    register::{
        ecfg::LineBasedInterrupt,
        estat::{Exception, Interrupt, Trap},
        *,
    },
    time::get_timer_freq,
};
#[cfg(target_arch = "riscv64")]
use riscv::register::{
    mtvec::TrapMode,
    satp,
    scause::{self, Exception, Interrupt, Trap},
    sie, stval, stvec,
};

#[cfg(target_arch = "riscv64")]
global_asm!(include_str!("trap_rv.s"));
#[cfg(target_arch = "loongarch64")]
global_asm!(include_str!("trap_la.s"));

/// Initialize trap handling
pub fn init() {
    #[cfg(target_arch = "riscv64")]
    set_kernel_trap_entry();
    #[cfg(target_arch = "loongarch64")]
    {
        // 清除时钟专断
        ticlr::clear_timer_interrupt();
        tcfg::set_en(false);
        // disable all interrupts
        ecfg::set_lie(LineBasedInterrupt::empty());
        // Ecfg::read().set_lie_with_index(11, false).write();
        // 关闭全局中断
        crmd::set_ie(false);

        // 设置普通异常和中断入口
        // 设置TLB重填异常地址
        println!("kernel_trap_entry: {:#x}", trap::kernel_trap_entry as usize);
        eentry::set_eentry(trap::kernel_trap_entry as usize);
        // 设置重填tlb地址
        tlbrentry::set_tlbrentry(trap::__tlb_rfill as usize);
        // 设置TLB的页面大小为16KiB
        stlbps::set_ps(0xe);
        // 设置TLB的页面大小为16KiB
        tlbrehi::set_ps(0xe);
        pwcl::set_ptbase(0xe);
        pwcl::set_ptwidth(0xb); //16KiB的页大小
        pwcl::set_dir1_base(25); //页目录表起始位置
        pwcl::set_dir1_width(0xb); //页目录表宽度为11位

        pwch::set_dir3_base(36); //第三级页目录表
        pwch::set_dir3_width(0xb); //页目录表宽度为11位

        // make sure that the interrupt is enabled when first task returns user mode
        prmd::set_pie(true);

        println!("trap init success");
    }
}

/// set trap entry for traps happen in kernel(supervisor) mode
#[inline]
fn set_kernel_trap_entry() {
    #[cfg(target_arch = "riscv64")]
    extern "C" {
        fn __trap_from_kernel();
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        stvec::write(__trap_from_kernel as usize, TrapMode::Direct);
    }

    #[cfg(target_arch = "loongarch64")]
    eentry::set_eentry(trap::kernel_trap_entry as usize);
}
/// set trap entry for traps happen in user mode
#[inline]
fn set_user_trap_entry() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        stvec::write(TRAMPOLINE as usize, TrapMode::Direct);
    }

    #[cfg(target_arch = "loongarch64")]
    eentry::set_eentry(__alltraps as usize); // 设置普通异常和中断入口
}

/// enable timer interrupt in supervisor mode
pub fn enable_timer_interrupt() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        sie::set_stimer();
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let timer_freq = get_timer_freq();
        ticlr::clear_timer_interrupt();
        // 设置计时器的配置
        // println!("timer freq: {}", timer_freq);
        tcfg::set_init_val(timer_freq / TICKS_PER_SEC);
        tcfg::set_en(true);
        tcfg::set_periodic(true);

        // 开启全局中断
        ecfg::set_lie(LineBasedInterrupt::TIMER | LineBasedInterrupt::HWI0);
        crmd::set_ie(true);

        println!("Interrupt enable: {:?}", ecfg::read().lie());
    }
}

/// trap handler
#[cfg(target_arch = "riscv64")]
#[no_mangle]
pub fn trap_handler() -> ! {
    set_kernel_trap_entry();
    let scause = scause::read();
    let stval = stval::read();
    // trace!("into {:?}", scause.cause());
    // to get kernel time
    let in_kernel_time = get_time();
    current_process()
        .inner_exclusive_access()
        .set_utime(in_kernel_time);
    match scause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            // jump to next instruction anyway
            let mut cx = current_trap_cx();
            cx.sepc += 4;
            // get system call return value
            debug!(
                "genenral register: x17 :{}, x10: {}, x11: {}, x12: {}, x13: {}, x14: {}, x15: {}",
                cx.x[17], cx.x[10], cx.x[11], cx.x[12], cx.x[13], cx.x[14], cx.x[15]
            );
            let result = syscall(
                cx.x[17],
                [cx.x[10], cx.x[11], cx.x[12], cx.x[13], cx.x[14], cx.x[15]],
            );
            // cx is changed during sys_exec, so we have to call it again
            cx = current_trap_cx();
            cx.x[10] = result as usize;
        }
        Trap::Exception(Exception::StorePageFault)
        | Trap::Exception(Exception::InstructionPageFault)
        | Trap::Exception(Exception::LoadPageFault) => {
            // page fault
            let mut res: bool;
            {
                let process = current_process();
                let inner = process.inner_exclusive_access();
                info!(
                    "[kernel] trap_handler: {:?} at {:#x} as vpn",
                    scause.cause(),
                    stval,
                );
                res = inner
                    .memory_set
                    .lazy_page_fault(VirtAddr::from(stval).floor(), scause.cause());
                if !res {
                    res = inner
                        .memory_set
                        .cow_page_fault(VirtAddr::from(stval).floor(), scause.cause());
                }
                // drop to avoid deadlock and exit exception
            }
            if !res {
                error!(
                    "[kernel] trap_handler: {:?} in application, bad addr = {:#x}, bad instruction = {:#x}, kernel killed it.",
                    scause.cause(),
                    stval,
                    current_trap_cx().sepc,
                );
                current_add_signal(SignalFlags::SIGSEGV);
            }
        }
        Trap::Exception(Exception::StoreFault)
        | Trap::Exception(Exception::InstructionFault)
        | Trap::Exception(Exception::LoadFault) => {
            error!(
                "[kernel] trap_handler: {:?} in application, bad addr = {:#x}, bad instruction = {:#x}, kernel killed it.",
                scause.cause(),
                stval,
                current_trap_cx().sepc,
            );
            exit_current_and_run_next(-2);
        }
        Trap::Exception(Exception::IllegalInstruction) => {
            current_add_signal(SignalFlags::SIGILL);
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            set_next_trigger();
            check_timer();
            suspend_current_and_run_next();
        }
        _ => {
            panic!(
                "Unsupported trap {:?}, stval = {:#x}!",
                scause.cause(),
                stval
            );
        }
    }
    // check signals
    if let Some((errno, msg)) = check_signals_of_current() {
        trace!("[kernel] trap_handler: .. check signals {}", msg);
        exit_current_and_run_next(errno);
    }
    let out_kernel_time = get_time();
    current_process()
        .inner_exclusive_access()
        .set_stime(in_kernel_time, out_kernel_time);
    trap_return();
}

#[cfg(target_arch = "loongarch64")]
#[no_mangle]
pub fn trap_handler(mut cx: &mut TrapContext) -> &mut TrapContext {
    set_kernel_trap_entry();
    let estat = estat::read();
    let crmd = crmd::read();
    if crmd.ie() {
        // 全局中断会在中断处理程序被关掉
        panic!("kerneltrap: global interrupt enable");
    }
    // to get kernel time
    let in_kernel_time = get_time();
    current_process()
        .inner_exclusive_access()
        .set_utime(in_kernel_time);
    match estat.cause() {
        Trap::Exception(Exception::Syscall) => {
            //系统调用
            cx.sepc += 4;
            // INFO!("call id:{}, {} {} {}",cx.x[11], cx.x[4], cx.x[5], cx.x[6]);
            let result = syscall(
                cx.x[11],
                [cx.x[4], cx.x[5], cx.x[6], cx.x[7], cx.x[8], cx.x[9]],
            ) as usize;
            cx = current_trap_cx();
            cx.x[4] = result;
        }
        Trap::Exception(Exception::LoadPageFault)
        | Trap::Exception(Exception::StorePageFault)
        | Trap::Exception(Exception::FetchPageFault)
        | Trap::Exception(Exception::InstructionNotExist) => {
            // 页面异常
            // tlb_page_fault();
            let t = estat.cause();
            let badv = badv::read().vaddr();
            info!("badv: {:#x}", badv);
            let mut res: bool;
            {
                let process = current_process();
                let inner = process.inner_exclusive_access();
                let add = VirtAddr::from(badv);
                info!("[kernel] trap_handler: {:?} at {:#x} as virtadd", t, add.0);
                let add = add.floor();
                info!("[kernel] trap_handler: {:?} at {:#x} as vpn", t, add.0);
                res = inner.memory_set.lazy_page_fault(add, t);
                if !res {
                    res = inner.memory_set.cow_page_fault(add, t);
                }
                // drop to avoid deadlock and exit exception
            }
            if !res {
                println!("[kernel] {:?} {:#x} in application, core dumped.", t, badv);
                // 设置SIGSEGV信号
                current_add_signal(SignalFlags::SIGSEGV);
            }
        }
        Trap::Exception(Exception::InstructionPrivilegeIllegal) => {
            // 指令权限不足
            println!("[kernel] InstructionPrivilegeIllegal in application, core dumped.");
            current_add_signal(SignalFlags::SIGILL);
        }
        Trap::Interrupt(Interrupt::Timer) => {
            // 时钟中断
            timer_handler();
        }
        Trap::Exception(Exception::TLBRFill) => {
            // 具体实现中TLB重填例外不会进入这里
            // 这部分只是用于Debug
            // 将TLB重填例外设置为这个入口，会导致速度变慢，但同时由于lddir与ldpte指令的原因
            // 页表项和页目录项的区别将会与riscv大不相同
            tlb_refill_handler();
        }
        Trap::Exception(Exception::PageModifyFault) => {
            // let badv = badv::read().vaddr();
            // let mut res: bool = false;
            // {
            //     let process = current_process();
            //     let inner = process.inner_exclusive_access();
            //     res = inner.memory_set
            //         .cow_page_fault(VirtAddr::from(badv).floor(), estat.cause());
            // }
            // if !res {
            //     error!(
            //         "[kernel] PageModifyFault at {:#x} in application, kernel killed it.",
            //         badv
            //     );
            //     current_add_signal(SignalFlags::SIGSEGV);
            // }
            tlb_page_modify_handler();
        }
        Trap::Exception(Exception::PagePrivilegeIllegal) => {
            //页权限不足
            tlb_page_fault();
            panic!("[kernel] PagePrivilegeIllegal in application, core dumped.");
        }
        Trap::Interrupt(Interrupt::HWI0) => {
            //中断0 --- 外部中断处理
            //hwi0_handler();
            unimplemented!()
        }
        _ => {
            panic!("{:?}", estat.cause());
        }
    }
    // check error signals (if error then exit)
    if let Some((errno, msg)) = check_signals_of_current() {
        println!("[kernel] {}", msg);
        exit_current_and_run_next(errno);
    }
    set_user_trap_entry();
    cx
}

extern "C" {
    fn __alltraps();
    fn __restore();
}

/// return to user space
#[cfg(target_arch = "riscv64")]
#[no_mangle]
pub fn trap_return() -> ! {
    //disable_supervisor_interrupt();
    set_user_trap_entry();
    let trap_cx_user_va = current_trap_cx_user_va();
    let user_satp = current_user_token();

    let restore_va = __restore as usize - __alltraps as usize + TRAMPOLINE;
    // trace!("[kernel] trap_return: ..before return");
    unsafe {
        asm!(
            "fence.i",
            "jr {restore_va}",         // jump to new addr of __restore asm function
            restore_va = in(reg) restore_va,
            in("a0") trap_cx_user_va,      // a0 = virt addr of Trap Context
            in("a1") user_satp,        // a1 = phy addr of usr page table
            options(noreturn)
        );
    }
}

#[cfg(target_arch = "loongarch64")]
#[no_mangle]
pub fn trap_return() {
    set_user_trap_entry();
    let trap_addr = current_trap_addr();
    unsafe {
        asm!("move $a0,{}",in(reg)trap_addr);
        __restore();
    }
}

/// handle trap from kernel
#[cfg(target_arch = "riscv64")]
#[no_mangle]
pub fn trap_from_kernel() -> ! {
    //use riscv::register::sepc;
    //trace!("stval = {:#x}, sepc = {:#x}", stval::read(), sepc::read());
    panic!("a trap {:?} from kernel!", scause::read().cause());
}

#[cfg(target_arch = "loongarch64")]
fn timer_handler() {
    // println!("timer interrupt from user");
    // 释放那些处于等待的任务
    check_timer();
    // 清除时钟中断
    ticlr::clear_timer_interrupt();
    suspend_current_and_run_next();
}

/// 当在内核态发生异常或中断时处理
/// 这里主要时处理时钟中断
/// 由于主函数开启时钟中断后会进行加载任务操作
/// 而加载任务的时间可能会触发时钟中断
/// 在正常运行后系统在从用户态trap进入内核态后是不会触发中断的
#[cfg(target_arch = "loongarch64")]
#[no_mangle]
pub fn trap_handler_kernel() {
    // println!("kernel trap");
    let estat = estat::read();
    let crmd = crmd::read();
    let era = era::read();
    if crmd.plv() != CpuMode::Ring0 {
        // 只有在内核态才会触发中断
        panic!("{:?}", estat.cause());
    }
    match estat.cause() {
        Trap::Interrupt(Interrupt::Timer) => {
            // 清除时钟专断
            trace!("timer interrupt from kernel");
            ticlr::clear_timer_interrupt();
        }
        Trap::Interrupt(Interrupt::HWI0) => {
            // 中断0 --- 外部中断处理
            // hwi0_handler();
            unimplemented!("unnecessary")
        }
        e => {
            panic!(
                "[pc:{:#x}], cause:{:?},  code:{:b}",
                era.pc(),
                e,
                estat.is(),
            );
        }
    }
    // era::set_pc(era.pc());
}

#[cfg(target_arch = "loongarch64")]
// loongarch64需要手动处理TLB重填异常
// 重填异常处理
fn tlb_refill_handler() {
    log::error!("TLB refill exception");
    unsafe {
        trap::__tlb_rfill();
    }
}

#[cfg(target_arch = "loongarch64")]
/// Exception(PageModifyFault)的处理
/// 页修改例外：store 操作的虚地址在 TLB 中找到了匹配，且
/// V=1，且特权等级合规的项，但是该页 表项的 D 位为 0，将触发该例外
fn tlb_page_modify_handler() {
    let pid = current_process().getpid();
    trace!("PageModifyFault handler [PID]{}", pid);
    // 找到对应的页表项，修改D位为1
    // 出错虚拟地址
    let badv = tlbrbadv::read().vaddr();
    let vpn: VirtAddr = badv.into();
    let vpn: VirtPageNum = vpn.floor();
    let token = current_user_token();
    let page_table = PageTable::from_token(token);
    // 获取页表项
    let pte = page_table.find_pte(vpn).unwrap();
    pte.set_dirty(); //修改D位为1
    unsafe {
        // 根据TLBEHI的虚双页号查询TLB对应项
        asm!("tlbsrch", "tlbrd",);
    }
    // 获取TLB项索引
    let tlbidx = tlbidx::read();
    assert_eq!(tlbidx.ne(), false);
    tlbelo1::set_dirty(true);
    tlbelo0::set_dirty(true);
    // 重新将tlbelo写入tlb
    unsafe {
        asm!("tlbwr");
    }
}

#[cfg(target_arch = "loongarch64")]
#[no_mangle]
fn tlb_page_fault() {
    // 检查pagefault相关内容
    unsafe { asm!("tlbsrch", "tlbrd",) }
    let tlbelo0 = tlbelo0::read();
    let tlbelo1 = tlbelo1::read();
    info!("tlbelo0 :{}", tlbelo0);
    info!("tlbelo1 :{}", tlbelo1);
}

pub use context::TrapContext;

#[allow(unused_variables)]

///wait ret
#[cfg(target_arch = "riscv64")]
pub fn wait_return() {
    info!("new round of father waiting for child to return");
    set_user_trap_entry();
    let trap_cx_user_va: usize = current_trap_cx_user_va().into();
    let user_satp = current_user_token();
    debug!(
        "[kernel] wait_return, trap_cx_user_va = {:#x}, user_satp = {:#x}",
        trap_cx_user_va, user_satp
    );

    extern "C" {
        fn __wait_return();
    }
    let entry_va = __wait_return as usize;
    warn!("reset satp to {:#x}", user_satp);
    unsafe {
        satp::write(user_satp);
        asm!("sfence.vma");
    }
}
