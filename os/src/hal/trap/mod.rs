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

use crate::config::{MSEC_PER_SEC, TICKS_PER_SEC};
use crate::hal::strampoline;
use crate::mm::VirtAddr;
use crate::println;
pub use crate::signal::SignalFlags;
use crate::signal::{check_if_any_sig_for_current_task, handle_signal};
use crate::syscall::syscall;
use crate::task::{
    check_signals_of_current, current_add_signal, current_process, current_trap_cx,
    current_user_token, exit_current_and_run_next, suspend_current_and_run_next, current_trap_cx_user_va,
};
use crate::timer::check_timer;
pub use context::{MachineContext, UserContext};

use crate::config::TRAMPOLINE;

#[cfg(target_arch = "riscv64")]
use crate::{
    timer::{get_time, set_next_trigger},
};
#[cfg(target_arch = "loongarch64")]
use crate::{
    mm::{PageTable, VirtPageNum},
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
        // make sure that the interrupt is enabled when first task returns user mode
        euen::set_fpe(true);
        prmd::set_pie(true);
        crmd::set_ie(false);
        crmd::set_pg(true);
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
        println!("(trap::init) __trap_from_kernel: {:#x}", __trap_from_kernel as usize);
        set_kernel_trap_entry();
        tlbrentry::set_tlbrentry(__tlb_refill as usize); // 设置重填tlb地址    
        stlbps::set_ps(0xc); // 设置TLB的页面大小为4KiB
        tlbrehi::set_ps(0xc); // 设置TLB的页面大小为4KiB

        dmw2::set_plv0(true);
        dmw2::set_vseg(8);
        dmw2::set_mat(MemoryAccessType::StronglyOrderedUnCached);

        pwcl::set_pte_width(8);
        pwcl::set_ptbase(0xc); // 第零级页表的起始地址
        pwcl::set_ptwidth(9); // 第零级页表的索引位数，4KiB的页大小，0xe->0xb, 0xc->0x9
        pwcl::set_dir1_base(21); //页目录表起始位置 PAGE_SIZE_BITS + DIR_WIDTH = 12 + 9
        pwcl::set_dir1_width(9); //页目录表宽度为9位

        pwch::set_dir3_base(30); //第三级页目录表
        pwch::set_dir3_width(9); //页目录表宽度为9位

        println!("trap init success");
    }
}

/// set trap entry for traps happen in kernel(supervisor) mode
#[inline]
fn set_kernel_trap_entry() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        stvec::write(__trap_from_kernel as usize, TrapMode::Direct);
    }

    #[cfg(target_arch = "loongarch64")]
    eentry::set_eentry(__trap_from_kernel as usize);
}
/// set trap entry for traps happen in user mode
#[inline]
fn set_user_trap_entry() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        stvec::write(TRAMPOLINE as usize, TrapMode::Direct);
    }

    #[cfg(target_arch = "loongarch64")]
    eentry::set_eentry(strampoline as usize); // 设置普通异常和中断入口
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
        tcfg::set_periodic(false);

        // 开启全局中断
        ecfg::set_lie(LineBasedInterrupt::TIMER);
        crmd::set_ie(true);

        //println!("Interrupt enable: {:?}", ecfg::read().lie());
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
            //debug!("in trap handler, before syscall, to get cx");
            let mut cx = current_trap_cx();
            cx.sepc += 4;
            // get system call return value
            // debug!(
            //     "before syscall ,genenral register: x17 :{}, x10: {}, x11: {}, x12: {}, x13: {}, x14: {}, x15: {}",
            //     cx.x[17], cx.x[10], cx.x[11], cx.x[12], cx.x[13], cx.x[14], cx.x[15]
            // );
            let result = syscall(
                cx.gp.x[17],
                [cx.gp.x[10], cx.gp.x[11], cx.gp.x[12], cx.gp.x[13], cx.gp.x[14], cx.gp.x[15]],
            );
            // cx is changed during sys_exec, so we have to call it again
            //debug!("after syscall, to get cx");
            cx = current_trap_cx();
            // debug!(
            //     "after syscall, genenral register: x17 :{}, x10: {}, x11: {}, x12: {}, x13: {}, x14: {}, x15: {}",
            //     cx.x[17], cx.x[10], cx.x[11], cx.x[12], cx.x[13], cx.x[14], cx.x[15]
            // );
            cx.gp.x[10] = result as usize;
            //debug!("return x10 is : {}", cx.x[10]);
        }
        Trap::Exception(Exception::StorePageFault)
        | Trap::Exception(Exception::InstructionPageFault)
        | Trap::Exception(Exception::LoadPageFault) => {
            // page fault
            //let mut res: bool = ;
            {
                // let process = current_process();
                // let inner = process.inner_exclusive_access();
                // info!(
                //     "[kernel] trap_handler: {:?} at {:#x} as vpn",
                //     scause.cause(),
                //     stval,
                // );
                // res = inner
                //     .memory_set
                //     .lazy_page_fault(VirtAddr::from(stval).floor(), scause.cause());
                // if !res {
                //     res = inner
                //         .memory_set
                //         .cow_page_fault(VirtAddr::from(stval).floor(), scause.cause());
                // }
                // drop to avoid deadlock and exit exception
            }
            //if !res {
            error!(
                        "[kernel] trap_handler: {:?} in application, bad addr = {:#x}, bad instruction = {:#x}, kernel killed it.",
                        scause.cause(),
                        stval,
                        current_trap_cx().sepc,
                    );
            current_add_signal(SignalFlags::SIGSEGV);
            // }
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
pub fn trap_handler() -> ! {
    warn!("(trap_handler) in loongarch64 trap handler");
    set_kernel_trap_entry();
    let estat = estat::read();
    let crmd = crmd::read();
    warn!("pgdl: {:#x}, pgdh: {:#x}, pgd: {:#x}", pgdl::read().raw(), pgdh::read().raw(), pgd::read().raw());
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
            let mut cx = current_trap_cx();
            cx.sepc += 4;
            // INFO!("call id:{}, {} {} {}",cx.x[11], cx.x[4], cx.x[5], cx.x[6]);
            let result = syscall(
                cx.gp.x[11],
                [cx.gp.x[4], cx.gp.x[5], cx.gp.x[6], cx.gp.x[7], cx.gp.x[8], cx.gp.x[9]],
            ) as usize;
            cx = current_trap_cx();
            cx.gp.x[4] = result;
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
            {
                let process = current_process();
                let inner = process.inner_exclusive_access();
                let add = VirtAddr::from(badv);
                info!("[kernel] trap_handler: {:?} at {:#x} as virtadd", t, add.0);
                let add = add.floor();
                info!("[kernel] trap_handler: {:?} at {:#x} as vpn", t, add.0);
                
                // debug
                let pte = inner.memory_set.get_ref().page_table.find_pte(add).unwrap();
                let token = inner.memory_set.token();
                info!("[kernel] trap_handler: {:?} at {:#x} as pte, pte ppn: {:#x}, pte flags: {:?}", t, add.0, pte.ppn().0, pte.flags());
                info!("[kernel] trap_handler, current user token: {:#x}", token);

                // drop to avoid deadlock and exit exception
            }
            println!("[kernel] {:?} {:#x} in application, core dumped.", t, badv);
            // 设置SIGSEGV信号
            current_add_signal(SignalFlags::SIGSEGV);
        }
        Trap::Exception(Exception::InstructionPrivilegeIllegal) => {
            // 指令权限不足
            println!("[kernel] InstructionPrivilegeIllegal in application, core dumped.");
            current_add_signal(SignalFlags::SIGILL);
        }
        Trap::Interrupt(Interrupt::Timer) => {
            // 时钟中断
            warn!("timer interrupt from user");
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
        _ => {
            panic!("{:?}", estat.cause());
        }
    }
    // check error signals (if error then exit)
    if let Some((errno, msg)) = check_signals_of_current() {
        println!("[kernel] {}", msg);
        exit_current_and_run_next(errno);
    }
    //set_user_trap_entry();
    trap_return();
}

extern "C" {
    fn __alltraps();
    fn __restore();
    fn __trap_from_kernel();
    fn __tlb_refill();
}

/// return to user space
#[cfg(target_arch = "riscv64")]
#[no_mangle]
pub fn trap_return() -> ! {
    if let Some(signo) = check_if_any_sig_for_current_task() {
        debug!("found signo in trap_return");
        handle_signal(signo);
    }
    //disable_supervisor_interrupt();
    set_user_trap_entry();
    let trap_cx_user_va = current_trap_cx_user_va();
    //debug!("in trap return, get trap va");
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
pub fn trap_return() -> ! {
    use crate::{config::PAGE_SIZE_BITS, task::current_trap_cx_user_pa};

    warn!("(trap_return) in loongarch64 trap return");
    set_user_trap_entry();
    let trap_cx_ptr = current_trap_cx_user_pa();
    //debug!("in trap return, get trap va");
    warn!("era: {:#x}, prmd: {:#x}, crmd: {:#x}", era::read().pc(), prmd::read().raw(), crmd::read().raw());
    prmd::set_pplv(CpuMode::Ring3);
    prmd::set_pie(true);
    let user_satp = current_user_token();

    let restore_va = __restore as usize - __alltraps as usize + strampoline as usize;
    debug!(
        "[kernel] trap_return: ..before return, restore_va = {:#x}, trap_cx_ptr = {:#x}, user_satp = {:#x}",
        restore_va,
        trap_cx_ptr,
        user_satp
    );
    //pgdl::set_base(user_satp << PAGE_SIZE_BITS);
    unsafe {
        asm!(
            "ibar 0",
            "jr {restore_va}",
            restore_va = in(reg) restore_va,
            in("$a0") trap_cx_ptr,
            in("$a1") user_satp,
            options(noreturn)
        );
    }
}

/// handle trap from kernel
#[no_mangle]
pub fn trap_from_kernel() -> ! {
    #[cfg(target_arch = "riscv64")]
    panic!("a trap {:?} from kernel!", scause::read().cause());
    #[cfg(target_arch = "loongarch64")]
    {
        warn!("(trap_from_kernel) in loongarch64 trap from kernel");
        let estat = estat::read();
        let era = era::read();
        panic!(
            "a trap {:?} from kernel! [pc:{:#x}], code:{:b}",
            estat::read().cause(),
            era.pc(),
            estat.is(),
        );
    }
    
}

#[cfg(target_arch = "loongarch64")]
fn timer_handler() {
    // println!("timer interrupt from user");
    // 释放那些处于等待的任务
    check_timer();
    // 清除时钟中断
    ticlr::clear_timer_interrupt();
    enable_timer_interrupt();
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
            ticlr::clear_timer_interrupt();
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
        __tlb_refill();
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
