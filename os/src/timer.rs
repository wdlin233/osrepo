//! RISC-V & LoongArch timer-related functionality

use core::cmp::Ordering;

use crate::config::CLOCK_FREQ;
use crate::sync::UPSafeCell;
use crate::task::TaskControlBlock;
use crate::config::{MSEC_PER_SEC, TICKS_PER_SEC};
use alloc::collections::BinaryHeap;
use alloc::sync::Arc;
use lazy_static::*;
#[cfg(target_arch = "riscv64")]
use riscv::register::time;
#[cfg(target_arch = "loongarch64")]
use loongarch64::time::{get_timer_freq, Time};

/// The number of microseconds per second
#[allow(dead_code)]
const MICRO_PER_SEC: usize = 1_000_000;


/// Get the current time in ticks
pub fn get_time() -> usize {
    #[cfg(target_arch = "riscv64")] return time::read();
    #[cfg(target_arch = "loongarch64")] return Time::read();
}

/// Get the current time in milliseconds
pub fn get_time_ms() -> usize {
    #[cfg(target_arch = "riscv64")] return time::read() * MSEC_PER_SEC / CLOCK_FREQ;
    #[cfg(target_arch = "loongarch64")] return Time::read() / (get_timer_freq() / MSEC_PER_SEC);
}

/// get current time in microseconds
pub fn get_time_us() -> usize {
    #[cfg(target_arch = "riscv64")] return time::read() * MICRO_PER_SEC / CLOCK_FREQ;
    #[cfg(target_arch = "loongarch64")] return Time::read() * MICRO_PER_SEC / get_timer_freq();
}

#[cfg(target_arch = "riscv64")]
/// Set the next timer interrupt
pub fn set_next_trigger() {
    use crate::hal::utils::set_timer;
    set_timer(get_time() + CLOCK_FREQ / TICKS_PER_SEC);
}

/// condvar for timer
pub struct TimerCondVar {
    /// The time when the timer expires, in milliseconds
    pub expire_ms: usize,
    /// The task to be woken up when the timer expires
    pub task: Arc<TaskControlBlock>,
}

impl PartialEq for TimerCondVar {
    fn eq(&self, other: &Self) -> bool {
        self.expire_ms == other.expire_ms
    }
}
impl Eq for TimerCondVar {}
impl PartialOrd for TimerCondVar {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let a = -(self.expire_ms as isize);
        let b = -(other.expire_ms as isize);
        Some(a.cmp(&b))
    }
}

impl Ord for TimerCondVar {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

lazy_static! {
    /// TIMERS: global instance: set of timer condvars
    static ref TIMERS: UPSafeCell<BinaryHeap<TimerCondVar>> =
        unsafe { UPSafeCell::new(BinaryHeap::<TimerCondVar>::new()) };
}

/// Add a timer
pub fn add_timer(expire_ms: usize, task: Arc<TaskControlBlock>) {
    // trace!(
    //     "kernel:pid[{}] add_timer",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    let mut timers = TIMERS.exclusive_access();
    timers.push(TimerCondVar { expire_ms, task });
}

/// Remove a timer
pub fn remove_timer(task: Arc<TaskControlBlock>) {
    //trace!("kernel:pid[{}] remove_timer", current_task().unwrap().process.upgrade().unwrap().getpid());
    //trace!("kernel: remove_timer");
    let mut timers = TIMERS.exclusive_access();
    let mut temp = BinaryHeap::<TimerCondVar>::new();
    for condvar in timers.drain() {
        if Arc::as_ptr(&task) != Arc::as_ptr(&condvar.task) {
            temp.push(condvar);
        }
    }
    timers.clear();
    timers.append(&mut temp);
    //trace!("kernel: remove_timer END");
}

/// Check if the timer has expired
pub fn check_timer() {
    // trace!(
    //     "kernel:pid[{}] check_timer",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    let current_ms = get_time_ms();
    let mut timers = TIMERS.exclusive_access();
    while let Some(timer) = timers.peek() {
        if timer.expire_ms <= current_ms {
            #[cfg(target_arch = "riscv64")]
            {
                use crate::task::wakeup_task;
                wakeup_task(Arc::clone(&timer.task));
            }
            #[cfg(target_arch = "loongarch64")]
            {
                use crate::task::add_task;
                add_task(Arc::clone(&timer.task));
            }
            timers.pop();
        } else {
            break;
        }
    }
}
