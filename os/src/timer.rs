//! RISC-V & LoongArch timer-related functionality

use core::cmp::Ordering;

use core::{
    //cmp::Ordering,
    ops::{Add, AddAssign, Sub},
};

use crate::config::CLOCK_FREQ;
use crate::sync::UPSafeCell;
use crate::config::{MSEC_PER_SEC, TICKS_PER_SEC};
use crate::task::{wakeup_futex_task, ProcessControlBlock};
use alloc::collections::BinaryHeap;
use alloc::sync::{Arc, Weak};
use lazy_static::*;
use polyhal::Time;

/// The number of microseconds per second
pub const NSEC_PER_SEC: usize = 1_000_000_000;
pub const NSEC_PER_MSEC: usize = 1_000_000;
pub const NSEC_PER_USEC: usize = 1_000;

pub const USEC_PER_SEC: usize = 1_000_000;
pub const USEC_PER_MSEC: usize = 1_000;

#[allow(dead_code)]
const MICRO_PER_SEC: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Traditional UNIX timespec structures represent elapsed time, measured by the system clock
/// # *CAUTION*
/// tv_sec & tv_usec should be usize.
/// SaZiKK impl TimeSpec ToT
pub struct TimeSpec {
    /// The tv_sec member represents the elapsed time, in whole seconds.
    pub tv_sec:  usize,
    /// The tv_usec member captures rest of the elapsed time, represented as the number of microseconds.
    pub tv_nsec: usize,
}
impl AddAssign for TimeSpec {
    fn add_assign(&mut self, rhs: Self) {
        self.tv_sec += rhs.tv_sec;
        self.tv_nsec += rhs.tv_nsec;
    }
}
impl Add for TimeSpec {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut sec = self.tv_sec + other.tv_sec;
        let mut nsec = self.tv_nsec + other.tv_nsec;
        sec += nsec / NSEC_PER_SEC;
        nsec %= NSEC_PER_SEC;
        Self {
            tv_sec:  sec,
            tv_nsec: nsec,
        }
    }
}

impl Sub for TimeSpec {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let self_ns = self.to_ns();
        let other_ns = other.to_ns();
        if self_ns <= other_ns {
            TimeSpec::new()
        } else {
            TimeSpec::from_ns(self_ns - other_ns)
        }
    }
}

impl Ord for TimeSpec {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.tv_sec.cmp(&other.tv_sec) {
            Ordering::Less => Ordering::Less,
            Ordering::Equal => self.tv_nsec.cmp(&other.tv_nsec),
            Ordering::Greater => Ordering::Greater,
        }
    }
}

impl PartialOrd for TimeSpec {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Default for TimeSpec {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSpec {
    pub fn new() -> Self {
        Self {
            tv_sec:  0,
            tv_nsec: 0,
        }
    }
    pub fn from_tick(tick: usize) -> Self {
        Self {
            tv_sec:  tick / CLOCK_FREQ,
            tv_nsec: (tick % CLOCK_FREQ) * NSEC_PER_SEC / CLOCK_FREQ,
        }
    }
    pub fn from_s(s: usize) -> Self {
        Self {
            tv_sec:  s,
            tv_nsec: 0,
        }
    }
    pub fn from_ms(ms: usize) -> Self {
        Self {
            tv_sec:  ms / MSEC_PER_SEC,
            tv_nsec: (ms % MSEC_PER_SEC) * NSEC_PER_MSEC,
        }
    }
    pub fn from_us(us: usize) -> Self {
        Self {
            tv_sec:  us / USEC_PER_SEC,
            tv_nsec: (us % USEC_PER_SEC) * NSEC_PER_USEC,
        }
    }
    pub fn from_ns(ns: usize) -> Self {
        Self {
            tv_sec:  ns / NSEC_PER_SEC,
            tv_nsec: ns % NSEC_PER_SEC,
        }
    }
    pub fn to_ns(&self) -> usize {
        self.tv_sec * NSEC_PER_SEC + self.tv_nsec
    }
    pub fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }
    pub fn now() -> Self {
        TimeSpec::from_tick(get_time())
    }
}

/// Get the current time in ticks
pub fn get_time() -> usize {
    Time::now().raw()
}

/// Get the current time in milliseconds
pub fn get_time_ms() -> usize {
    Time::now().to_msec()
}

/// get current time in microseconds
pub fn get_time_us() -> usize {
    Time::now().to_usec()
}

#[derive(Debug, PartialEq, Eq)]
pub enum TimerType {
    Futex,
    Stopped,
}

/// condvar for timer
pub struct TimerCondVar {
    /// The time when the timer expires, in milliseconds
    pub expire_ms: usize,
    /// The task to be woken up when the timer expires
    pub task: Weak<ProcessControlBlock>,
    /// The type of the timer
    pub timer_type: TimerType,
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
pub fn add_futex_timer(expire_ms: usize, task: Arc<ProcessControlBlock>) {
    // trace!(
    //     "kernel:pid[{}] add_timer",
    //     current_task().unwrap().process.upgrade().unwrap().getpid()
    // );
    let mut timers = TIMERS.exclusive_access();
    timers.push(TimerCondVar { expire_ms, task: Arc::downgrade(&task), timer_type: TimerType::Futex });
}

pub fn add_stopped_timer(expire_ms: usize, task: Arc<ProcessControlBlock>) {
    let mut timers = TIMERS.exclusive_access();
    timers.push(TimerCondVar { expire_ms, task: Arc::downgrade(&task), timer_type: TimerType::Stopped });
}

/// Remove a timer
pub fn remove_timer(_task: Arc<ProcessControlBlock>) {
    //trace!("kernel:pid[{}] remove_timer", current_task().unwrap().process.upgrade().unwrap().getpid());
    //trace!("kernel: remove_timer");
    unimplemented!("remove_timer is not implemented yet");
    // let mut timers = TIMERS.exclusive_access();
    // let mut temp = BinaryHeap::<TimerCondVar>::new();
    // for condvar in timers.drain() {
    //     if Arc::as_ptr(&task) != Arc::as_ptr(&condvar.task) {
    //         temp.push(condvar);
    //     }
    // }
    // timers.clear();
    // timers.append(&mut temp);
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
            if let Some(task) = timer.task.upgrade() {
                debug!("kernel: check_timer: wake up task pid {} tid {}", task.getpid(), task.gettid());
                if timer.timer_type == TimerType::Futex {
                    // Wake up futex waiters
                    wakeup_futex_task(Arc::clone(&task));
                } else if timer.timer_type == TimerType::Stopped {
                    // Wake up stopped task
                    unimplemented!("Stopped timer is not implemented yet");
                }
            }
            timers.pop();
        } else {
            break;
        }
    }
}
