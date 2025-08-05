//! RISC-V & LoongArch timer-related functionality

use core::cmp::Ordering;

use core::{
    //cmp::Ordering,
    ops::{Add, AddAssign, Sub},
};

use crate::config::CLOCK_FREQ;
use crate::config::{MSEC_PER_SEC, TICKS_PER_SEC};
use crate::signal::SignalFlags;
use crate::sync::UPSafeCell;
use crate::task::TaskControlBlock;
use alloc::collections::BinaryHeap;
use alloc::sync::Arc;
use lazy_static::*;
#[cfg(target_arch = "loongarch64")]
use loongarch64::time::{get_timer_freq, Time};
#[cfg(target_arch = "riscv64")]
use riscv::register::time;

/// The number of microseconds per second
pub const NSEC_PER_SEC: usize = 1_000_000_000;
pub const NSEC_PER_MSEC: usize = 1_000_000;
pub const NSEC_PER_USEC: usize = 1_000;

pub const USEC_PER_SEC: usize = 1_000_000;
pub const USEC_PER_MSEC: usize = 1_000;

#[allow(dead_code)]
const MICRO_PER_SEC: usize = 1_000_000;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

impl TimeVal {
    pub fn new(sec: usize, usec: usize) -> Self {
        Self { sec, usec }
    }
    pub fn now() -> Self {
        let now_time = get_time_ms();
        Self {
            sec: now_time / 1000,
            usec: (now_time % 1000) * 1000,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.sec == 0 && self.usec == 0
    }
}

impl Add for TimeVal {
    type Output = TimeVal;

    fn add(self, rhs: Self) -> Self::Output {
        let usec = self.usec + rhs.usec;
        Self {
            sec: self.sec + rhs.sec + usec / 1_000_000,
            usec: usec % 1_000_000,
        }
    }
}

impl PartialOrd for TimeVal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.sec > other.sec {
            Some(Ordering::Greater)
        } else if self.sec < other.sec {
            Some(Ordering::Less)
        } else {
            if self.usec > other.usec {
                Some(Ordering::Greater)
            } else if self.usec < other.usec {
                Some(Ordering::Less)
            } else {
                Some(Ordering::Equal)
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Itimerval {
    /// Interval for periodic timer
    pub it_interval: TimeVal,
    /// Time until next expiration
    pub it_value: TimeVal,
}

impl Itimerval {
    pub fn new() -> Self {
        Self {
            it_interval: TimeVal::new(0, 0),
            it_value: TimeVal::new(0, 0),
        }
    }
}
///以实际（即挂钟）时间倒计时。在每次到期时，都会生成一个 SIGALRM 信号
pub const ITIMER_REAL: usize = 0;
/// 此计时器根据进程消耗的用户模式 CPU 时间倒计时。（测量值包括进程中所有线程消耗的 CPU 时间。
/// 在每次到期时，都会生成一个 SIGVTALRM 信号
pub const ITIMER_VIRTUAL: usize = 1;
/// 此计时器根据进程消耗的总 CPU 时间（即用户和系统）进行倒计时。（测量值包括进程中所有线程消耗的 CPU 时间。
/// 在每次到期时，都会生成一个 SIGPROF 信号。
pub const ITIMER_PROF: usize = 2;

/// 三种 itimer,实际只会使用ITIMER_REAL
pub struct Timer {
    pub inner: UPSafeCell<TimerInner>,
}

pub struct TimerInner {
    pub timer: Itimerval,
    pub last_time: TimeVal,
    pub once: bool,
    pub sig: SignalFlags,
}

impl TimerInner {
    pub fn new() -> Self {
        Self {
            timer: Itimerval::new(),
            last_time: TimeVal::new(0, 0),
            once: false,
            sig: SignalFlags::empty(),
        }
    }
}

impl Timer {
    pub fn new() -> Self {
        unsafe {
            Self {
                inner: UPSafeCell::new(TimerInner::new()),
            }
        }
    }
    pub fn set_timer(&self, new: Itimerval, newsig: SignalFlags) {
        let inner = self.inner.get_unchecked_mut();
        inner.timer = new;
        inner.once = false;
        inner.last_time = TimeVal::new(0, 0);
        inner.sig = newsig;
    }
    pub fn set_last_time(&self, last_time: TimeVal) {
        self.inner.get_unchecked_mut().last_time = last_time;
    }
    pub fn set_trigger_once(&self, once: bool) {
        self.inner.get_unchecked_mut().once = once;
    }
    pub fn trigger_once(&self) -> bool {
        self.inner.get_unchecked_ref().once
    }
    pub fn last_time(&self) -> TimeVal {
        self.inner.get_unchecked_ref().last_time
    }
    pub fn timer(&self) -> Itimerval {
        self.inner.get_unchecked_ref().timer
    }
    pub fn sig(&self) -> SignalFlags {
        self.inner.get_unchecked_ref().sig
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Traditional UNIX timespec structures represent elapsed time, measured by the system clock
/// # *CAUTION*
/// tv_sec & tv_usec should be usize.
/// SaZiKK impl TimeSpec ToT
pub struct TimeSpec {
    /// The tv_sec member represents the elapsed time, in whole seconds.
    pub tv_sec: usize,
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
            tv_sec: sec,
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
            tv_sec: 0,
            tv_nsec: 0,
        }
    }
    pub fn from_tick(tick: usize) -> Self {
        Self {
            tv_sec: tick / CLOCK_FREQ,
            tv_nsec: (tick % CLOCK_FREQ) * NSEC_PER_SEC / CLOCK_FREQ,
        }
    }
    pub fn from_s(s: usize) -> Self {
        Self {
            tv_sec: s,
            tv_nsec: 0,
        }
    }
    pub fn from_ms(ms: usize) -> Self {
        Self {
            tv_sec: ms / MSEC_PER_SEC,
            tv_nsec: (ms % MSEC_PER_SEC) * NSEC_PER_MSEC,
        }
    }
    pub fn from_us(us: usize) -> Self {
        Self {
            tv_sec: us / USEC_PER_SEC,
            tv_nsec: (us % USEC_PER_SEC) * NSEC_PER_USEC,
        }
    }
    pub fn from_ns(ns: usize) -> Self {
        Self {
            tv_sec: ns / NSEC_PER_SEC,
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

pub fn calculate_left_timespec(endtime: TimeSpec) -> TimeSpec {
    let nowtime = get_time_spec();
    let mut endsec = endtime.tv_sec;
    let mut nsec: isize = endtime.tv_nsec as isize - nowtime.tv_nsec as isize;
    if nsec < 0 {
        endsec -= 1;
        nsec = 1_000_000_000isize + nsec;
    }
    TimeSpec {
        tv_sec: endsec - nowtime.tv_sec,
        tv_nsec: nsec as usize,
    }
}

/// Get the current time in ticks
pub fn get_time() -> usize {
    #[cfg(target_arch = "riscv64")]
    return time::read();
    #[cfg(target_arch = "loongarch64")]
    return Time::read();
}

/// Get the current time in milliseconds
pub fn get_time_ms() -> usize {
    #[cfg(target_arch = "riscv64")]
    return time::read() * MSEC_PER_SEC / CLOCK_FREQ;
    #[cfg(target_arch = "loongarch64")]
    return Time::read() / (get_timer_freq() / MSEC_PER_SEC);
}

/// get current time in microseconds
pub fn get_time_us() -> usize {
    #[cfg(target_arch = "riscv64")]
    return time::read() * MICRO_PER_SEC / CLOCK_FREQ;
    #[cfg(target_arch = "loongarch64")]
    return Time::read() * MICRO_PER_SEC / get_timer_freq();
}

#[cfg(target_arch = "riscv64")]
/// Set the next timer interrupt
pub fn set_next_trigger() {
    use crate::hal::utils::set_timer;
    set_timer(get_time() + CLOCK_FREQ / TICKS_PER_SEC);
}

pub fn get_time_spec() -> TimeSpec {
    let time = get_time_ms();
    TimeSpec {
        tv_sec: time / 1000,
        tv_nsec: (time % 1000) * 1000000,
    }
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
    debug!("in add timer");
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
    let mut timers: core::cell::RefMut<'_, BinaryHeap<TimerCondVar>> = TIMERS.exclusive_access();
    while let Some(timer) = timers.peek() {
        debug!("in check timer, peek ok");
        if timer.expire_ms <= current_ms {
            debug!(
                "expire is : {}, current is : {}",
                timer.expire_ms, current_ms
            );
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
