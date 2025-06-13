//! Signal flags and function for convert signal flag to integer & string

use bitflags::*;

bitflags! {
    /// Signal flags
    pub struct SignalFlags: u32 {
        // Default signal handling
        const SIGDEF = 1;
        const SIGHUP = 1 << 1; 
        /// Interrupt
        const SIGINT = 1 << 2;
        const SIGQUIT = 1 << 3;
        /// Illegal instruction
        const SIGILL = 1 << 4;
        const SIGTRAP = 1 << 5;
        /// Abort
        const SIGABRT = 1 << 6;
        const SIGBUS = 1 << 7;
        /// Floating point exception
        const SIGFPE = 1 << 8;
        const SIGKILL = 1 << 9;
        const SIGUSR1 = 1 << 10;
        /// Segmentation fault
        const SIGSEGV = 1 << 11;
        const SIGUSR2 = 1 << 12;
        const SIGPIPE = 1 << 13;
        const SIGALRM = 1 << 14;
        const SIGTERM = 1 << 15;
        const SIGSTKFLT = 1 << 16;
        const SIGCHLD = 1 << 17;
        const SIGCONT = 1 << 18;
        const SIGSTOP = 1 << 19;
        const SIGTSTP = 1 << 20;
        const SIGTTIN = 1 << 21;
        const SIGTTOU = 1 << 22;
        const SIGURG = 1 << 23;
        const SIGXCPU = 1 << 24;
        const SIGXFSZ = 1 << 25;
        const SIGVTALRM = 1 << 26;
        const SIGPROF = 1 << 27;
        const SIGWINCH = 1 << 28;
        const SIGIO = 1 << 29;
        const SIGPWR = 1 << 30;
        const SIGSYS = 1 << 31;
    }
}

impl SignalFlags {
    /// convert signal flag to integer & string
    pub fn check_error(&self) -> Option<(i32, &'static str)> {
        if self.contains(Self::SIGINT) {
            Some((-2, "Killed, SIGINT=2"))
        } else if self.contains(Self::SIGILL) {
            Some((-4, "Illegal Instruction, SIGILL=4"))
        } else if self.contains(Self::SIGABRT) {
            Some((-6, "Aborted, SIGABRT=6"))
        } else if self.contains(Self::SIGFPE) {
            Some((-8, "Erroneous Arithmetic Operation, SIGFPE=8"))
        } else if self.contains(Self::SIGKILL) {
            Some((-9, "Killed, SIGKILL=9"))
        } else if self.contains(Self::SIGSEGV) {
            Some((-11, "Segmentation Fault, SIGSEGV=11"))
        } else {
            // warn!("[kernel] signalflags check_error  {:?}", self);
            None
        }
    }
}

pub fn send_signal_to_thread(_tid: usize, _sig: SignalFlags) {
    // let tid2task = TID_TO_TASK.lock();
    // if let Some(task) = tid2task.get(&tid) {
    //     add_signal(Arc::clone(task), sig);
    // }
    unimplemented!()
}
