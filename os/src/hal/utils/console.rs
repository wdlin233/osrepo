//! SBI console driver, for text output
use core::fmt::{self, Write, Arguments};

struct Stdout;

#[cfg(target_arch = "riscv64")]
impl Write for Stdout {
    /// write str to console
    fn write_str(&mut self, s: &str) -> fmt::Result {
        use crate::hal::utils::console_putchar;
        for c in s.chars() {
            console_putchar(c as usize);
        }
        Ok(())
    }
}

use crate::{config::UART, hal::uart::Uart};
use spin::{Lazy, Mutex};

pub struct Console {
    inner: Uart,
}

impl Console {
    pub const fn new(address: usize) -> Self {
        let uart = Uart::new(address);
        Self { inner: uart }
    }
    pub fn write_str(&mut self, str: &str) {
        for ch in str.bytes() {
            self.inner.put(ch)
        }
    }
    pub fn get_char(&mut self) -> Option<u8> {
        self.inner.get()
    }
}

#[cfg(target_arch = "loongarch64")]
impl Write for Console {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.write_str(s);
        Ok(())
    }
}

pub static CONSOLE: Mutex<Console> = Mutex::new(Console::new(UART));

pub fn get_char() -> u8 {
    // todo!根据rcore内部实现推测这里应该是一个阻塞调用
    loop {
        let ch = CONSOLE.lock().get_char();
        if let Some(ch) = ch {
            return ch;
        }
    }
}

/// print to the host console using the format string and arguments.
pub fn _print(args: Arguments) {
    #[cfg(target_arch = "riscv64")]
    Stdout.write_fmt(args).unwrap();
    #[cfg(target_arch = "loongarch64")]
    CONSOLE.lock().write_fmt(args).unwrap()
}

/// Print! macro to the host console using the format string and arguments.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::hal::utils::console::_print(format_args!("{}", format_args!($($arg)*)))
    };
}

/// Println! macro to the host console using the format string and arguments.
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => {
        $crate::print!($($arg)*);
        $crate::print!("\n");
    };
}
