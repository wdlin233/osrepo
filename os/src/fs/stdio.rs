use super::File;
use crate::mm::UserBuffer;
use crate::task::suspend_current_and_run_next;
use polyhal::debug_console::DebugConsole;

/// stdin file for getting chars from console
pub struct Stdin;

/// stdout file for putting chars to console
pub struct Stdout;

impl File for Stdin {
    fn readable(&self) -> bool {
        true
    }
    fn writable(&self) -> bool {
        false
    }
    fn read(&self, mut user_buf: UserBuffer) -> usize {
        assert_eq!(user_buf.len(), 1);
        assert!(!user_buf.buffers.is_empty(), "UserBuffer has no buffers");
        assert!(user_buf.buffers[0].len() >= 1, "Buffer too small");
        // busy loop
        let c: u8;
        loop {
            if let Some(ch) = DebugConsole::getchar() {
                c = ch;
                break;
            }
            suspend_current_and_run_next();
        }
        user_buf.buffers[0][0] = c as u8;
        1
    }
    fn write(&self, _user_buf: UserBuffer) -> usize {
        panic!("Cannot write to stdin!");
    }
    fn state(&self) -> Option<super::Stat> {
        unimplemented!()
    }
}

impl File for Stdout {
    fn readable(&self) -> bool {
        false
    }
    fn writable(&self) -> bool {
        true
    }
    fn read(&self, _user_buf: UserBuffer) -> usize {
        panic!("Cannot read from stdout!");
    }
    fn write(&self, user_buf: UserBuffer) -> usize {
        // for buffer in user_buf.buffers.iter() {
        //     //print!("{}", core::str::from_utf8(*buffer).unwrap());
        //     // for &b in *buffer {
        //     print!("{}", *buffer as char);
        //     // }
        // }
        for buffer in user_buf.buffers.iter() {
            match core::str::from_utf8(*buffer) {
                Ok(s) => print!("{}", s),
                Err(_) => {
                    continue;
                }
            }
        }
        user_buf.len()
    }
    fn state(&self) -> Option<super::Stat> {
        unimplemented!()
    }
}
