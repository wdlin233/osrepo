//! File trait & inode(dir, file, pipe, stdin, stdout)

//use alloc::vec::Vec;

//use crate::{fs::BlockDevice, config::BLOCK_SIZE};

/// #fs mod
pub mod fs;

/// #fs inode
pub mod inode;

/// root inode num defines here
pub const ROOT_INO: u32 = 2;
