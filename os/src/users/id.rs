//! Allocator for managing user IDs and group IDs, similar to a process ID allocator.
//! 
//! Provides functionality for allocating and deallocating user and group IDs, 
//! ensuring uniqueness and reusability of IDs.

use alloc::vec::Vec;
use lazy_static::*;
use crate::sync::UPSafeCell;

/// to manager userid and groupid
/// like pid allocator
pub struct IdAllocator {
    current: usize,
    recycled: Vec<usize>,
}

impl IdAllocator {
    /// new a allocator
    pub fn new() -> Self {
        IdAllocator{
            current: 0,
            recycled: Vec::new(),
        }

    }
    /// allocate a new item
    pub fn alloc(&mut self) -> usize {
        if let Some(id) = self.recycled.pop() {
            id
        } else {
            self.current += 1;
            self.current - 1
        }
    }
    /// deallocate an item
    pub fn dealloc(&mut self, id: usize) {
        assert!(id < self.current);
        assert!(
            !self.recycled.iter().any(|i| *i == id),
            "id {} has been deallocated!",
            id
        );
        self.recycled.push(id);
    }
}


lazy_static! {
    /// global allocator for user
    static ref USER_ID_ALLOCAATOR : UPSafeCell<IdAllocator> = unsafe {
        UPSafeCell::new(IdAllocator::new())
    };
    /// global allocator for group
    static ref GROUP_ID_ALLOCAATOR : UPSafeCell<IdAllocator> = unsafe {
        UPSafeCell::new(IdAllocator::new())
    };

}

/// user id
pub struct Uid(pub usize);

impl Drop for Uid {
    fn drop(&mut self) {
        USER_ID_ALLOCAATOR.exclusive_access().dealloc(self.0);
    }
}

impl From<usize> for Uid {
    fn from(v: usize) -> Self {
        Self(v)
    }
}


/// group id
pub struct Gid(pub usize);

impl Drop for Gid {
    fn drop(&mut self) {
        debug!("in drop for gid");
        GROUP_ID_ALLOCAATOR.exclusive_access().dealloc(self.0);
    }
}

impl From<usize> for Gid {
    fn from(v: usize) -> Self {
        Self(v)
    }
}


/// alloc user id
pub fn uid_alloc()-> Uid {
    USER_ID_ALLOCAATOR.exclusive_access().alloc().into()
}

/// alloc group id
pub fn gid_alloc()-> Gid {
    GROUP_ID_ALLOCAATOR.exclusive_access().alloc().into()
}





