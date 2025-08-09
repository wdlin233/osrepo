//! manager users and groups

use lazy_static::*;
use crate::sync::UPSafeCell;
use alloc::{
    sync::Arc,
    vec::Vec,
};

mod id;
mod group;
mod users;

pub use group::{Group};
pub use users::{User};
pub use id::{Gid,Uid};


/// to manager user
pub struct UserManager {
    /// current user
    current: Option<Arc<User>>,
}

impl UserManager {
    /// new a manager
    pub fn new()->Self {
        UserManager {
            current: Some(User::new()),
        }
    }

    ///Get current task in cloning semanteme
    pub fn current(&self) -> Option<Arc<User>> {
        self.current.as_ref().map(Arc::clone)
    }
}

/// to manager groups
pub struct GroupManager {
    /// groups
    groups: Vec<Arc<Group>>
}

impl GroupManager {
    /// new a GroupManager
    pub fn new()-> Self {
        GroupManager{
            groups: Vec::new(),
        }
    }
    
    /// add a group
    pub fn push(&mut self,group: Arc<Group>) {
        self.groups.push(group);
    }
}

lazy_static! {
    /// record current user
    pub static ref CURRENT_USER: UPSafeCell<UserManager> = 
        unsafe { UPSafeCell::new(UserManager::new())};
    /// record all groups
    pub static ref GROUPS: UPSafeCell<GroupManager> = 
        unsafe { UPSafeCell::new(GroupManager::new())};
}

/// get current user
pub fn current_user()->Option<Arc<User>> {
    CURRENT_USER.exclusive_access().current()
}

