//! users

use alloc::{
    sync::{Arc,Weak},
    vec::Vec,
    string::String,
};
use super::id::{Uid,Gid,uid_alloc,gid_alloc};
use super::group::{Group};
use super::GROUPS;



/// user
pub struct User {
    /// user id
    pub uid: Arc<Uid>,
    /// user name
    pub username: String,
    /// user group
    pub group: Vec<Weak<Gid>>,
    /// password
    pub pwd: String,
    /// home 
    pub homedir: String,
    /// shell
    pub shell: String,
}

impl User {
    /// new a User
    pub fn new()-> Arc<Self> {
        let uid = uid_alloc();
        let mut group = Vec::new();
        let gid = gid_alloc();
        GROUPS.exclusive_access().push(Arc::new(Group::from_gid(gid.0)));
        group.push(Arc::downgrade(&Arc::new(gid)));
        let user = Arc::new(User {
            uid:Arc::new(uid),
            username: String::new(),
            group,
            pwd: String::new(),
            homedir: String::new(),
            shell: String::new(),
        });
        user
    }

    /// get uid
    pub fn getuid(&self)-> usize {
        self.uid.0
    }

    ///get gid
    pub fn getgid(&self)->usize {
        self.group[0].upgrade().unwrap().0
    }
}

