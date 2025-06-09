//! groups

use alloc::{
    sync::{ Weak},
    vec::Vec,
    string::String,
};
use super::id::{Uid,Gid,gid_alloc};




/// group to save users
pub struct Group {
    /// group id
    pub gid: Gid,
    /// group name
    pub gname: String,
    /// group members
    pub users: Vec<Weak<Uid>>,
}

impl Group {
    /// new a group 
    pub fn new() -> Self {
        let gid = gid_alloc();
        Group {
            gid,
            gname: String::new(),
            users: Vec::new(),
        }
    }
    /// new a group from gid
    pub fn from_gid(gid: usize)->Self {
        Group{
            gid: Gid(gid),
            gname: String::new(),
            users: Vec::new(),
        }
    }
}


