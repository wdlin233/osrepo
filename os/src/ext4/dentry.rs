#![allow(missing_docs)] 

use alloc::{
    string::{String, ToString}, sync::{Arc, Weak}
};

use crate::{ext4::{Ext4Inode, Ext4SuperBlock}, fs::StatMode};

use alloc::collections::BTreeMap;
use crate::fs::defs::{OpenFlags};
use crate::fs::File;
use spin::mutex::Mutex;

// dentry​​：负责路径解析和目录结构管理
// inode​​：负责文件数据和元数据管理
pub struct Ext4Dentry {
    pub name: String,
    pub inode: Mutex<Option<Arc<Ext4Inode>>>,
    pub superblock: Arc<Ext4SuperBlock>,
    pub father: Option<Arc<Ext4Dentry>>,
    pub children: Mutex<BTreeMap<String, Weak<Ext4Dentry>>>,
    pub dentry_type: DentryType,
}

impl Ext4Dentry {
    pub fn new(name: &str, inode: Arc<Ext4Inode>, father: Option<Arc<Ext4Dentry>>) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            superblock: inode.superblock().clone(),
            inode: Mutex::new(Some(inode)),
            father: father,
            children: Mutex::new(BTreeMap::new()),
            dentry_type: DentryType::Invalid,
        })
    }
    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_inode(&self) -> Arc<Ext4Inode> {
        self.inode.lock()
            .as_ref()
            .expect("Inode is not set")
            .clone()
    }

    pub fn get_father(&self) -> Option<Arc<Ext4Dentry>> {
        self.father.clone()
    }

    pub fn path(&self) -> String {
        let mut _path = String::new();
        if let Some(father) = &self.get_father() {
            _path = father.path();
            if _path != "/" {
                _path.push('/');
            }
        } else {
            return String::from("/");
        }
        _path.push_str(&self.get_name());
        _path
    }

    pub fn get_child(&self, name: &str) -> Option<Arc<Ext4Dentry>> {
        let children = self.children.lock();
        if let Some(child) = children.get(name){
            return child.upgrade();    
        }
        // cache finding is optional
        return None;
    }
    pub fn add_child(&self, child: Weak<Ext4Dentry>) {
        let mut children = self.children.lock();
        children.insert(child.upgrade().unwrap().name.clone(), child);
    }

    pub fn get_superblock(&self) -> Arc<Ext4SuperBlock> {
        self.superblock.clone()
    }

    pub fn set_inode(&self, inode: Arc<Ext4Inode>) {
        let mut lock = self.inode.lock();
        *lock = Some(inode);
    } 

    pub fn get_state(&self) -> DentryType {
        self.dentry_type.clone()
    }

    pub fn lookup(self: Arc<Self>, name: &str) -> Option<Arc<Ext4Dentry>> {
        let superblock = self.get_superblock(); 
        let child = self.get_child(name).unwrap();
        let path = self.get_child(name)?.path();
        let res = superblock.ext4.ext4_dir_open(path.as_str()).expect("Failed to open directory");
        
        let inode_ref = superblock.ext4.get_inode_ref(res);
        let mode: StatMode = if inode_ref.inode.is_dir() {
            StatMode::DIR
        } else if inode_ref.inode.is_file() {
            StatMode::FILE
        } else {
            StatMode::NULL
        };
        let child_inode = Arc::new(Ext4Inode::new(res as usize, superblock, mode));
        child.set_inode(child_inode.clone());
        Some(child)
    }

    pub fn new_child(self, name: &str) -> Arc<Ext4Dentry> {
        let dentry_father = self.clone();
        let child = Ext4Dentry::new(
            name, 
            Arc::new(Ext4Inode::new(0, self.get_superblock(), StatMode::FILE)), // use concrete_create, temporarily set inode to 0 
            Some(dentry_father)
        );
        self.add_child(Arc::downgrade(&child));
        child
    }

    pub fn find_dentry_create(&self, name: &str, _type: StatMode) -> Arc<Ext4Dentry> {
        if let Some(child) = self.get_child(name) {
            return child;
        }
        // 如果没有找到，则创建一个新的 dentry
        let new_dentry = self.new_child(name);
        
        //let mut state = new_dentry.get_state();
        //state = DentryType::Dirty;
        //drop(state);
        new_dentry
    }

    pub fn create(self: Arc<Self>, name: &str, _type: StatMode) -> Option<Arc<Ext4Dentry>> {
        if !self.get_inode().is_dir() {
            return None; // 只能在目录中创建
        }
        let spblock = self.clone().get_superblock();
        let _child = self.find_dentry_create(name, _type);
        // 创建一个新的 dentry
        let new_dentry = self.new_child(name);
    
        new_dentry.set_inode(Arc::new(Ext4Inode::new(0, spblock, _type))); // use concrete_create, temporarily set inode to 0
        Some(new_dentry)
    }
    pub fn clear(&self) {
        // 清除 dentry 的状态
        //let mut state = self.get_state();
        //state = DentryType::Invalid;
        unimplemented!()
    }
    pub fn is_dir(&self) -> bool {
        self.get_inode().is_dir()
    }
}

#[derive(Clone, Copy)]
pub enum DentryType {
    Invalid,
    Vaild,
    Dirty,
}


