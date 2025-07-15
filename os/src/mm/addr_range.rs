use hashbrown::HashSet;
use lazy_static::lazy_static;
use polyhal::{pagetable::PAGE_SIZE, VirtAddr};

use crate::sync::UPSafeCell;

#[derive(Copy, Clone, Debug)]
pub struct VAddrRange {
    l: VirtAddr,
    r: VirtAddr,
}
impl VAddrRange {
    pub fn new(start: VirtAddr, end: VirtAddr) -> Self {
        assert!(start <= end, "start {:?} > end {:?}!", start, end);
        Self { l: start, r: end }
    }
    pub fn get_start(&self) -> VirtAddr {
        self.l
    }
    pub fn get_end(&self) -> VirtAddr {
        self.r
    }
    pub fn range(&self) -> (VirtAddr, VirtAddr) {
        (self.l, self.r)
    }
}


impl IntoIterator for VAddrRange {
    type Item = VirtAddr;
    type IntoIter = SimpleRangeIterator;
    fn into_iter(self) -> Self::IntoIter {
        SimpleRangeIterator::new(self.l, self.r)
    }
}
pub struct SimpleRangeIterator {
    current: VirtAddr,
    end: VirtAddr,
}
impl SimpleRangeIterator {
    pub fn new(l: VirtAddr, r: VirtAddr) -> Self {
        Self { current: l, end: r }
    }
}
impl Iterator for SimpleRangeIterator {
    type Item = VirtAddr;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current == self.end {
            None
        } else {
            let t = self.current;
            self.current = self.current + PAGE_SIZE; // aka self.current.step()
            Some(t)
        }
    }
}

//坏地址表，mmap映射坏地址时加入此表
lazy_static! {
    pub static ref BAD_ADDRESS: UPSafeCell<HashSet<usize>> = 
        unsafe { UPSafeCell::new(HashSet::new()) };
}

pub fn insert_bad_address(va: usize) {
    BAD_ADDRESS.exclusive_access().insert(va);
}

pub fn is_bad_address(va: usize) -> bool {
    BAD_ADDRESS.exclusive_access().contains(&va)
}

pub fn remove_bad_address(va: usize) {
    BAD_ADDRESS.exclusive_access().remove(&va);
}