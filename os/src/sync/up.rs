//! Safe Cell for uniprocessor（single cpu core）
//!
//! UPSafeCell is used to wrap a static data structure which can access safely.
//!
//! NOTICE: We should only use it in environment with uniprocessor（single cpu core）, and the kernel can not support task preempting in kernel mode （or trap in kernel mode）.

use core::cell::{RefCell, RefMut};

/// Wrap a static data structure inside it so that we are
/// able to access it without any `unsafe`.
///
/// We should only use it in uniprocessor.
///
/// In order to get mutable reference of inner data, call
/// `exclusive_access`.
pub struct UPSafeCell<T> {
    /// inner data
    inner: RefCell<T>,
}

unsafe impl<T> Sync for UPSafeCell<T> {}

impl<T> UPSafeCell<T> {
    /// User is responsible to guarantee that inner struct is only used in
    /// uniprocessor.
    pub unsafe fn new(value: T) -> Self {
        Self {
            inner: RefCell::new(value),
        }
    }
    /// Panic if the data has been borrowed.
    pub fn exclusive_access(&self) -> RefMut<'_, T> {
        self.inner.borrow_mut()
    }
    pub fn borrow(&self) -> RefMut<'_, T> {
        self.inner.borrow_mut()
    }
}

pub struct SyncUnsafeCell<T>(core::cell::SyncUnsafeCell<T>);

impl<T> SyncUnsafeCell<T> {
    #[inline]
    pub fn new(value: T) -> Self {
        Self(core::cell::SyncUnsafeCell::new(value))
    }

    /// This method is unsafe.
    /// 绕过所有权检查
    #[inline]
    pub fn get_unchecked_mut(&self) -> &mut T {
        unsafe { &mut *self.0.get() }
    }

    #[inline]
    pub fn get(&self) -> *mut T {
        self.0.get()
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.0.get_mut()
    }

    pub fn get_unchecked_ref(&self) -> &T {
        unsafe { &*self.0.get() }
    }
}

