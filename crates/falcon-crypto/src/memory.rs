use std::fmt;
use std::ops::{Deref, DerefMut};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// Prevent core dumps so a crash can't spill key material to disk.
pub fn harden_process() -> bool {
    #[cfg(unix)]
    {
        let mut ok = true;
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
            ok = false;
        }

        #[cfg(target_os = "linux")]
        {
            if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
                ok = false;
            }
        }

        ok
    }

    #[cfg(not(unix))]
    {
        true
    }
}

fn lock_pages(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }

    #[cfg(unix)]
    {
        unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
    }

    #[cfg(windows)]
    {
        unsafe {
            windows_sys::Win32::System::Memory::VirtualLock(ptr as *const core::ffi::c_void, len)
                != 0
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
        false
    }
}

fn unlock_pages(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }

    #[cfg(unix)]
    unsafe {
        let _ = libc::munlock(ptr as *const libc::c_void, len);
    }

    #[cfg(windows)]
    unsafe {
        let _ = windows_sys::Win32::System::Memory::VirtualUnlock(
            ptr as *const core::ffi::c_void,
            len,
        );
    }
}

// Heap-boxed so moving the struct doesn't invalidate the mlock'd virtual address.
pub struct SecureArray<const N: usize> {
    inner: Box<[u8; N]>,
    locked: bool,
}

impl<const N: usize> SecureArray<N> {
    pub fn zeroed() -> Self {
        let inner = Box::new([0u8; N]);
        let locked = lock_pages(inner.as_ptr(), N);
        Self { inner, locked }
    }

    pub fn from_mut_array(src: &mut [u8; N]) -> Self {
        let mut buf = Self::zeroed();
        buf.inner.copy_from_slice(src);
        src.zeroize();
        buf
    }

    pub fn from_slice(src: &[u8]) -> Option<Self> {
        if src.len() != N {
            return None;
        }
        let mut buf = Self::zeroed();
        buf.inner.copy_from_slice(src);
        Some(buf)
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.inner.as_slice().ct_eq(other.inner.as_slice()))
    }

    pub fn as_array(&self) -> &[u8; N] {
        &self.inner
    }

    pub fn as_array_mut(&mut self) -> &mut [u8; N] {
        &mut self.inner
    }
}

impl<const N: usize> Clone for SecureArray<N> {
    fn clone(&self) -> Self {
        let mut copy = Self::zeroed();
        copy.inner.copy_from_slice(self.inner.as_slice());
        copy
    }
}

impl<const N: usize> Deref for SecureArray<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<const N: usize> DerefMut for SecureArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<const N: usize> Drop for SecureArray<N> {
    fn drop(&mut self) {
        self.inner.zeroize();
        if self.locked {
            unlock_pages(self.inner.as_ptr(), N);
        }
    }
}

impl<const N: usize> fmt::Debug for SecureArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureArray<{N}>([redacted])")
    }
}

pub struct SecureBytes {
    inner: Vec<u8>,
}

impl SecureBytes {
    pub fn from_vec(inner: Vec<u8>) -> Self {
        Self { inner }
    }

    pub fn from_string(mut s: String) -> Self {
        let bytes = s.as_bytes().to_vec();
        s.zeroize();
        Self { inner: bytes }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBytes([redacted; {} bytes])", self.inner.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_and_zeroizes_source() {
        let mut raw = [0x42u8; 32];
        let sec = SecureArray::from_mut_array(&mut raw);
        assert_eq!(raw, [0u8; 32]);
        let dbg = format!("{sec:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("42"));
    }

    #[test]
    fn constant_time_eq_works() {
        let a = SecureArray::<16>::from_slice(&[7u8; 16]).unwrap();
        let b = SecureArray::<16>::from_slice(&[7u8; 16]).unwrap();
        let c = SecureArray::<16>::from_slice(&[8u8; 16]).unwrap();
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }

    #[test]
    fn harden_process_does_not_panic() {
        let _ = harden_process();
    }
}
