use std::ffi::CStr;
use std::fmt::{Debug, Formatter, Result as FmtResult};

use libc::c_char;
use widestring::WideCStr;

pub struct Lpcstr(*const c_char);

impl Lpcstr {
    pub fn load(&self) -> Option<&CStr> {
        if self.0.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(self.0) })
        }
    }
}

impl Debug for Lpcstr {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        if let Some(cs) = self.load() {
            Debug::fmt(cs, f)
        } else {
            f.write_str("<null>")
        }
    }
}

pub struct Lpcwstr(*const u16);

impl Lpcwstr {
    pub fn load(&self) -> Option<&WideCStr> {
        if self.0.is_null() {
            None
        } else {
            Some(unsafe { WideCStr::from_ptr_str(self.0) })
        }
    }
}

impl Debug for Lpcwstr {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        if let Some(cs) = self.load() {
            write!(f, "\"{}\"", cs.to_string_lossy())
        } else {
            f.write_str("<null>")
        }
    }
}
