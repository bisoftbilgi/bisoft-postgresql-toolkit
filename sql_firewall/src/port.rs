use libc::NI_MAXHOST;
use std::ffi::{c_char, CStr, CString};

use pgrx::pg_sys;

extern "C" {
    fn sqlfw_port_application_name(port: *mut pg_sys::Port) -> *const c_char;
    fn sqlfw_port_client_addr(
        port: *mut pg_sys::Port,
        buffer: *mut c_char,
        buffer_len: usize,
    ) -> bool;
}

pub fn current_port() -> *mut pg_sys::Port {
    unsafe { pg_sys::MyProcPort }
}

pub fn application_name(port: *mut pg_sys::Port) -> Option<String> {
    unsafe {
        let ptr = sqlfw_port_application_name(port);
        cstr_to_string(ptr)
    }
}

pub fn client_addr(port: *mut pg_sys::Port) -> Option<String> {
    if port.is_null() {
        return None;
    }
    let mut buffer = vec![0i8; NI_MAXHOST as usize];
    let ok = unsafe { sqlfw_port_client_addr(port, buffer.as_mut_ptr() as *mut c_char, buffer.len()) };
    if ok {
        cstr_to_string(buffer.as_ptr() as *const c_char)
    } else {
        None
    }
}

pub fn current_application_name() -> Option<String> {
    application_name(current_port()).or_else(|| guc_option("application_name"))
}

pub fn current_client_addr() -> Option<String> {
    client_addr(current_port())
}

fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_owned()) }
    }
}

fn guc_option(name: &str) -> Option<String> {
    let cname = CString::new(name).ok()?;
    unsafe {
        let ptr = pg_sys::GetConfigOptionByName(cname.as_ptr(), std::ptr::null_mut(), false);
        if ptr.is_null() {
            return None;
        }
        // CRITICAL: Clone the string before freeing PostgreSQL's palloc'd memory
        let result = CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_owned());
        // Free the palloc'd buffer to prevent memory leak
        pg_sys::pfree(ptr as *mut std::ffi::c_void);
        result
    }
}
