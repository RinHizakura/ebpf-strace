use anyhow::{anyhow, Result};
use libc::{execvp as __execvp, fork as __fork, getpid as __getpid};
use std::ffi::CString;
use std::io::Error;

/* Reference: https://github.com/samwho/rust-debugger/blob/master/src/sys/mod.rs#L48 */
pub fn execvp(cmd: &Vec<String>) -> Result<()> {
    if cmd.is_empty() {
        return Err(anyhow!("Command cannot be empty"));
    }

    let mut cstr_array = Vec::with_capacity(cmd.len());
    for arg in cmd {
        cstr_array.push(CString::new(arg.clone())?);
    }

    let mut ptr_array = Vec::with_capacity(cmd.len() + 1);
    for arg in &cstr_array {
        ptr_array.push(arg.as_ptr());
    }
    /* We should NULL terminate the array! */
    ptr_array.push(std::ptr::null());

    unsafe {
        __execvp(*ptr_array.first().unwrap(), ptr_array.as_ptr());
    }

    /* Return error here because execvp is expected to not return */
    Err(anyhow!(format!(
        "Failed to execve: {}",
        Error::last_os_error()
    )))
}

pub fn fork() -> i32 {
    unsafe { __fork() }
}

pub fn getpid() -> i32 {
    unsafe { __getpid() }
}
