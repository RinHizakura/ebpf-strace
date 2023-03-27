use anyhow::{anyhow, Result};
use libc::{execvp as __execvp, fork as __fork};
use std::ffi::CString;

/* Reference: https://github.com/samwho/rust-debugger/blob/master/src/sys/mod.rs#L48 */
pub fn execvp(cmd: &Vec<String>) -> Result<()> {
    if cmd.is_empty() {
        return Err(anyhow!("Command cannot be empty"));
    }

    let mut cstr_array = Vec::with_capacity(cmd.len());
    for arg in cmd {
        cstr_array.push(CString::new(arg.clone())?);
    }
    let mut ptr_array = Vec::with_capacity(cmd.len());
    for arg in &cstr_array {
        ptr_array.push(arg.as_ptr());
    }

    unsafe {
        __execvp(*ptr_array.first().unwrap(), ptr_array.as_ptr());
    }

    Ok(())
}

pub fn fork() -> i32 {
    unsafe { __fork() }
}
