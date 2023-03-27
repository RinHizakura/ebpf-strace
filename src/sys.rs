use anyhow::{anyhow, Result};
use libc::{execvp as __execvp, fork};
use std::ffi::CString;

/* Reference: https://github.com/samwho/rust-debugger/blob/master/src/sys/mod.rs#L48 */
fn execvp(cmd: &Vec<String>) -> Result<()> {
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

pub fn spawn(cmd: Vec<String>) -> Result<i32> {
    let pid = match unsafe { fork() } {
        0 => {
            execvp(&cmd)?;
            unreachable!();
        }
        child_pid => child_pid,
    };

    Ok(pid)
}
