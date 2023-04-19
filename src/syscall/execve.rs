use crate::syscall::common::*;
use plain::Plain;
use std::str::from_utf8;

#[repr(C)]
struct ExecveArgs {
    pathname: [u8; BUF_SIZE],
    argv: usize,
    envp: usize,
    argc: u8,
    envp_cnt: u8,
}
unsafe impl Plain for ExecveArgs {}

pub(super) fn handle_execve_args(args: &[u8]) {
    let size = std::mem::size_of::<ExecveArgs>();
    let slice = &args[0..size];
    let execve = plain::from_bytes::<ExecveArgs>(slice).expect("Fail to cast bytes to ExecveArgs");

    /* Trickly use the last byte in the buffer to distinguish whether
     * we have a complete C string. */
    if execve.pathname[BUF_SIZE - 1] == 0 {
        let s = from_utf8(&execve.pathname).unwrap();
        eprint!("({}, 0x{:x} /* argc = {} */, 0x{:x})", s, execve.argv, execve.argc, execve.envp);
    } else {
        let len = BUF_SIZE;

        eprint!("(");
        format_buf(&execve.pathname, len);
        eprint!("0x{:x} /* argc = {} */, 0x{:x})", execve.argv, execve.argc, execve.envp);
    }
}
