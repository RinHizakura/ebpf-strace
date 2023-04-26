use crate::syscall::common::*;

const ARGV_MAX_CNT: usize = 4;
#[repr(C)]
struct ExecveArgs {
    pathname: [u8; BUF_SIZE],
    argv: [[u8; BUF_SIZE]; ARGV_MAX_CNT],
    envp: usize,
    argc: u8,
    envp_cnt: u8,
}
unsafe impl plain::Plain for ExecveArgs {}

pub(super) fn handle_execve_args(args: &[u8]) -> String {
    let execve = get_args::<ExecveArgs>(args);
    let printed_argc = (execve.argc as usize).min(ARGV_MAX_CNT);

    let mut s = String::new();
    let pathname = format_str(&execve.pathname);
    s.push_str(&pathname);

    s.push('[');
    for idx in 0..printed_argc {
        s.push_str(&format_str(&execve.argv[idx]));
    }
    if execve.argc as usize > ARGV_MAX_CNT {
        s.push_str("...");
    }

    s.push(']');
    s.push_str(&format!(
        ", 0x{:x} /* {} vars */)",
        execve.envp, execve.envp_cnt
    ));

    s
}
