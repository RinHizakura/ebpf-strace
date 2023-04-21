use crate::syscall::common::*;
use plain::Plain;

const ARGV_MAX_CNT: usize = 4;
#[repr(C)]
struct ExecveArgs {
    pathname: [u8; BUF_SIZE],
    argv: [[u8; BUF_SIZE]; ARGV_MAX_CNT],
    envp: usize,
    argc: u8,
    envp_cnt: u8,
}
unsafe impl Plain for ExecveArgs {}

pub(super) fn handle_execve_args(args: &[u8]) {
    let size = std::mem::size_of::<ExecveArgs>();
    let slice = &args[0..size];
    let execve = plain::from_bytes::<ExecveArgs>(slice).expect("Fail to cast bytes to ExecveArgs");
    let printed_argc = (execve.argc as usize).min(ARGV_MAX_CNT);

    eprint!("(");
    format_str(&execve.pathname);

    eprint!("[");
    for idx in 0..printed_argc {
        format_str(&execve.argv[idx]);
    }
    eprint!(
        "{}], ",
        if execve.argc as usize > ARGV_MAX_CNT {
            "..."
        } else {
            ""
        }
    );

    eprint!("0x{:x} /* {} vars */)", execve.envp, execve.envp_cnt);
}
