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

    let pathname = format_str(&execve.pathname);

    /* FIXME: We should make this prettier if there's the way :( */
    let mut argv_list = String::new();
    for idx in 0..printed_argc {
        argv_list.push_str(&format_str(&execve.argv[idx]));
        argv_list.push(',');
    }
    // Pop out the last ','
    argv_list.pop();
    if execve.argc as usize > ARGV_MAX_CNT {
        argv_list.push_str("...");
    }

    return format!(
        "{}, [{}], 0x{:x} /* {} var{} */",
        pathname,
        argv_list,
        execve.envp,
        execve.envp_cnt,
        if execve.envp_cnt > 1 { "s" } else { "" }
    );
}
