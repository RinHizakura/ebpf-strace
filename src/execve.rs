use crate::common::*;

#[repr(C)]
struct ExecveArgs {
    pathname: [u8; BUF_SIZE],
    argv: [[u8; BUF_SIZE]; ARR_ENT_SIZE],
    envp: usize,
    argc: u8,
    envp_cnt: u8,
}
unsafe impl plain::Plain for ExecveArgs {}

pub(super) fn handle_execve_args(args: &[u8]) -> String {
    let execve = get_args::<ExecveArgs>(args);

    let pathname = format_str(&execve.pathname);
    let argv_list = format_arr(&execve.argv, execve.argc as usize, format_str);

    return format!(
        "{}, {}, 0x{:x} /* {} var{} */",
        pathname,
        argv_list,
        execve.envp,
        execve.envp_cnt,
        if execve.envp_cnt > 1 { "s" } else { "" }
    );
}
