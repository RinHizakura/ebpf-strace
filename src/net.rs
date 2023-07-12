use crate::common::*;

#[repr(C)]
struct PipeArgs {
    pipefd: [c_int; 2],
}
unsafe impl plain::Plain for PipeArgs {}

fn format_fd(fd: &c_int) -> String {
    fd.to_string()
}

pub(super) fn handle_pipe_args(args: &[u8]) -> String {
    let pipe = get_args::<PipeArgs>(args);

    let pipefd = format_arr(&pipe.pipefd, 2, format_fd);
    return format!("{}", pipefd);
}
