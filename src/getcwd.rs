use crate::common::*;

#[repr(C)]
struct GetcwdArgs {
    buf: [u8; BUF_SIZE],
    size: usize,
}
unsafe impl plain::Plain for GetcwdArgs {}

pub(super) fn handle_getcwd_args(args: &[u8]) -> String {
    let g = get_args::<GetcwdArgs>(args);
    format!("{}, {}", format_str(&g.buf), g.size)
}
