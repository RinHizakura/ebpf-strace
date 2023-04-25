use crate::syscall::common::*;

#[repr(C)]
struct OpenArgs {
    pathname: [u8; BUF_SIZE],
    flags: i32,
}
unsafe impl plain::Plain for OpenArgs {}

pub(super) fn handle_open_args(args: &[u8]) {
    let open = get_args::<OpenArgs>(args);

    eprint!("({:?},", open.pathname);
    format_str(&open.pathname);
    eprint!("{})", open.flags);
}
