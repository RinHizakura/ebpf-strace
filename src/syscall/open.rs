use crate::syscall::common::*;
use crate::syscall::get_args;
use plain::Plain;

#[repr(C)]
struct OpenArgs {
    pathname: [u8; BUF_SIZE],
    flags: i32,
}
unsafe impl Plain for OpenArgs {}

pub(super) fn handle_open_args(args: &[u8]) {
    let open = get_args::<OpenArgs>(args);

    eprint!("({:?},", open.pathname);
    format_str(&open.pathname);
    eprint!("{})", open.flags);
}
