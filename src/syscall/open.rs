use crate::syscall::common::*;
use plain::Plain;

#[repr(C)]
struct OpenArgs {
    pathname: [u8; BUF_SIZE],
    flags: i32,
}
unsafe impl Plain for OpenArgs {}

pub(super) fn handle_open_args(args: &[u8]) {
    let size = std::mem::size_of::<OpenArgs>();
    let slice = &args[0..size];
    let open = plain::from_bytes::<OpenArgs>(slice).expect("Fail to cast bytes to OpenArgs");

    eprint!("({:?},", open.pathname);
    format_str(&open.pathname);
    eprint!("{})", open.flags);
}
