use crate::syscall::common::*;

#[repr(C)]
struct OpenArgs {
    pathname: [u8; BUF_SIZE],
    flags: i32,
}
unsafe impl plain::Plain for OpenArgs {}

pub(super) fn handle_open_args(args: &[u8]) -> String {
    let open = get_args::<OpenArgs>(args);

    let pathname = format_str(&open.pathname);
    return format!("{}, {}", pathname, open.flags);
}

#[repr(C)]
struct OpenAtArgs {
    pathname: [u8; BUF_SIZE],
    dirfd: i32,
    flags: i32,
}
unsafe impl plain::Plain for OpenAtArgs {}

pub(super) fn handle_openat_args(args: &[u8]) -> String {
    let openat = get_args::<OpenAtArgs>(args);

    let pathname = format_str(&openat.pathname);
    return format!("{}, {}, {}", openat.dirfd, pathname, openat.flags);
}

#[repr(C)]
struct CloseArgs {
    fd: i32,
}
unsafe impl plain::Plain for CloseArgs {}

pub(super) fn handle_close_args(args: &[u8]) -> String {
    let close = get_args::<CloseArgs>(args);

    return format!("{}", close.fd);
}
