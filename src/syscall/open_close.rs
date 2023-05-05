use crate::syscall::common::*;
use libc::O_RDONLY;

pub const OPENFLAGS_DESCS: &[FlagDesc] = &[FlagDesc {
    val: O_RDONLY,
    name: "O_RDONLY",
}];

#[repr(C)]
struct OpenArgs {
    pathname: [u8; BUF_SIZE],
    flags: i32,
}
unsafe impl plain::Plain for OpenArgs {}

pub(super) fn handle_open_args(args: &[u8]) -> String {
    let open = get_args::<OpenArgs>(args);

    let pathname = format_str(&open.pathname);
    let flags = format_flags(open.flags, '|', OPENFLAGS_DESCS);
    return format!("{}, {}", pathname, flags);
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
    let flags = format_flags(openat.flags, '|', OPENFLAGS_DESCS);
    return format!("{}, {}, {}", openat.dirfd, pathname, flags);
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
