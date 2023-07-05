use std::ffi::c_int;

use crate::common::*;

use libc::{
    mode_t, O_ACCMODE, O_APPEND, O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY, O_DSYNC, O_EXCL,
    O_NOATIME, O_NOCTTY, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_RDONLY, O_RDWR, O_SYNC, O_TMPFILE,
    O_TRUNC, O_WRONLY,
};

const OPEN_FLAGS_DESCS: &[Desc] = &[
    /* access */
    desc!(O_RDONLY),
    desc!(O_WRONLY),
    desc!(O_RDWR),
    desc!(O_ACCMODE),
    /* mode */
    desc!(O_CREAT),
    desc!(O_EXCL),
    desc!(O_NOCTTY),
    desc!(O_TRUNC),
    desc!(O_APPEND),
    desc!(O_NONBLOCK),
    desc!(O_SYNC),
    desc!(O_DSYNC),
    desc!(O_DIRECT),
    //desc!(O_LARGEFILE), <- This is also set to 0 for gnu/b64 platform
    desc!(O_NOFOLLOW),
    desc!(O_NOATIME),
    desc!(O_CLOEXEC),
    desc!(O_PATH),
    desc!(O_TMPFILE),
    desc!(O_DIRECTORY),
];

#[repr(C)]
struct OpenArgs {
    pathname: [u8; BUF_SIZE],
    flags: c_int,
    mode: mode_t,
}
unsafe impl plain::Plain for OpenArgs {}

pub(super) fn handle_open_args(args: &[u8]) -> String {
    let open = get_args::<OpenArgs>(args);

    let pathname = format_str(&open.pathname);
    let flags = format_flags(open.flags as u64, '|', OPEN_FLAGS_DESCS);
    let result = if (open.flags & (O_CREAT | O_TMPFILE)) != 0 {
        format!("{}, {}, 0{:o}", pathname, flags, open.mode)
    } else {
        format!("{}, {}", pathname, flags)
    };

    return result;
}

#[repr(C)]
struct OpenAtArgs {
    pathname: [u8; BUF_SIZE],
    dirfd: c_int,
    flags: c_int,
    mode: mode_t,
}
unsafe impl plain::Plain for OpenAtArgs {}

pub(super) fn handle_openat_args(args: &[u8]) -> String {
    let openat = get_args::<OpenAtArgs>(args);

    let dirfd = format_dirfd(openat.dirfd);
    let pathname = format_str(&openat.pathname);
    let flags = format_flags(openat.flags as u64, '|', OPEN_FLAGS_DESCS);
    let result = if (openat.flags & (O_CREAT | O_TMPFILE)) != 0 {
        format!("{}, {}, {}, 0{:o}", dirfd, pathname, flags, openat.mode)
    } else {
        format!("{}, {}, {}", dirfd, pathname, flags)
    };

    return result;
}

#[repr(C)]
struct CloseArgs {
    fd: c_int,
}
unsafe impl plain::Plain for CloseArgs {}

pub(super) fn handle_close_args(args: &[u8]) -> String {
    let close = get_args::<CloseArgs>(args);

    return format!("{}", close.fd);
}
