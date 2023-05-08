use crate::syscall::common::*;

use libc::{
    O_ACCMODE, O_APPEND, O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY, O_DSYNC, O_EXCL, O_NOATIME,
    O_NOCTTY, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_RDONLY, O_RDWR, O_SYNC, O_TMPFILE, O_TRUNC,
    O_WRONLY,
};

pub const OPENFLAGS_DESCS: &[FlagDesc] = &[
    /* access */
    flag_desc!(O_RDONLY),
    flag_desc!(O_WRONLY),
    flag_desc!(O_RDWR),
    flag_desc!(O_ACCMODE),
    /* mode */
    flag_desc!(O_CREAT),
    flag_desc!(O_EXCL),
    flag_desc!(O_NOCTTY),
    flag_desc!(O_TRUNC),
    flag_desc!(O_APPEND),
    flag_desc!(O_NONBLOCK),
    flag_desc!(O_SYNC),
    flag_desc!(O_DSYNC),
    flag_desc!(O_DIRECT),
    //flag_desc!(O_LARGEFILE), <- This is also set to 0 for gnu/b64 platform
    flag_desc!(O_NOFOLLOW),
    flag_desc!(O_NOATIME),
    flag_desc!(O_CLOEXEC),
    flag_desc!(O_PATH),
    flag_desc!(O_TMPFILE),
    flag_desc!(O_DIRECTORY),
];

fn format_dirfd(fd: i32) -> String {
    if fd == libc::AT_FDCWD {
        "AT_FDCWD".to_string()
    } else {
        // TODO
        "".to_string()
    }
}

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

    let dirfd = format_dirfd(openat.dirfd);
    let pathname = format_str(&openat.pathname);
    let flags = format_flags(openat.flags, '|', OPENFLAGS_DESCS);
    return format!("{}, {}, {}", dirfd, pathname, flags);
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
