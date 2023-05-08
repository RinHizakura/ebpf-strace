use crate::syscall::common::*;
use libc::{
    O_ACCMODE, O_APPEND, O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY, O_DSYNC, O_EXCL, O_NOATIME,
    O_NOCTTY, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_RDONLY, O_RDWR, O_SYNC, O_TMPFILE, O_TRUNC,
    O_WRONLY,
};

macro_rules! open_flag_desc {
    ( $flag:expr ) => {
        FlagDesc {
            val: $flag,
            name: stringify!($flag),
        }
    };
}

pub const OPENFLAGS_DESCS: &[FlagDesc] = &[
    /* access */
    open_flag_desc!(O_RDONLY),
    open_flag_desc!(O_WRONLY),
    open_flag_desc!(O_RDWR),
    open_flag_desc!(O_ACCMODE),
    /* mode */
    open_flag_desc!(O_CREAT),
    open_flag_desc!(O_EXCL),
    open_flag_desc!(O_NOCTTY),
    open_flag_desc!(O_TRUNC),
    open_flag_desc!(O_APPEND),
    open_flag_desc!(O_NONBLOCK),
    open_flag_desc!(O_SYNC),
    open_flag_desc!(O_DSYNC),
    open_flag_desc!(O_DIRECT),
    //open_flag_desc!(O_LARGEFILE), <- This is also set to 0 for gnu/b64 platform
    open_flag_desc!(O_NOFOLLOW),
    open_flag_desc!(O_NOATIME),
    open_flag_desc!(O_CLOEXEC),
    open_flag_desc!(O_PATH),
    open_flag_desc!(O_TMPFILE),
    open_flag_desc!(O_DIRECTORY),
];

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
