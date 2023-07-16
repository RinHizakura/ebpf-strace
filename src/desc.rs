use std::ffi::c_int;

use libc::{fd_set, timeval};

use crate::common::*;

#[repr(C)]
struct CloseArgs {
    fd: c_int,
}
unsafe impl plain::Plain for CloseArgs {}

pub(super) fn handle_close_args(args: &[u8]) -> String {
    let close = get_args::<CloseArgs>(args);

    return format!("{}", close.fd);
}

#[repr(C)]
struct SelectArgs {
    nfds: c_int,
    readfds: fd_set,
    writefds: fd_set,
    exceptfds: fd_set,
    timeout: timeval,

    is_readfds_exist: bool,
    is_writefds_exist: bool,
    is_exceptfds_exist: bool,
    is_timeout_exist: bool,
}
unsafe impl plain::Plain for SelectArgs {}

pub(super) fn handle_select_args(args: &[u8]) -> String {
    let select = get_args::<SelectArgs>(args);

    return format!("{}", select.nfds);
}
