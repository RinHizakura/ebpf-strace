use std::ffi::c_int;

use libc::{timeval, FD_SETSIZE};

use crate::common::*;
use crate::utils::*;

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
struct FdSet {
    fds_bits: [c_long; FD_SETSIZE / LONG_BIT as usize],
}

#[repr(C)]
struct SelectArgs {
    nfds: c_int,
    readfds: FdSet,
    writefds: FdSet,
    exceptfds: FdSet,
    timeout: timeval,

    is_readfds_exist: bool,
    is_writefds_exist: bool,
    is_exceptfds_exist: bool,
    is_timeout_exist: bool,
}
unsafe impl plain::Plain for SelectArgs {}

fn format_fd_set(fds: &FdSet, nfds: c_int) -> String {
    let mut s = String::new();
    s.push('[');

    let mut i = next_set_bit(&fds.fds_bits, 0, nfds);
    while i >= 0 {
        s.push_str(&i.to_string());
        s.push(' ');
        i += 1;
        i = next_set_bit(&fds.fds_bits, i, nfds);
    }

    if s.len() != 1 {
        s.pop();
    }
    s.push(']');
    return s;
}

pub(super) fn handle_select_args(args: &[u8]) -> String {
    let select = get_args::<SelectArgs>(args);

    let nfds = select.nfds;
    let readfds = format_or_null!(
        format_fd_set,
        select.is_readfds_exist,
        &select.readfds,
        nfds
    );
    let writefds = format_or_null!(
        format_fd_set,
        select.is_writefds_exist,
        &select.writefds,
        nfds
    );
    let exceptfds = format_or_null!(
        format_fd_set,
        select.is_exceptfds_exist,
        &select.exceptfds,
        nfds
    );

    return format!("{}, {}, {}, {}", nfds, readfds, writefds, exceptfds);
}
