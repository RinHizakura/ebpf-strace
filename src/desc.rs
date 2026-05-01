use std::ffi::c_int;

use libc::{timeval, FD_SETSIZE, O_CLOEXEC, O_NONBLOCK};

use crate::common::*;
use crate::utils::*;

const CLOSE_RANGE_CLOEXEC: u32 = 4;
const CLOSE_RANGE_UNSHARE: u32 = 2;

const PIPE2_FLAGS_DESCS: &[Desc] = &[desc!(O_CLOEXEC), desc!(O_NONBLOCK)];

const CLOSE_RANGE_FLAGS_DESCS: &[Desc] = &[
    Desc {
        val: CLOSE_RANGE_CLOEXEC as u64,
        name: "CLOSE_RANGE_CLOEXEC",
    },
    Desc {
        val: CLOSE_RANGE_UNSHARE as u64,
        name: "CLOSE_RANGE_UNSHARE",
    },
];

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

fn format_fd_set(fds: &FdSet, mut nfds: c_int) -> String {
    /* Adjust nfds to not overflow the array */
    if nfds > FD_SETSIZE as c_int {
        nfds = FD_SETSIZE as c_int;
    }

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
    let timeout = format_or_null!(format_timeval, select.is_timeout_exist, &select.timeout);

    return format!(
        "{}, {}, {}, {}, {}",
        nfds, readfds, writefds, exceptfds, timeout
    );
}

#[repr(C)]
struct PipeArgs {
    pipefd: [c_int; 2],
}
unsafe impl plain::Plain for PipeArgs {}

pub(super) fn handle_pipe_args(args: &[u8]) -> String {
    let pipe = get_args::<PipeArgs>(args);
    format!("[{}, {}]", pipe.pipefd[0], pipe.pipefd[1])
}

#[repr(C)]
struct Pipe2Args {
    pipefd: [c_int; 2],
    flags: c_int,
}
unsafe impl plain::Plain for Pipe2Args {}

pub(super) fn handle_pipe2_args(args: &[u8]) -> String {
    let p = get_args::<Pipe2Args>(args);
    let flags = format_flags(p.flags as u64, '|', PIPE2_FLAGS_DESCS, Format::Hex);
    format!("[{}, {}], {}", p.pipefd[0], p.pipefd[1], flags)
}

#[repr(C)]
struct FsyncArgs {
    fd: c_int,
}
unsafe impl plain::Plain for FsyncArgs {}

pub(super) fn handle_fsync_args(args: &[u8]) -> String {
    let f = get_args::<FsyncArgs>(args);
    format!("{}", f.fd)
}

#[repr(C)]
struct FdatasyncArgs {
    fd: c_int,
}
unsafe impl plain::Plain for FdatasyncArgs {}

pub(super) fn handle_fdatasync_args(args: &[u8]) -> String {
    let f = get_args::<FdatasyncArgs>(args);
    format!("{}", f.fd)
}

#[repr(C)]
struct SyncfsArgs {
    fd: c_int,
}
unsafe impl plain::Plain for SyncfsArgs {}

pub(super) fn handle_syncfs_args(args: &[u8]) -> String {
    let s = get_args::<SyncfsArgs>(args);
    format!("{}", s.fd)
}

#[repr(C)]
struct CloseRangeArgs {
    fd: u32,
    max_fd: u32,
    flags: u32,
}
unsafe impl plain::Plain for CloseRangeArgs {}

pub(super) fn handle_close_range_args(args: &[u8]) -> String {
    let c = get_args::<CloseRangeArgs>(args);
    let flags = format_flags(c.flags as u64, '|', CLOSE_RANGE_FLAGS_DESCS, Format::Hex);
    format!("{}, {}, {}", c.fd, c.max_fd, flags)
}
