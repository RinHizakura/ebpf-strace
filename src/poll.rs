use std::ffi::c_int;

use libc::{POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLPRI};

use crate::common::*;

const POLL_EVENTS_DESCS: &[Desc] = &[
    desc!(POLLIN),
    desc!(POLLPRI),
    desc!(POLLOUT),
    desc!(POLLHUP),
    desc!(POLLNVAL),
];

#[repr(C)]
struct PollArgs {
    fds: [libc::pollfd; ARR_ENT_SIZE],
    nfds: u32,
    timeout: c_int,
}
unsafe impl plain::Plain for PollArgs {}

fn format_pollfd(fd: &libc::pollfd) -> String {
    let events = format_flags(fd.events as u64, '|', POLL_EVENTS_DESCS, Format::Hex);
    return format!("{{fd={}, events={}}}", fd.fd, events);
}

pub(super) fn handle_poll_args(args: &[u8]) -> String {
    let poll = get_args::<PollArgs>(args);
    let pollfd_list = format_arr(&poll.fds, poll.nfds as usize, format_pollfd);
    return format!("{}, {}, {}", pollfd_list, poll.nfds, poll.timeout);
}
