use libc::{POLLIN, POLLPRI, POLLOUT, POLLHUP, POLLNVAL};

use crate::syscall::common::*;

const POLL_FLAGS_DESCS: &[FlagDesc] = &[
    flag_desc!(POLLIN),
    flag_desc!(POLLPRI),
    flag_desc!(POLLOUT),
    flag_desc!(POLLHUP),
    flag_desc!(POLLNVAL),
];

#[repr(C)]
struct PollArgs {
    fds: [libc::pollfd; ARR_ENT_SIZE],
    nfds: u32,
    timeout: i32,
}
unsafe impl plain::Plain for PollArgs {}

fn format_pollfd(fd: &libc::pollfd) -> String {
    let events = format_flags(fd.events as u32, '|', POLL_FLAGS_DESCS);
    return format!("{{fd={}, events={}}}", fd.fd, events);
}

pub(super) fn handle_poll_args(args: &[u8]) -> String {
    let poll = get_args::<PollArgs>(args);
    let pollfd_list = format_arr(&poll.fds, poll.nfds as usize, format_pollfd);
    return format!("{}, {}, {}", pollfd_list, poll.nfds, poll.timeout);
}
