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
    revents: [i16; ARR_ENT_SIZE],
}
unsafe impl plain::Plain for PollArgs {}

fn format_pollfd(fd: &libc::pollfd) -> String {
    let events = format_flags(fd.events as u64, '|', POLL_EVENTS_DESCS, Format::Hex);
    format!("{{fd={}, events={}}}", fd.fd, events)
}

fn format_pollfd_revents(fd: &libc::pollfd, revents: i16) -> String {
    let rev = format_flags(revents as u64, '|', POLL_EVENTS_DESCS, Format::Hex);
    format!("{{fd={}, revents={}}}", fd.fd, rev)
}

pub(super) fn handle_poll_args(args: &[u8]) -> String {
    let poll = get_args::<PollArgs>(args);
    let n = poll.nfds as usize;
    let pollfd_list = format_arr(&poll.fds, n, format_pollfd);
    format!("{}, {}, {}", pollfd_list, poll.nfds, poll.timeout)
}

pub(super) fn handle_poll_ret_aux(args: &[u8], ret: i64) -> String {
    if ret == 0 {
        return " (Timeout)".to_owned();
    }
    if ret < 0 {
        return String::new();
    }
    let poll = get_args::<PollArgs>(args);
    let n = poll.nfds as usize;
    let mut rev_parts = Vec::new();
    for i in 0..n.min(ARR_ENT_SIZE) {
        if poll.revents[i] != 0 {
            rev_parts.push(format_pollfd_revents(&poll.fds[i], poll.revents[i]));
        }
    }
    if rev_parts.is_empty() {
        return String::new();
    }
    format!(" ([{}])", rev_parts.join(", "))
}
