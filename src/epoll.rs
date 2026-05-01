use crate::common::*;
use libc::{
    EPOLLERR, EPOLLET, EPOLLHUP, EPOLLIN, EPOLLONESHOT, EPOLLOUT, EPOLLPRI, EPOLLRDHUP,
    EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
};

const EPOLL_OP_DESCS: &[Desc] = &[
    desc!(EPOLL_CTL_ADD),
    desc!(EPOLL_CTL_DEL),
    desc!(EPOLL_CTL_MOD),
];

const EPOLL_EVENTS_DESCS: &[Desc] = &[
    desc!(EPOLLIN),
    desc!(EPOLLOUT),
    desc!(EPOLLRDHUP),
    desc!(EPOLLPRI),
    desc!(EPOLLERR),
    desc!(EPOLLHUP),
    desc!(EPOLLET),
    desc!(EPOLLONESHOT),
];

const EPOLL_CREATE1_FLAGS_DESCS: &[Desc] = &[desc!(EPOLL_CLOEXEC)];

#[repr(C)]
struct EpollCreate1Args {
    flags: c_int,
}
unsafe impl plain::Plain for EpollCreate1Args {}

pub(super) fn handle_epoll_create1_args(args: &[u8]) -> String {
    let e = get_args::<EpollCreate1Args>(args);
    let flags = format_flags(e.flags as u64, '|', EPOLL_CREATE1_FLAGS_DESCS, Format::Hex);
    format!("{}", flags)
}

#[repr(C)]
struct EpollCtlArgs {
    epfd: c_int,
    op: c_int,
    fd: c_int,
    events: u32,
    data: u64,
    is_event_exist: bool,
}
unsafe impl plain::Plain for EpollCtlArgs {}

pub(super) fn handle_epoll_ctl_args(args: &[u8]) -> String {
    let e = get_args::<EpollCtlArgs>(args);
    let op = format_value(
        e.op as u64,
        Some("EPOLL_CTL_???"),
        EPOLL_OP_DESCS,
        Format::Hex,
    );
    let event = if e.is_event_exist {
        let events = format_flags(e.events as u64, '|', EPOLL_EVENTS_DESCS, Format::Hex);
        format!(
            "{{events={}, data={{u32={}, u64={}}}}}",
            events, e.data as u32, e.data
        )
    } else {
        NULL_STR.to_owned()
    };
    format!("{}, {}, {}, {}", e.epfd, op, e.fd, event)
}

#[repr(C)]
struct EpollWaitArgs {
    epfd: c_int,
    maxevents: c_int,
    timeout: c_int,
    ev_events: u32,
    ev_data: u64,
}
unsafe impl plain::Plain for EpollWaitArgs {}

pub(super) fn handle_epoll_wait_args(args: &[u8], ret: i64) -> String {
    let e = get_args::<EpollWaitArgs>(args);
    let events_str = if ret > 0 {
        let ev_flags = format_flags(e.ev_events as u64, '|', EPOLL_EVENTS_DESCS, Format::Hex);
        format!(
            "[{{events={}, data={{u32={}, u64={}}}}}]",
            ev_flags, e.ev_data as u32, e.ev_data
        )
    } else {
        "[]".to_owned()
    };
    format!("{}, {}, {}, {}", e.epfd, events_str, e.maxevents, e.timeout)
}
