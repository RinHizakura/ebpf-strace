use crate::syscall::common::*;

#[repr(C)]
struct PollArgs {
    fds: [libc::pollfd; 4],
    nfds: u32,
    timeout: i32,
}
unsafe impl plain::Plain for PollArgs {}

pub(super) fn handle_poll_args(args: &[u8]) -> String {
    let poll = get_args::<PollArgs>(args);

    return format!("{}, {}", poll.nfds, poll.timeout);
}
