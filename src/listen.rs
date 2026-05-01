use crate::common::*;

#[repr(C)]
struct ListenArgs {
    sockfd: c_int,
    backlog: c_int,
}
unsafe impl plain::Plain for ListenArgs {}

pub(super) fn handle_listen_args(args: &[u8]) -> String {
    let l = get_args::<ListenArgs>(args);
    format!("{}, {}", l.sockfd, l.backlog)
}
