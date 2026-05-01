use crate::common::*;
use libc::{SHUT_RD, SHUT_RDWR, SHUT_WR};

const SHUTDOWN_HOW_DESCS: &[Desc] = &[desc!(SHUT_RD), desc!(SHUT_WR), desc!(SHUT_RDWR)];

#[repr(C)]
struct ShutdownArgs {
    sockfd: c_int,
    how: c_int,
}
unsafe impl plain::Plain for ShutdownArgs {}

pub(super) fn handle_shutdown_args(args: &[u8]) -> String {
    let s = get_args::<ShutdownArgs>(args);
    let how = format_value(
        s.how as u64,
        Some("SHUT_???"),
        SHUTDOWN_HOW_DESCS,
        Format::Hex,
    );
    format!("{}, {}", s.sockfd, how)
}
