use std::ffi::c_uchar;

use crate::common::*;
use crate::net::format_sockaddr;
use libc::socklen_t;

const SOCKADDR_BUF_SIZE: usize = 28;

#[repr(C)]
struct BindArgs {
    sockfd: c_int,
    addr: [c_uchar; SOCKADDR_BUF_SIZE],
    addrlen: socklen_t,
}
unsafe impl plain::Plain for BindArgs {}

pub(super) fn handle_bind_args(args: &[u8]) -> String {
    let b = get_args::<BindArgs>(args);
    format!(
        "{}, {}, {}",
        b.sockfd,
        format_sockaddr(&b.addr, b.addrlen),
        b.addrlen
    )
}
