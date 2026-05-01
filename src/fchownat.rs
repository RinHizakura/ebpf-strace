use crate::common::*;
use libc::{gid_t, uid_t};

#[repr(C)]
struct ChownArgs {
    path: [u8; BUF_SIZE],
    uid: uid_t,
    gid: gid_t,
}
unsafe impl plain::Plain for ChownArgs {}

pub(super) fn handle_chown_args(args: &[u8]) -> String {
    let c = get_args::<ChownArgs>(args);
    format!("{}, {}, {}", format_str(&c.path), c.uid, c.gid)
}

#[repr(C)]
struct FchownArgs {
    fd: c_int,
    uid: uid_t,
    gid: gid_t,
}
unsafe impl plain::Plain for FchownArgs {}

pub(super) fn handle_fchown_args(args: &[u8]) -> String {
    let f = get_args::<FchownArgs>(args);
    format!("{}, {}, {}", f.fd, f.uid, f.gid)
}
