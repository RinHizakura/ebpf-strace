use crate::common::*;
use libc::{gid_t, uid_t};

#[repr(C)]
struct SetuidArgs {
    uid: uid_t,
}
unsafe impl plain::Plain for SetuidArgs {}

pub(super) fn handle_setuid_args(args: &[u8]) -> String {
    let setuid = get_args::<SetuidArgs>(args);
    format!("{}", setuid.uid)
}

#[repr(C)]
struct SetgidArgs {
    gid: gid_t,
}
unsafe impl plain::Plain for SetgidArgs {}

pub(super) fn handle_setgid_args(args: &[u8]) -> String {
    let setgid = get_args::<SetgidArgs>(args);
    format!("{}", setgid.gid)
}
