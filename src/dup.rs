use std::ffi::c_int;

use crate::common::*;

#[repr(C)]
struct DupArgs {
    oldfd: c_int,
}
unsafe impl plain::Plain for DupArgs {}

pub(super) fn handle_dup_args(args: &[u8]) -> String {
    let dup = get_args::<DupArgs>(args);

    return format!("{}", dup.oldfd);
}

#[repr(C)]
struct Dup2Args {
    oldfd: c_int,
    newfd: c_int,
}
unsafe impl plain::Plain for Dup2Args {}

pub(super) fn handle_dup2_args(args: &[u8]) -> String {
    let dup2 = get_args::<Dup2Args>(args);

    return format!("{}, {}", dup2.oldfd, dup2.newfd);
}
