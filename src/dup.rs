use std::ffi::c_int;

use libc::O_CLOEXEC;

use crate::common::*;

const DUP3_FLAGS_DESCS: &[Desc] = &[desc!(O_CLOEXEC)];

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

#[repr(C)]
struct Dup3Args {
    oldfd: c_int,
    newfd: c_int,
    flags: c_int,
}
unsafe impl plain::Plain for Dup3Args {}

pub(super) fn handle_dup3_args(args: &[u8]) -> String {
    let d = get_args::<Dup3Args>(args);
    let flags = format_flags(d.flags as u64, '|', DUP3_FLAGS_DESCS, Format::Hex);
    format!("{}, {}, {}", d.oldfd, d.newfd, flags)
}
