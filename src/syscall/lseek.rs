use std::ffi::c_int;

use libc::{SEEK_CUR, SEEK_DATA, SEEK_END, SEEK_HOLE, SEEK_SET};

use crate::syscall::common::*;

const LSEEK_WHENCE_DESCS: &[FlagDesc] = &[
    flag_desc!(SEEK_SET),
    flag_desc!(SEEK_CUR),
    flag_desc!(SEEK_END),
    flag_desc!(SEEK_DATA),
    flag_desc!(SEEK_HOLE),
];

#[repr(C)]
struct LseekArgs {
    fd: c_int,
    offset: libc::off_t,
    whence: c_int,
}
unsafe impl plain::Plain for LseekArgs {}

pub(super) fn handle_lseek_args(args: &[u8]) -> String {
    let lseek = get_args::<LseekArgs>(args);
    let whence = format_flags(lseek.whence as u64, '|', &LSEEK_WHENCE_DESCS);

    return format!("{}, {}, {}", lseek.fd, lseek.offset, whence);
}
