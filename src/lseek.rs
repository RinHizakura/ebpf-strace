use std::ffi::c_int;

use libc::{SEEK_CUR, SEEK_DATA, SEEK_END, SEEK_HOLE, SEEK_SET};

use crate::common::*;

const LSEEK_WHENCE_DESCS: &[Desc] = &[
    desc!(SEEK_SET),
    desc!(SEEK_CUR),
    desc!(SEEK_END),
    desc!(SEEK_DATA),
    desc!(SEEK_HOLE),
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
    let whence = format_value(
        lseek.whence as u64,
        Some("SEEK_???"),
        &LSEEK_WHENCE_DESCS,
        Format::Hex,
    );

    return format!("{}, {}, {}", lseek.fd, lseek.offset, whence);
}
