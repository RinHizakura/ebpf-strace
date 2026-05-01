use crate::common::*;
use libc::AT_REMOVEDIR;

#[repr(C)]
struct UnlinkArgs {
    path: [u8; BUF_SIZE],
}
unsafe impl plain::Plain for UnlinkArgs {}

pub(super) fn handle_unlink_args(args: &[u8]) -> String {
    let u = get_args::<UnlinkArgs>(args);
    format_str(&u.path)
}

const UNLINKAT_FLAGS_DESCS: &[Desc] = &[desc!(AT_REMOVEDIR)];

#[repr(C)]
struct UnlinkatArgs {
    dirfd: c_int,
    path: [u8; BUF_SIZE],
    flags: c_int,
}
unsafe impl plain::Plain for UnlinkatArgs {}

pub(super) fn handle_unlinkat_args(args: &[u8]) -> String {
    let u = get_args::<UnlinkatArgs>(args);
    let flags = format_flags(u.flags as u64, '|', UNLINKAT_FLAGS_DESCS, Format::Hex);
    format!(
        "{}, {}, {}",
        format_dirfd(u.dirfd),
        format_str(&u.path),
        flags
    )
}
