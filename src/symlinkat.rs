use crate::common::*;

#[repr(C)]
struct SymlinkArgs {
    target: [u8; BUF_SIZE],
    linkpath: [u8; BUF_SIZE],
}
unsafe impl plain::Plain for SymlinkArgs {}

pub(super) fn handle_symlink_args(args: &[u8]) -> String {
    let s = get_args::<SymlinkArgs>(args);
    format!("{}, {}", format_str(&s.target), format_str(&s.linkpath))
}
