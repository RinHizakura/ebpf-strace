use crate::common::*;

#[repr(C)]
struct RmdirArgs {
    path: [u8; BUF_SIZE],
}
unsafe impl plain::Plain for RmdirArgs {}

pub(super) fn handle_rmdir_args(args: &[u8]) -> String {
    let r = get_args::<RmdirArgs>(args);
    format_str(&r.path)
}
