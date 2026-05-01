use crate::common::*;

#[repr(C)]
struct LinkArgs {
    old_path: [u8; BUF_SIZE],
    new_path: [u8; BUF_SIZE],
}
unsafe impl plain::Plain for LinkArgs {}

pub(super) fn handle_link_args(args: &[u8]) -> String {
    let l = get_args::<LinkArgs>(args);
    format!("{}, {}", format_str(&l.old_path), format_str(&l.new_path))
}
