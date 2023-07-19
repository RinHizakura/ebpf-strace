use libc::{F_OK, R_OK, W_OK, X_OK};

use crate::common::*;

#[repr(C)]
struct AccessArgs {
    pathname: [u8; BUF_SIZE],
    mode: c_int,
}
unsafe impl plain::Plain for AccessArgs {}

const ACCESS_MODE_DESCS: &[Desc] = &[desc!(F_OK), desc!(R_OK), desc!(W_OK), desc!(X_OK)];

pub(super) fn handle_access_args(args: &[u8]) -> String {
    let access = get_args::<AccessArgs>(args);

    let pathname = format_str(&access.pathname);
    let mode = format_flags(access.mode as u64, '|', ACCESS_MODE_DESCS, Format::Octal);

    return format!("{}, {}", pathname, mode);
}
