use crate::common::*;

#[repr(C)]
struct ChdirArgs {
    path: [u8; BUF_SIZE],
}
unsafe impl plain::Plain for ChdirArgs {}

pub(super) fn handle_chdir_args(args: &[u8]) -> String {
    let c = get_args::<ChdirArgs>(args);
    format_str(&c.path)
}

#[repr(C)]
struct FchdirArgs {
    fd: c_int,
}
unsafe impl plain::Plain for FchdirArgs {}

pub(super) fn handle_fchdir_args(args: &[u8]) -> String {
    let f = get_args::<FchdirArgs>(args);
    format!("{}", f.fd)
}
