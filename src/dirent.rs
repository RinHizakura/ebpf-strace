use crate::common::*;

#[repr(C)]
struct Getdents64Args {
    fd: c_int,
    count: usize,
}
unsafe impl plain::Plain for Getdents64Args {}

pub(super) fn handle_getdents64_args(args: &[u8]) -> String {
    let g = get_args::<Getdents64Args>(args);
    format!("{}, {}", g.fd, g.count)
}
