use crate::common::*;

#[repr(C)]
struct ReadArgs {
    fd: c_int,
    buf: [u8; BUF_SIZE],
    count: usize,
}
unsafe impl plain::Plain for ReadArgs {}

#[repr(C)]
struct WriteArgs {
    fd: c_int,
    buf: [u8; BUF_SIZE],
    count: usize,
}
unsafe impl plain::Plain for WriteArgs {}

pub(super) fn handle_read_args(args: &[u8], read_cnt: usize) -> String {
    let read = get_args::<ReadArgs>(args);

    let buf = format_buf(&read.buf, read_cnt);
    return format!("{}, {}, {}", read.fd, buf, read.count);
}

pub(super) fn handle_write_args(args: &[u8]) -> String {
    let write = get_args::<WriteArgs>(args);

    let buf = format_buf(&write.buf, write.count);
    return format!("{}, {}, {}", write.fd, buf, write.count);
}
