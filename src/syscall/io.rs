use crate::syscall::common::*;
use crate::syscall::get_args;
use plain::Plain;

#[repr(C)]
struct ReadArgs {
    fd: i32,
    buf: [u8; BUF_SIZE],
    count: usize,
}
unsafe impl Plain for ReadArgs {}

#[repr(C)]
struct WriteArgs {
    fd: i32,
    buf: [u8; BUF_SIZE],
    count: usize,
}
unsafe impl Plain for WriteArgs {}

pub(super) fn handle_read_args(args: &[u8], read_cnt: usize) {
    let read = get_args::<ReadArgs>(args);

    eprint!("({}, ", read.fd);
    format_buf(&read.buf, read_cnt);
    eprint!("{})", read.count)
}

pub(super) fn handle_write_args(args: &[u8]) {
    let write = get_args::<WriteArgs>(args);

    eprint!("({}, ", write.fd);
    format_buf(&write.buf, write.count);
    eprint!("{})", write.count);
}
