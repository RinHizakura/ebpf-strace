use crate::syscall::common::*;
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
    let size = std::mem::size_of::<ReadArgs>();
    let slice = &args[0..size];
    let read = plain::from_bytes::<ReadArgs>(slice).expect("Fail to cast bytes to ReadArgs");

    eprint!("({}, ", read.fd);
    format_buf(&read.buf, read_cnt);
    eprint!("{})", read.count)
}

pub(super) fn handle_write_args(args: &[u8]) {
    let size = std::mem::size_of::<WriteArgs>();
    let slice = &args[0..size];
    let write = plain::from_bytes::<WriteArgs>(slice).expect("Fail to cast bytes to WriteArgs");

    eprint!("({}, ", write.fd);
    format_buf(&write.buf, write.count);
    eprint!("{})", write.count);
}
