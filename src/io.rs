use libc::off_t;

use crate::common::*;

#[repr(C)]
struct ReadArgs {
    fd: c_int,
    buf: [u8; BUF_SIZE],
    count: usize,
}
unsafe impl plain::Plain for ReadArgs {}

pub(super) fn handle_read_args(args: &[u8], read_cnt: usize) -> String {
    let read = get_args::<ReadArgs>(args);

    let buf = format_buf(&read.buf, read_cnt);
    return format!("{}, {}, {}", read.fd, buf, read.count);
}

#[repr(C)]
struct WriteArgs {
    fd: c_int,
    buf: [u8; BUF_SIZE],
    count: usize,
}
unsafe impl plain::Plain for WriteArgs {}

pub(super) fn handle_write_args(args: &[u8]) -> String {
    let write = get_args::<WriteArgs>(args);

    let buf = format_buf(&write.buf, write.count);
    return format!("{}, {}, {}", write.fd, buf, write.count);
}

#[repr(C)]
struct PreadArgs {
    fd: c_int,
    buf: [u8; BUF_SIZE],
    count: usize,
    offset: off_t,
}
unsafe impl plain::Plain for PreadArgs {}

pub(super) fn handle_pread_args(args: &[u8], read_cnt: usize) -> String {
    let pread = get_args::<PreadArgs>(args);

    let buf = format_buf(&pread.buf, read_cnt);
    return format!("{}, {}, {}, {}", pread.fd, buf, pread.count, pread.offset);
}

#[repr(C)]
struct PwriteArgs {
    fd: c_int,
    buf: [u8; BUF_SIZE],
    count: usize,
    offset: off_t,
}
unsafe impl plain::Plain for PwriteArgs {}

pub(super) fn handle_pwrite_args(args: &[u8]) -> String {
    let pwrite = get_args::<PwriteArgs>(args);

    let buf = format_buf(&pwrite.buf, pwrite.count);
    return format!(
        "{}, {}, {}, {}",
        pwrite.fd, buf, pwrite.count, pwrite.offset
    );
}
