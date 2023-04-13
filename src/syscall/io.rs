use crate::syscall::common::BUF_SIZE;
use std::str::from_utf8;
use std::fmt;
use plain::Plain;

/* This should be synchronized with the structure
 * syscall_ent_t in syscall/strace_ent.h */
#[repr(C)]
struct ReadArgs {
    fd: i32,
    buf: [u8; BUF_SIZE],
    count: usize,
}
unsafe impl Plain for ReadArgs {}
impl fmt::Display for ReadArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let extra = if self.count > (BUF_SIZE - 1) { "..." } else { "" };
        write!(f, "{}, ", self.fd)?;
        write!(f, "\"")?;
        for c in self.buf {
            if (c as char).is_ascii_graphic() || (c as char).is_whitespace() {
                write!(f, "{}", c as char)?;
            } else {
                write!(f, "\\{}", c)?;
            }
        }
        write!(f, "\"{}, ", extra)?;
        write!(f, "{}", self.count)
    }
}

#[repr(C)]
struct WriteArgs {
    fd: i32,
    buf: [u8; BUF_SIZE],
    count: usize,
}
unsafe impl Plain for WriteArgs {}
impl fmt::Display for WriteArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let extra = if self.count > (BUF_SIZE - 1) { "..." } else { "" };
        let count = if self.count > (BUF_SIZE - 1) { BUF_SIZE } else { self.count };
        let s = from_utf8(&self.buf[0..count]).unwrap();
        write!(f, "{}, \"{}\"{}, {}", self.fd, s, extra, self.count)

    }
}

pub(super) fn handle_read_args(args: &[u8]) {
    let size = std::mem::size_of::<ReadArgs>();
    let slice = &args[0..size];
    let read = plain::from_bytes::<ReadArgs>(slice).expect("Fail to cast bytes to ReadArgs");

    eprint!("({})", read);
}

pub(super) fn handle_write_args(args: &[u8]) {
    let size = std::mem::size_of::<WriteArgs>();
    let slice = &args[0..size];
    let write = plain::from_bytes::<WriteArgs>(slice).expect("Fail to cast bytes to WriteArgs");

    eprint!("({})", write);
}
