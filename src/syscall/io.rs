use crate::syscall::common::BUF_SIZE;
use plain::Plain;

fn format_io_buf(buf: &[u8; BUF_SIZE], count: usize) {
    let extra = if count > (BUF_SIZE - 1) { "..." } else { "" };
    let count = count.min(BUF_SIZE);
    eprint!("\"");
    for byte in &buf[0..count] {
        let c = *byte;
        /* TODO: cover all possible special character */
        if (c as char).is_ascii_graphic() || (c as char) == ' ' {
            eprint!("{}", c as char);
        } else if (c as char) == '\n' {
            eprint!("\\n");
        } else if (c as char) == '\t' {
            eprint!("\\n");
        } else {
            /* Print it as octal(base-8) like what
             * strace do by default */
            eprint!("\\{:o}", c);
        }
    }
    eprint!("\"{}, ", extra);
}

/* This should be synchronized with the structure
 * syscall_ent_t in syscall/strace_ent.h */
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
    format_io_buf(&read.buf, read_cnt);
    eprint!("{})", read.count)
}

pub(super) fn handle_write_args(args: &[u8]) {
    let size = std::mem::size_of::<WriteArgs>();
    let slice = &args[0..size];
    let write = plain::from_bytes::<WriteArgs>(slice).expect("Fail to cast bytes to WriteArgs");

    eprint!("({}, ", write.fd);
    format_io_buf(&write.buf, write.count);
    eprint!("{})", write.count);
}
