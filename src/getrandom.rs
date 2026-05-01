use crate::common::*;
use libc::{GRND_NONBLOCK, GRND_RANDOM};

const GETRANDOM_FLAGS_DESCS: &[Desc] = &[desc!(GRND_NONBLOCK), desc!(GRND_RANDOM)];

#[repr(C)]
struct GetrandomArgs {
    buflen: usize,
    flags: u32,
    buf: [u8; BUF_SIZE],
}
unsafe impl plain::Plain for GetrandomArgs {}

pub(super) fn handle_getrandom_args(args: &[u8], ret: i64) -> String {
    let g = get_args::<GetrandomArgs>(args);
    let flags = format_flags(g.flags as u64, '|', GETRANDOM_FLAGS_DESCS, Format::Hex);
    let buf_str = if ret > 0 {
        format_buf_hex(&g.buf, ret as usize)
    } else {
        format!("0x{:x}", 0)
    };
    format!("{}, {}, {}", buf_str, g.buflen, flags)
}
