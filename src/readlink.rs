use crate::common::*;

#[repr(C)]
struct ReadlinkArgs {
    path: [u8; BUF_SIZE],
    buf: [u8; BUF_SIZE],
    bufsiz: usize,
}
unsafe impl plain::Plain for ReadlinkArgs {}

pub(super) fn handle_readlink_args(args: &[u8], ret: u64) -> String {
    let r = get_args::<ReadlinkArgs>(args);
    let ret_len = ret as i64;
    let buf_str = if ret_len > 0 {
        format_buf(&r.buf, ret_len as usize)
    } else {
        format_str(&r.buf)
    };
    format!("{}, {}, {}", format_str(&r.path), buf_str, r.bufsiz)
}
