use crate::common::*;

const DIRENT_BUF_SIZE: usize = 4096;
const DIRENT64_HDR_LEN: usize = 19; // 8(ino) + 8(off) + 2(reclen) + 1(type)

#[repr(C)]
struct Getdents64Args {
    fd: c_int,
    buf_used: u32,
    count: usize,
    buf: [u8; DIRENT_BUF_SIZE],
}
unsafe impl plain::Plain for Getdents64Args {}

fn format_dtype(d_type: u8) -> &'static str {
    match d_type {
        0 => "DT_UNKNOWN",
        1 => "DT_FIFO",
        2 => "DT_CHR",
        4 => "DT_DIR",
        6 => "DT_BLK",
        8 => "DT_REG",
        10 => "DT_LNK",
        12 => "DT_SOCK",
        14 => "DT_WHT",
        _ => "DT_UNKNOWN",
    }
}

pub(super) fn handle_getdents64_args(args: &[u8], ret: i64) -> String {
    let g = get_args::<Getdents64Args>(args);

    if ret <= 0 {
        return format!("{}, [], {}", g.fd, g.count);
    }

    let buf_used = (g.buf_used as usize).min(DIRENT_BUF_SIZE);
    let buf = &g.buf[..buf_used];

    let mut entries = String::from("[");
    let mut offset = 0usize;
    let mut first = true;

    while offset + DIRENT64_HDR_LEN <= buf.len() {
        let d_ino = u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());
        let d_off = i64::from_le_bytes(buf[offset + 8..offset + 16].try_into().unwrap());
        let d_reclen =
            u16::from_le_bytes(buf[offset + 16..offset + 18].try_into().unwrap()) as usize;
        let d_type = buf[offset + 18];

        if d_reclen == 0 || offset + d_reclen > buf.len() {
            break;
        }

        let name_start = offset + DIRENT64_HDR_LEN;
        let name_end = buf[name_start..offset + d_reclen]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_start + p)
            .unwrap_or(offset + d_reclen);
        let name = std::str::from_utf8(&buf[name_start..name_end]).unwrap_or("???");

        if !first {
            entries.push_str(", ");
        }
        entries.push_str(&format!(
            "{{d_ino={}, d_off={}, d_reclen={}, d_type={}, d_name=\"{}\"}}",
            d_ino,
            d_off,
            d_reclen,
            format_dtype(d_type),
            name
        ));
        first = false;

        offset += d_reclen;
    }

    entries.push(']');
    format!("{}, {}, {}", g.fd, entries, g.count)
}
