use crate::common::*;
use libc::{
    F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, F_GETLK, F_GETOWN, F_SETFD, F_SETFL, F_SETLK,
    F_SETLKW, F_SETOWN,
};

const FCNTL_CMD_DESCS: &[Desc] = &[
    desc!(F_DUPFD),
    desc!(F_DUPFD_CLOEXEC),
    desc!(F_GETFD),
    desc!(F_SETFD),
    desc!(F_GETFL),
    desc!(F_SETFL),
    desc!(F_GETLK),
    desc!(F_SETLK),
    desc!(F_SETLKW),
    desc!(F_GETOWN),
    desc!(F_SETOWN),
];

#[repr(C)]
struct FcntlArgs {
    fd: c_int,
    cmd: c_int,
    arg: c_ulong,
}
unsafe impl plain::Plain for FcntlArgs {}

pub(super) fn handle_fcntl_args(args: &[u8]) -> String {
    let f = get_args::<FcntlArgs>(args);
    let cmd = format_value(f.cmd as u64, Some("F_???"), FCNTL_CMD_DESCS, Format::Hex);
    format!("{}, {}, 0x{:x}", f.fd, cmd, f.arg)
}
