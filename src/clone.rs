use crate::common::*;
use libc::{
    CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_DETACHED, CLONE_FILES, CLONE_FS, CLONE_IO,
    CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER,
    CLONE_NEWUTS, CLONE_PARENT, CLONE_PARENT_SETTID, CLONE_PTRACE, CLONE_SETTLS, CLONE_SIGHAND,
    CLONE_SYSVSEM, CLONE_THREAD, CLONE_UNTRACED, CLONE_VFORK, CLONE_VM,
};

#[repr(C)]
struct CloneArgs {
    flags: c_ulong,
}
unsafe impl plain::Plain for CloneArgs {}

const CLONE_FLAGS_DESCS: &[Desc] = &[
    desc!(CLONE_VM),
    desc!(CLONE_FS),
    desc!(CLONE_FILES),
    desc!(CLONE_SIGHAND),
    desc!(CLONE_PTRACE),
    desc!(CLONE_VFORK),
    desc!(CLONE_PARENT),
    desc!(CLONE_THREAD),
    desc!(CLONE_NEWNS),
    desc!(CLONE_SYSVSEM),
    desc!(CLONE_SETTLS),
    desc!(CLONE_PARENT_SETTID),
    desc!(CLONE_CHILD_CLEARTID),
    desc!(CLONE_DETACHED),
    desc!(CLONE_UNTRACED),
    desc!(CLONE_CHILD_SETTID),
    desc!(CLONE_NEWCGROUP),
    desc!(CLONE_NEWUTS),
    desc!(CLONE_NEWIPC),
    desc!(CLONE_NEWUSER),
    desc!(CLONE_NEWPID),
    desc!(CLONE_NEWNET),
    desc!(CLONE_IO),
];

pub(super) fn handle_clone_args(args: &[u8]) -> String {
    let clone = get_args::<CloneArgs>(args);
    let signum = (clone.flags & 0xff) as c_int;
    let signal_str = if signum != 0 {
        format_signum(signum)
    } else {
        "0".to_owned()
    };
    let flags = format_flags(clone.flags & !0xff, '|', CLONE_FLAGS_DESCS, Format::Hex);
    format!("flags={}|{}", flags, signal_str)
}
