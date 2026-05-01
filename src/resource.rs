use crate::common::*;
use libc::{
    pid_t, RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA, RLIMIT_FSIZE, RLIMIT_LOCKS,
    RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE, RLIMIT_NICE, RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_RSS,
    RLIMIT_RTPRIO, RLIMIT_RTTIME, RLIMIT_SIGPENDING, RLIMIT_STACK, RLIM_INFINITY,
};

#[repr(C)]
struct RlimitTrace {
    rlim_cur: u64,
    rlim_max: u64,
}

fn format_rlim_val(v: u64) -> String {
    if v == RLIM_INFINITY {
        "RLIM_INFINITY".to_owned()
    } else {
        v.to_string()
    }
}

fn format_rlimit(rlim: &RlimitTrace) -> String {
    format!(
        "{{rlim_cur={}, rlim_max={}}}",
        format_rlim_val(rlim.rlim_cur),
        format_rlim_val(rlim.rlim_max)
    )
}

const RESOURCE_DESCS: &[Desc] = &[
    desc!(RLIMIT_CPU),
    desc!(RLIMIT_FSIZE),
    desc!(RLIMIT_DATA),
    desc!(RLIMIT_STACK),
    desc!(RLIMIT_CORE),
    desc!(RLIMIT_RSS),
    desc!(RLIMIT_NPROC),
    desc!(RLIMIT_NOFILE),
    desc!(RLIMIT_MEMLOCK),
    desc!(RLIMIT_AS),
    desc!(RLIMIT_LOCKS),
    desc!(RLIMIT_SIGPENDING),
    desc!(RLIMIT_MSGQUEUE),
    desc!(RLIMIT_NICE),
    desc!(RLIMIT_RTPRIO),
    desc!(RLIMIT_RTTIME),
];

#[repr(C)]
struct Prlimit64Args {
    pid: pid_t,
    resource: c_int,
    new_rlim: RlimitTrace,
    old_rlim: RlimitTrace,
    is_new_exist: bool,
}
unsafe impl plain::Plain for Prlimit64Args {}

pub(super) fn handle_prlimit64_args(args: &[u8]) -> String {
    let p = get_args::<Prlimit64Args>(args);
    let resource = format_value(
        p.resource as u64,
        Some("RLIMIT_???"),
        RESOURCE_DESCS,
        Format::Hex,
    );
    let new_rlim = if p.is_new_exist {
        format_rlimit(&p.new_rlim)
    } else {
        NULL_STR.to_owned()
    };
    format!(
        "{}, {}, {}, {}",
        p.pid,
        resource,
        new_rlim,
        format_rlimit(&p.old_rlim)
    )
}

#[repr(C)]
struct SetrlimitArgs {
    resource: c_int,
    rlim: RlimitTrace,
}
unsafe impl plain::Plain for SetrlimitArgs {}

pub(super) fn handle_setrlimit_args(args: &[u8]) -> String {
    let s = get_args::<SetrlimitArgs>(args);
    let resource = format_value(
        s.resource as u64,
        Some("RLIMIT_???"),
        RESOURCE_DESCS,
        Format::Hex,
    );
    format!("{}, {}", resource, format_rlimit(&s.rlim))
}

#[repr(C)]
struct GetrlimitArgs {
    resource: c_int,
    rlim: RlimitTrace,
}
unsafe impl plain::Plain for GetrlimitArgs {}

pub(super) fn handle_getrlimit_args(args: &[u8]) -> String {
    let g = get_args::<GetrlimitArgs>(args);
    let resource = format_value(
        g.resource as u64,
        Some("RLIMIT_???"),
        RESOURCE_DESCS,
        Format::Hex,
    );
    format!("{}, {}", resource, format_rlimit(&g.rlim))
}
