use crate::common::*;
use libc::{
    timeval, CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM, CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE,
    CLOCK_MONOTONIC_RAW, CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME, CLOCK_REALTIME_ALARM,
    CLOCK_REALTIME_COARSE, CLOCK_TAI, CLOCK_THREAD_CPUTIME_ID,
};

#[repr(C)]
struct TimespecTrace {
    tv_sec: i64,
    tv_nsec: i64,
}

fn format_timespec(t: &TimespecTrace) -> String {
    format!("{{tv_sec={}, tv_nsec={}}}", t.tv_sec, t.tv_nsec)
}

const CLOCKID_DESCS: &[Desc] = &[
    desc!(CLOCK_REALTIME),
    desc!(CLOCK_MONOTONIC),
    desc!(CLOCK_PROCESS_CPUTIME_ID),
    desc!(CLOCK_THREAD_CPUTIME_ID),
    desc!(CLOCK_MONOTONIC_RAW),
    desc!(CLOCK_REALTIME_COARSE),
    desc!(CLOCK_MONOTONIC_COARSE),
    desc!(CLOCK_BOOTTIME),
    desc!(CLOCK_REALTIME_ALARM),
    desc!(CLOCK_BOOTTIME_ALARM),
    desc!(CLOCK_TAI),
];

#[repr(C)]
struct NanosleepArgs {
    req: TimespecTrace,
    rem: TimespecTrace,
    is_rem_exist: bool,
}
unsafe impl plain::Plain for NanosleepArgs {}

pub(super) fn handle_nanosleep_args(args: &[u8]) -> String {
    let n = get_args::<NanosleepArgs>(args);
    let req = format_timespec(&n.req);
    let rem = if n.is_rem_exist {
        format_timespec(&n.rem)
    } else {
        NULL_STR.to_owned()
    };
    format!("{}, {}", req, rem)
}

#[repr(C)]
struct ClockGettimeArgs {
    clockid: c_int,
    tp: TimespecTrace,
}
unsafe impl plain::Plain for ClockGettimeArgs {}

pub(super) fn handle_clock_gettime_args(args: &[u8]) -> String {
    let c = get_args::<ClockGettimeArgs>(args);
    let clockid = format_value(
        c.clockid as u64,
        Some("CLOCK_???"),
        CLOCKID_DESCS,
        Format::Hex,
    );
    format!("{}, {}", clockid, format_timespec(&c.tp))
}

#[repr(C)]
struct ClockGetresArgs {
    clockid: c_int,
    res: TimespecTrace,
    is_res_exist: bool,
}
unsafe impl plain::Plain for ClockGetresArgs {}

pub(super) fn handle_clock_getres_args(args: &[u8]) -> String {
    let c = get_args::<ClockGetresArgs>(args);
    let clockid = format_value(
        c.clockid as u64,
        Some("CLOCK_???"),
        CLOCKID_DESCS,
        Format::Hex,
    );
    let res = if c.is_res_exist {
        format_timespec(&c.res)
    } else {
        NULL_STR.to_owned()
    };
    format!("{}, {}", clockid, res)
}

#[repr(C)]
struct GettimeofdayArgs {
    tv: timeval,
    is_tv_exist: bool,
}
unsafe impl plain::Plain for GettimeofdayArgs {}

pub(super) fn handle_gettimeofday_args(args: &[u8]) -> String {
    let g = get_args::<GettimeofdayArgs>(args);
    let tv = if g.is_tv_exist {
        format_timeval(&g.tv)
    } else {
        NULL_STR.to_owned()
    };
    format!("{}, NULL", tv)
}
