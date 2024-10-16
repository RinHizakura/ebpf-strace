use crate::handler::signal::signal_ent_handler;
use crate::handler::syscall::syscall_ent_handler;
use crate::syscall::syscall_nr::SYS_EXIT_GROUP;
use crate::syscall::syscall_tbl::SYSCALLS;

use plain::Plain;

mod signal;
mod syscall;

#[repr(C)]
struct MsgEnt {
    msg_type: u64,
}
unsafe impl Plain for MsgEnt {}

const MSG_SYSCALL: u64 = 0;
const MSG_SIGNAL: u64 = 1;

pub fn msg_ent_handler(bytes: &[u8]) -> i32 {
    /* The first u64 is used for encoding the type of message. Pick up
     * the corresponding handler for the inner entry accordingly. */
    let ent_size = std::mem::size_of::<MsgEnt>();
    let ent =
        plain::from_bytes::<MsgEnt>(&bytes[0..ent_size]).expect("Fail to cast bytes to MsgEnt");
    let inner = &bytes[ent_size..];

    match ent.msg_type {
        MSG_SYSCALL => syscall_ent_handler(inner),
        MSG_SIGNAL => signal_ent_handler(inner),
        _ => unreachable!(),
    }
}

#[repr(C)]
struct TimeMsgEnt {
    id: u64,
    ret: u64,
    start_time: u64,
    end_time: u64,
}
unsafe impl Plain for TimeMsgEnt {}

pub fn time_msg_handler(bytes: &[u8]) -> i32 {
    let ent_size = std::mem::size_of::<MsgEnt>();
    let ent =
        plain::from_bytes::<MsgEnt>(&bytes[0..ent_size]).expect("Fail to cast bytes to MsgEnt");

    // Only MSG_SYSCALL is expected to be received under time mode
    if ent.msg_type != MSG_SYSCALL {
        return -1;
    }

    let bytes = &bytes[ent_size..];
    let ent_size = std::mem::size_of::<TimeMsgEnt>();
    let ent = plain::from_bytes::<TimeMsgEnt>(&bytes[0..ent_size])
        .expect("Fail to cast bytes to TimeMsgEnt");

    let mut rslt = 0;
    let id = ent.id;
    let syscall = &SYSCALLS[id as usize];

    if id == SYS_EXIT_GROUP {
        /* Simulate an ctrl-c interrupt here to hint that the
         * traced process exits normally. */
        rslt = -libc::EINTR;
    }

    eprint!(
        "{}: {} ms\n",
        syscall.name,
        (ent.end_time - ent.start_time) as f32 / 10.0_f32.powi(6)
    );

    rslt
}
