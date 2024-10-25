use crate::handler::signal::signal_ent_handler;
use crate::handler::syscall::syscall_ent_handler;

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
