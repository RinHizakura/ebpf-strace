use crate::common::*;
use plain::Plain;

#[repr(C)]
struct SignalEnt {
    signo: c_int,
    siginfo: libc::siginfo_t,
}
unsafe impl Plain for SignalEnt {}

const SI_USER: c_int = 0;
const SI_KERNEL: c_int = 0x80;
const SI_QUEUE: c_int = -1;
const SI_TIMER: c_int = -2;
const SI_MESGQ: c_int = -3;
const SI_ASYNCIO: c_int = -4;
const SI_SIGIO: c_int = -5;
const SI_TKILL: c_int = -6;

const SI_CODE_DESCS: &[Desc] = &[
    desc!(SI_USER),
    desc!(SI_KERNEL),
    desc!(SI_QUEUE),
    desc!(SI_TIMER),
    desc!(SI_MESGQ),
    desc!(SI_ASYNCIO),
    desc!(SI_SIGIO),
    desc!(SI_TKILL),
];

pub(super) fn signal_ent_handler(bytes: &[u8]) -> i32 {
    let ent_size = std::mem::size_of::<SignalEnt>();
    let ent = plain::from_bytes::<SignalEnt>(&bytes[0..ent_size])
        .expect("Fail to cast bytes to SignalEnt");

    let signo = format_signum(ent.signo);
    let si_signo = format_signum(ent.siginfo.si_signo);
    let si_code = format_value(ent.siginfo.si_code as u64, "SI_??", &SI_CODE_DESCS);
    eprint!(
        "--- {} {{si_signo={}, si_code={}}} ---\n",
        signo, si_signo, si_code
    );
    0
}

