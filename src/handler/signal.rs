use crate::common::*;
use plain::Plain;

#[repr(C)]
struct SiKill {
    pid: libc::pid_t,
    uid: libc::uid_t,
}
unsafe impl Plain for SiKill {}

/* FIXME: We use the own defined siginfo_t struct instead of the libc one.
 * It is because the padding bytes here are inaccessible for some
 * reasons, but we'll need them for the specific struct in
 * union __sifields. However, this could be unsafe if kernel modifies
 * the structure someday.
 *
 * See https://docs.rs/libc/latest/libc/struct.siginfo_t.html */
#[repr(C)]
struct SigInfo {
    pub si_signo: c_int,
    pub si_errno: c_int,
    pub si_code: c_int,
    _pad: [u8; 1 * 4],
    pub sifields: [u8; 28 * 4],
    _align: [u64; 0],
}
unsafe impl Plain for SigInfo {}

#[repr(C)]
struct SignalEnt {
    signo: c_int,
    siginfo: SigInfo,
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
    let siginfo = format_siginfo(&ent.siginfo);
    eprint!("--- {} {{{}}} ---\n", signo, siginfo);
    0
}

fn format_si_info(sip: &SigInfo) -> String {
    let sifields = &sip.sifields;
    match sip.si_code {
        SI_TKILL => {
            let si_kill = get_args::<SiKill>(sifields);
            format!("si_pid={}, si_uid={}", si_kill.pid, si_kill.uid)
        }
        _ => "".to_string(),
    }
}

fn format_siginfo(siginfo: &SigInfo) -> String {
    let si_signo = format_signum(siginfo.si_signo);
    let si_code = format_value(
        siginfo.si_code as u64,
        Some("SI_??"),
        &SI_CODE_DESCS,
        Format::Hex,
    );
    let si_info = format_si_info(siginfo);

    return format!("si_signo={}, si_code={}, {}", si_signo, si_code, si_info);
}
