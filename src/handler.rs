use crate::common::*;
use crate::syscall::syscall_nr::*;
use crate::syscall::syscall_tbl::SYSCALLS;
use crate::{execve, exit, io, lseek, mem, open_close, poll, rt_sigreturn, signal, stat};

use plain::Plain;

/* These should be synchronized with the structure
 * syscall_ent_t in syscall/syscall_ent.h */
#[repr(C)]
struct MsgEnt {
    msg_type: u64,
}
unsafe impl Plain for MsgEnt {}

#[repr(C)]
struct SyscallEnt {
    id: u64,
    ret: u64,
}
unsafe impl Plain for SyscallEnt {}

#[repr(C)]
struct SignalEnt {
    signo: c_int,
    siginfo: libc::siginfo_t,
}
unsafe impl Plain for SignalEnt {}

fn handle_args(id: u64, args: &[u8], ret: u64) -> String {
    match id {
        SYS_READ => io::handle_read_args(args, ret as usize),
        SYS_WRITE => io::handle_write_args(args),
        SYS_OPEN => open_close::handle_open_args(args),
        SYS_CLOSE => open_close::handle_close_args(args),
        SYS_STAT => stat::handle_stat_args(args),
        SYS_FSTAT => stat::handle_fstat_args(args),
        SYS_LSTAT => stat::handle_lstat_args(args),
        SYS_POLL => poll::handle_poll_args(args),
        SYS_LSEEK => lseek::handle_lseek_args(args),
        SYS_MMAP => mem::handle_mmap_args(args),
        SYS_MPROTECT => mem::handle_mprotect_args(args),
        SYS_MUNMAP => mem::handle_munmap_args(args),
        SYS_BRK => mem::handle_brk_args(args),
        SYS_RT_SIGACTION => signal::handle_rt_sigaction_args(args),
        SYS_RT_SIGPROCMASK => signal::handle_rt_sigprocmask_args(args),
        SYS_RT_SIGRETURN => rt_sigreturn::handle_rt_sigreturn_args(args),
        SYS_NEWFSTATAT => stat::handle_newfstatat_args(args),
        SYS_EXECVE => execve::handle_execve_args(args),
        SYS_OPENAT => open_close::handle_openat_args(args),
        SYS_EXIT_GROUP => exit::handle_exit_group_args(args),
        _ => "".to_string(),
    }
}

fn syscall_ent_handler(bytes: &[u8]) -> i32 {
    let ent_size = std::mem::size_of::<SyscallEnt>();
    let ent = plain::from_bytes::<SyscallEnt>(&bytes[0..ent_size])
        .expect("Fail to cast bytes to SyscallEnt");
    let args = &bytes[ent_size..];

    let id = ent.id;
    let ret = ent.ret;

    let syscall = &SYSCALLS[id as usize];
    let args_str = handle_args(id, args, ret);

    match id {
        SYS_BRK | SYS_MMAP => eprint!("{}({}) = 0x{:x}\n", syscall.name, args_str, ret),
        SYS_RT_SIGRETURN => eprint!("{}({}) = ?\n", syscall.name, args_str),
        SYS_EXIT_GROUP => {
            eprint!("{}({}) = ?\n", syscall.name, args_str);
            /* Simulate an ctrl-c interrupt here to hint that the
             * traced process exits normally. */
            return -libc::EINTR;
        }
        _ => eprint!("{}({}) = {}\n", syscall.name, args_str, ret as i64),
    }

    0
}

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

fn signal_ent_handler(bytes: &[u8]) -> i32 {
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
