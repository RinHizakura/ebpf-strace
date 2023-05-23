#[macro_use]
mod common;
mod execve;
mod exit;
mod io;
mod open_close;
mod stat;
mod syscall_desc;
mod syscall_nr;
mod syscall_tbl;

use crate::syscall;
use crate::syscall::syscall_nr::*;
use crate::syscall::syscall_tbl::SYSCALLS;

use plain::Plain;

/* This should be synchronized with the structure
 * syscall_ent_t in syscall/syscall_ent.h */
#[repr(C)]
struct SyscallEnt {
    id: u64,
    ret: u64,
}
unsafe impl Plain for SyscallEnt {}

fn handle_args(id: u64, args: &[u8], ret: u64) -> String {
    match id {
        SYS_READ => syscall::io::handle_read_args(args, ret as usize),
        SYS_WRITE => syscall::io::handle_write_args(args),
        SYS_OPEN => syscall::open_close::handle_open_args(args),
        SYS_CLOSE => syscall::open_close::handle_close_args(args),
        SYS_STAT => syscall::stat::handle_stat_args(args),
        SYS_FSTAT => syscall::stat::handle_fstat_args(args),
        SYS_LSTAT => syscall::stat::handle_lstat_args(args),
        SYS_EXECVE => syscall::execve::handle_execve_args(args),
        SYS_OPENAT => syscall::open_close::handle_openat_args(args),
        SYS_EXIT_GROUP => syscall::exit::handle_exit_group_args(args),
        _ => "".to_string(),
    }
}

pub fn syscall_ent_handler(bytes: &[u8]) -> i32 {
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
