mod common;
mod execve;
mod exit;
mod io;
mod syscall_desc;
mod syscall_nr;
mod syscall_tbl;

use crate::syscall::execve::*;
use crate::syscall::exit::*;
use crate::syscall::io::*;
use crate::syscall::syscall_nr::*;
use crate::syscall::syscall_tbl::*;
use plain::Plain;

/* This should be synchronized with the structure
 * syscall_ent_t in syscall/syscall_ent.h */
#[repr(C)]
struct SyscallEnt {
    id: u64,
    ret: u64,
}
unsafe impl Plain for SyscallEnt {}

fn handle_args(id: u64, args: &[u8], ret: u64) {
    match id {
        SYS_READ => handle_read_args(args, ret as usize),
        SYS_WRITE => handle_write_args(args),
        SYS_EXECVE => handle_execve_args(args),
        SYS_EXIT_GROUP => handle_exit_group_args(args),
        _ => eprint!("()"),
    }
}

fn handle_ret_value(id: u64, ret: u64) -> i32 {
    match id {
        SYS_BRK | SYS_MMAP => eprint!(" = 0x{:x}", ret),
        SYS_EXIT_GROUP => {
            eprint!(" = ?");
            /* Simulate an ctrl-c interrupt here to hint that the
             * traced process exits normally. */
            return -libc::EINTR;
        }
        _ => eprint!(" = {}", ret as i64),
    };

    0
}

pub fn syscall_ent_handler(bytes: &[u8]) -> i32 {
    let ent_size = std::mem::size_of::<SyscallEnt>();
    let ent = plain::from_bytes::<SyscallEnt>(&bytes[0..ent_size])
        .expect("Fail to cast bytes to SyscallEnt");
    let args = &bytes[ent_size..];

    let id = ent.id;
    let ret = ent.ret;

    let syscall = &SYSCALLS[id as usize];
    eprint!("{}", syscall.name);

    handle_args(id, args, ret);

    let result = handle_ret_value(id, ret);

    /* End up with a change line here */
    eprint!("\n");

    result
}
