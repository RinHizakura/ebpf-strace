mod common;
mod io;
mod syscall_desc;
mod syscall_nr;
mod syscall_tbl;

use crate::syscall::io::*;
use crate::syscall::syscall_nr::*;
use crate::syscall::syscall_tbl::*;
use plain::Plain;

#[repr(C)]
struct SyscallEnt {
    id: u64,
    ret: u64,
    args: [u8; 64],
}
unsafe impl Plain for SyscallEnt {}

fn handle_args(id: u64, args: &[u8], ret: u64) {
    match id {
        SYS_READ => handle_read_args(args, ret as usize),
        SYS_WRITE => handle_write_args(args),
        _ => eprint!("()"),
    }
}

fn handle_ret_value(id: u64, ret: u64) {
    match id {
        SYS_BRK | SYS_MMAP => eprint!(" = 0x{:x}", ret),
        _ => eprint!(" = {}", ret as i64),
    };
}

pub fn syscall_ent_handler(bytes: &[u8]) -> i32 {
    let ent = plain::from_bytes::<SyscallEnt>(bytes).expect("Fail to cast bytes to SyscallEnt");

    let syscall = &SYSCALLS[ent.id as usize];
    eprint!("{}", syscall.name);

    handle_args(ent.id, &ent.args, ent.ret);

    handle_ret_value(ent.id, ent.ret);

    /* End up with a change line here */
    eprint!("\n");
    return 0;
}
