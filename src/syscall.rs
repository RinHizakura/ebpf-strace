use crate::syscall_nr::*;
use crate::syscall_tbl::*;
use plain::Plain;

/* This should be synchronized with the structure
 * syscall_ent_t in strace.bpf.c */
#[repr(C)]
struct ReadArgs {
    fd: i32,
    buf: [u8; 32],
    count: usize,
}
unsafe impl Plain for ReadArgs {}

#[repr(C)]
struct SyscallEnt {
    id: u64,
    ret: u64,
    args: [u8; 64],
}
unsafe impl Plain for SyscallEnt {}

fn handle_read_args(args: &[u8]) {
    let size = std::mem::size_of::<ReadArgs>();
    let slice = &args[0..size];
    let read = plain::from_bytes::<ReadArgs>(slice).expect("Fail to cast bytes to ReadArgs");
    eprint!("({}, {}, {})", read.fd, read.buf[0], read.count);
}

fn handle_args(id: u64, args: &[u8]) {
    match id {
        SYS_READ => handle_read_args(args),
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

    handle_args(ent.id, &ent.args);

    handle_ret_value(ent.id, ent.ret);

    /* End up with a change line here */
    eprint!("\n");
    return 0;
}
