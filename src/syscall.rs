use crate::syscall_nr::*;
use crate::syscall_tbl::*;
use plain::Plain;
use std::str::from_utf8;

const BUF_SIZE: usize = 32;
/* This should be synchronized with the structure
 * syscall_ent_t in syscall/strace_ent.h */
#[repr(C)]
struct ReadArgs {
    fd: i32,
    buf: [u8; BUF_SIZE],
    count: usize,
}
unsafe impl Plain for ReadArgs {}

#[repr(C)]
struct WriteArgs {
    fd: i32,
    buf: [u8; BUF_SIZE],
    count: usize,
}
unsafe impl Plain for WriteArgs {}

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

    let extra = if read.count > (BUF_SIZE - 1) { "..." } else { "" };
    eprint!("({}, {:?} {}, {})", read.fd, read.buf, extra, read.count);
}

fn handle_write_args(args: &[u8]) {
    let size = std::mem::size_of::<WriteArgs>();
    let slice = &args[0..size];
    let write = plain::from_bytes::<WriteArgs>(slice).expect("Fail to cast bytes to WriteArgs");

    let extra = if write.count > (BUF_SIZE - 1) { "..." } else { "" };
    let count = if write.count > (BUF_SIZE - 1) { BUF_SIZE } else { write.count };
    let s = from_utf8(&write.buf[0..count]).unwrap();
    eprint!("({}, {} {}, {})", write.fd, s, extra, write.count);
}

fn handle_args(id: u64, args: &[u8]) {
    match id {
        SYS_READ => handle_read_args(args),
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

    handle_args(ent.id, &ent.args);

    handle_ret_value(ent.id, ent.ret);

    /* End up with a change line here */
    eprint!("\n");
    return 0;
}
