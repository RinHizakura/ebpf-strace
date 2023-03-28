use crate::syscall_tbl::*;
use plain::Plain;

/* This should be synchronized with the structure
 * syscall_ent_t in strace.bpf.c */
#[repr(C)]
struct SyscallEnt {
    id: u64,
    ret: u64,
}

unsafe impl Plain for SyscallEnt {}

pub fn syscall_ent_handler(bytes: &[u8]) -> i32 {
    let result = plain::from_bytes::<SyscallEnt>(bytes);
    if result.is_err() {
        return -1;
    }
    let ent = result.unwrap();

    let syscall = &SYSCALLS[ent.id as usize];
    eprintln!("{} = {}", syscall.name, ent.ret as i64);

    0
}
