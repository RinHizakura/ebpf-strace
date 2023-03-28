use crate::syscall_tbl::*;
use crate::syscall_nr::*;
use plain::Plain;

/* This should be synchronized with the structure
 * syscall_ent_t in strace.bpf.c */
#[repr(C)]
struct SyscallEnt {
    id: u64,
    ret: u64,
}

unsafe impl Plain for SyscallEnt {}

fn handle_ret_value(id: u64, ret: u64) {
    match id {
        SYS_BRK | SYS_MMAP => eprint!(" = 0x{:x}", ret),
        _ => eprint!(" = {}", ret as i64),
    };
}

pub fn syscall_ent_handler(bytes: &[u8]) -> i32 {
    let result = plain::from_bytes::<SyscallEnt>(bytes);
    if result.is_err() {
        return -1;
    }
    let ent = result.unwrap();

    let syscall = &SYSCALLS[ent.id as usize];
    eprint!("{}", syscall.name);
    handle_ret_value(ent.id, ent.ret);

    /* End up with a change line here */
    eprint!("\n");
    0
}
