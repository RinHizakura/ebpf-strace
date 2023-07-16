use crate::syscall::syscall_nr::*;
use crate::syscall::syscall_tbl::SYSCALLS;
use crate::{
    access, desc, execve, exit, io, ioctl, lseek, mem, net, open, poll, rt_sigreturn, signal, stat,
};
use plain::Plain;

#[repr(C)]
struct SyscallEnt {
    id: u64,
    ret: u64,
}
unsafe impl Plain for SyscallEnt {}

fn handle_args(id: u64, args: &[u8], ret: u64) -> String {
    match id {
        SYS_READ => io::handle_read_args(args, ret as usize),
        SYS_WRITE => io::handle_write_args(args),
        SYS_OPEN => open::handle_open_args(args),
        SYS_CLOSE => desc::handle_close_args(args),
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
        SYS_IOCTL => ioctl::handle_ioctl_args(args),
        SYS_PREAD64 => io::handle_pread_args(args, ret as usize),
        SYS_PWRITE64 => io::handle_pwrite_args(args),
        SYS_READV => io::handle_readv_args(args),
        SYS_WRITEV => io::handle_writev_args(args),
        SYS_ACCESS => access::handle_access_args(args),
        SYS_PIPE => net::handle_pipe_args(args),
        SYS_SELECT => desc::handle_select_args(args),
        SYS_NEWFSTATAT => stat::handle_newfstatat_args(args),
        SYS_EXECVE => execve::handle_execve_args(args),
        SYS_OPENAT => open::handle_openat_args(args),
        SYS_EXIT_GROUP => exit::handle_exit_group_args(args),
        _ => "".to_string(),
    }
}

pub(super) fn syscall_ent_handler(bytes: &[u8]) -> i32 {
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
