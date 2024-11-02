use crate::common::EMPTY_STR;
use crate::config::CONFIG;

use crate::arch::syscall_nr::*;
use crate::arch::syscall_tbl::SYSCALLS;

use crate::{
    access, desc, dup, execve, exit, io, ioctl, ipc_shm, lseek, mem, net, open, poll, rt_sigreturn,
    signal, stat,
};
use plain::Plain;

#[repr(C)]
struct SyscallEnt {
    id: u64,
    ret: u64,
    start_time: u64,
    end_time: u64,
}
unsafe impl Plain for SyscallEnt {}

fn handle_args(id: u64, args: &[u8], ret: u64) -> String {
    match id {
        SYS_READ => io::handle_read_args(args, ret as usize),
        SYS_WRITE => io::handle_write_args(args),
        SYS_CLOSE => desc::handle_close_args(args),
        SYS_FSTAT => stat::handle_fstat_args(args),
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
        SYS_MREMAP => mem::handle_mremap_args(args),
        SYS_MSYNC => mem::handle_msync_args(args),
        SYS_MINCORE => mem::handle_mincore_args(args),
        SYS_MADVISE => mem::handle_madvise_args(args),
        SYS_SHMGET => ipc_shm::handle_shmget_args(args),
        SYS_SHMAT => ipc_shm::handle_shmat_args(args),
        SYS_SHMCTL => ipc_shm::handle_shmctl_args(args),
        SYS_DUP => dup::handle_dup_args(args),
        SYS_NEWFSTATAT => stat::handle_newfstatat_args(args),
        SYS_EXECVE => execve::handle_execve_args(args),
        SYS_OPENAT => open::handle_openat_args(args),
        SYS_EXIT_GROUP => exit::handle_exit_group_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_OPEN => open::handle_open_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_STAT => stat::handle_stat_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_LSTAT => stat::handle_lstat_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_POLL => poll::handle_poll_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_ACCESS => access::handle_access_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_PIPE => net::handle_pipe_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_SELECT => desc::handle_select_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_DUP2 => dup::handle_dup2_args(args),
        _ => EMPTY_STR.to_owned(),
    }
}

fn handle_return(id: u64, ret_val: u64) -> (String, String) {
    let ret_val = ret_val as i64;

    let ret = if ret_val < 0 {
        "-1".to_owned()
    } else {
        match id {
            SYS_BRK | SYS_MMAP | SYS_MREMAP | SYS_SHMAT => format!("0x{:x}", ret_val),
            SYS_RT_SIGRETURN | SYS_EXIT_GROUP => "?".to_owned(),
            _ => ret_val.to_string(),
        }
    };

    let mut aux = EMPTY_STR.to_owned();

    if ret_val < 0 {
        aux = format!(" {}", std::io::Error::from_raw_os_error(-(ret_val as i32)))
    }

    #[cfg(all(target_arch = "x86_64"))]
    if id == SYS_SELECT && ret_val == 0 {
        aux = " (Timeout)".to_string()
    }

    (ret, aux)
}

fn handle_time(start_time: u64, end_time: u64) -> String {
    let time = (end_time - start_time) as f32 / 10.0_f32.powi(6);
    let time_str = if CONFIG.syscall_times {
        format!(" <{time} ms>")
    } else {
        EMPTY_STR.to_owned()
    };

    time_str
}

pub(super) fn syscall_ent_handler(bytes: &[u8]) -> i32 {
    let mut rslt = 0;

    let ent_size = std::mem::size_of::<SyscallEnt>();
    let ent = plain::from_bytes::<SyscallEnt>(&bytes[0..ent_size])
        .expect("Fail to cast bytes to SyscallEnt");
    let args = &bytes[ent_size..];

    let id = ent.id;
    let syscall = &SYSCALLS[id as usize];
    let name = syscall.name;

    let args_str = handle_args(id, args, ent.ret);
    let (ret, aux) = handle_return(id, ent.ret);
    let time = handle_time(ent.start_time, ent.end_time);

    if id == SYS_EXIT_GROUP {
        /* Simulate an ctrl-c interrupt here to hint that the
         * traced process exits normally. */
        rslt = -libc::EINTR;
    }

    eprint!("{name}({args_str}) = {ret}{aux}{time}\n");

    rslt
}
