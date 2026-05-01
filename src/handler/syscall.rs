use crate::common::{format_errno, EMPTY_STR};
use crate::config::CONFIG;

use crate::arch::syscall_nr::*;
use crate::arch::syscall_tbl::SYSCALLS;

use crate::{
    access, bind, chdir, chmod, clone, desc, dirent, dup, epoll, execve, exit, fchownat, fcntl,
    getcwd, getpid, getrandom, io, ioctl, ipc_shm, link, listen, lseek, mem, mkdir, net, open,
    poll, prctl, readlink, renameat, resource, rmdir, rt_sigreturn, shutdown, signal, stat,
    symlinkat, time, truncate, uid, unlink, wait,
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
        // signal (kill family)
        SYS_KILL => signal::handle_kill_args(args),
        SYS_TKILL => signal::handle_tkill_args(args),
        SYS_TGKILL => signal::handle_tgkill_args(args),
        // process management
        SYS_WAIT4 => wait::handle_wait4_args(args, ret),
        SYS_CLONE => clone::handle_clone_args(args),
        SYS_SETUID => uid::handle_setuid_args(args),
        SYS_SETGID => uid::handle_setgid_args(args),
        SYS_SETPGID => getpid::handle_setpgid_args(args),
        SYS_GETPGID => getpid::handle_getpgid_args(args),
        SYS_GETSID => getpid::handle_getsid_args(args),
        SYS_PRCTL => prctl::handle_prctl_args(args),
        // fd / sync
        SYS_FSYNC => desc::handle_fsync_args(args),
        SYS_FDATASYNC => desc::handle_fdatasync_args(args),
        SYS_SYNCFS => desc::handle_syncfs_args(args),
        SYS_CLOSE_RANGE => desc::handle_close_range_args(args),
        SYS_PIPE2 => desc::handle_pipe2_args(args),
        SYS_DUP3 => dup::handle_dup3_args(args),
        SYS_FCNTL => fcntl::handle_fcntl_args(args),
        // file ops
        SYS_FCHDIR => chdir::handle_fchdir_args(args),
        SYS_FCHMOD => chmod::handle_fchmod_args(args),
        SYS_FCHOWN => fchownat::handle_fchown_args(args),
        SYS_FTRUNCATE => truncate::handle_ftruncate_args(args),
        SYS_GETDENTS64 => dirent::handle_getdents64_args(args, ret as i64),
        SYS_CHDIR => chdir::handle_chdir_args(args),
        SYS_GETCWD => getcwd::handle_getcwd_args(args),
        SYS_MKDIRAT => mkdir::handle_mkdirat_args(args),
        SYS_UNLINKAT => unlink::handle_unlinkat_args(args),
        SYS_RENAMEAT => renameat::handle_renameat_args(args),
        // network
        SYS_SOCKET => net::handle_socket_args(args),
        SYS_SHUTDOWN => shutdown::handle_shutdown_args(args),
        SYS_LISTEN => listen::handle_listen_args(args),
        SYS_BIND => bind::handle_bind_args(args),
        SYS_CONNECT => net::handle_connect_args(args),
        SYS_ACCEPT => net::handle_accept_args(args),
        SYS_ACCEPT4 => net::handle_accept4_args(args),
        SYS_SENDTO => net::handle_sendto_args(args),
        SYS_RECVFROM => net::handle_recvfrom_args(args, ret),
        // time
        SYS_NANOSLEEP => time::handle_nanosleep_args(args),
        SYS_CLOCK_GETTIME => time::handle_clock_gettime_args(args),
        SYS_CLOCK_GETRES => time::handle_clock_getres_args(args),
        SYS_GETTIMEOFDAY => time::handle_gettimeofday_args(args),
        // epoll
        SYS_EPOLL_CREATE1 => epoll::handle_epoll_create1_args(args),
        SYS_EPOLL_CTL => epoll::handle_epoll_ctl_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_EPOLL_WAIT => epoll::handle_epoll_wait_args(args, ret as i64),
        // resource limits
        SYS_PRLIMIT64 => resource::handle_prlimit64_args(args),
        SYS_SETRLIMIT => resource::handle_setrlimit_args(args),
        SYS_GETRLIMIT => resource::handle_getrlimit_args(args),
        // misc
        SYS_GETRANDOM => getrandom::handle_getrandom_args(args, ret as i64),
        // memory locking
        SYS_MLOCK => mem::handle_mlock_args(args),
        SYS_MUNLOCK => mem::handle_munlock_args(args),
        SYS_MLOCKALL => mem::handle_mlockall_args(args),
        SYS_MLOCK2 => mem::handle_mlock2_args(args),
        SYS_TRUNCATE => truncate::handle_truncate_args(args),
        // x86_64-only old syscalls
        #[cfg(all(target_arch = "x86_64"))]
        SYS_MKDIR => mkdir::handle_mkdir_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_RMDIR => rmdir::handle_rmdir_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_UNLINK => unlink::handle_unlink_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_CHMOD => chmod::handle_chmod_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_CHOWN => fchownat::handle_chown_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_RENAME => renameat::handle_rename_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_LINK => link::handle_link_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_SYMLINK => symlinkat::handle_symlink_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_READLINK => readlink::handle_readlink_args(args, ret),
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
        SYS_PIPE => desc::handle_pipe_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_SELECT => desc::handle_select_args(args),
        #[cfg(all(target_arch = "x86_64"))]
        SYS_DUP2 => dup::handle_dup2_args(args),
        _ => EMPTY_STR.to_owned(),
    }
}

fn handle_return_aux(id: u64, args: &[u8], ret_val: u64) -> String {
    #[cfg(target_arch = "x86_64")]
    if id == SYS_POLL {
        return poll::handle_poll_ret_aux(args, ret_val as i64);
    }
    if id == SYS_PRCTL {
        return prctl::handle_prctl_ret_aux(args, ret_val as i64);
    }
    #[cfg(target_arch = "x86_64")]
    if id == SYS_SELECT {
        return desc::handle_select_ret_aux(args, ret_val as i64);
    }
    let _ = (id, args, ret_val);
    EMPTY_STR.to_owned()
}

fn handle_return(id: u64, ret_val: u64) -> (String, String) {
    let ret_val = ret_val as i64;

    let ret = if ret_val < 0 {
        "-1".to_owned()
    } else {
        match id {
            SYS_BRK | SYS_MMAP | SYS_MREMAP | SYS_SHMAT => format!("0x{:x}", ret_val),
            SYS_EXIT_GROUP => "?".to_owned(),
            _ => ret_val.to_string(),
        }
    };

    let mut aux = EMPTY_STR.to_owned();

    if ret_val < 0 {
        aux = format!(" {}", format_errno(-(ret_val as i32)))
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
    let (ret, mut aux) = handle_return(id, ent.ret);
    aux.push_str(&handle_return_aux(id, args, ent.ret));
    let time = handle_time(ent.start_time, ent.end_time);

    if id == SYS_EXIT_GROUP {
        /* Simulate an ctrl-c interrupt here to hint that the
         * traced process exits normally. */
        rslt = -libc::EINTR;
    }

    eprint!("{name}({args_str}) = {ret}{aux}{time}\n");

    rslt
}
