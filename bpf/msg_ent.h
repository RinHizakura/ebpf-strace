#ifndef SYSCALL_ENT_H
#define SYSCALL_ENT_H

/* Reference:
 * - https://elixir.bootlin.com/linux/latest/source/include/linux/build_bug.h */
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)

#define ARR_ENT_SIZE 4
#define BUF_SIZE 32
#define ARGS_SIZE 1024

/* TODO: Decomment the following lines to check the arguments
 * size when all of them are completed.
 *
 * #define __SYSCALL(nr, call)                            \
 *   static_assert(sizeof(call##_args_t) <= ARGS_SIZE);
 * #include "../syscall/syscall_tbl.h"
 * #undef __SYSCALL
 */
#define MSG_SYSCALL 0
#define MSG_SIGNAL 1
typedef struct {
    u64 msg_type;
    u8 inner[0];
} msg_ent_t;

typedef struct {
    u64 id;
    u64 ret;
} basic_t;

typedef struct {
    basic_t basic;
    u8 bytes[ARGS_SIZE];
} syscall_ent_t;

typedef struct {
    int fd;
    u8 buf[BUF_SIZE];
    size_t count;
} read_args_t;

typedef struct {
    int fd;
    u8 buf[BUF_SIZE];
    size_t count;
} write_args_t;

typedef struct {
    u8 pathname[BUF_SIZE];
    int flags;
    mode_t mode;
} open_args_t;

typedef struct {
    int fd;
} close_args_t;

typedef struct {
    u8 pathname[BUF_SIZE];
    struct stat statbuf;
} stat_args_t;

typedef struct {
    int fd;
    struct stat statbuf;
} fstat_args_t;

typedef struct {
    u8 pathname[BUF_SIZE];
    struct stat statbuf;
} lstat_args_t;

typedef struct {
    struct pollfd fds[ARR_ENT_SIZE];
    u32 nfds;
    int timeout;
} poll_args_t;

typedef struct {
    int fd;
    off_t offset;
    int whence;
} lseek_args_t;

typedef struct {
    void *addr;
    size_t length;
    int prot;
    int flags;
    int fd;
    off_t offset;
} mmap_args_t;

typedef struct {
    void *addr;
    size_t len;
    int prot;
} mprotect_args_t;

typedef struct {
    void *addr;
    size_t length;
} munmap_args_t;

typedef struct {
    void *addr;
} brk_args_t;

typedef struct {
    struct sigaction act;
    struct sigaction oldact;
    size_t sigsetsize;
    int signum;

    /* These are extra field(not copy directly from the syscall) to
     * hint whether the sigaction is passed as NULL originally */
    bool is_act_exist;
    bool is_oldact_exist;
} rt_sigaction_args_t;

typedef struct {
    sigset_t set;
    sigset_t oldset;
    size_t sigsetsize;
    int how;

    /* These are extra field(not copy directly from the syscall) to
     * hint whether the sigset_t is passed as NULL originally */
    bool is_set_exist;
    bool is_oldset_exist;
} rt_sigprocmask_args_t;

typedef struct {
    sigset_t set;
} rt_sigreturn_args_t;

typedef struct {
    int fd;
    unsigned long request;
    unsigned long arg;
} ioctl_args_t;

typedef struct {
    int fd;
    u8 buf[BUF_SIZE];
    size_t count;
    off_t offset;
} pread64_args_t;

typedef struct {
    int fd;
    u8 buf[BUF_SIZE];
    size_t count;
    off_t offset;
} pwrite64_args_t;

typedef struct {
    u8 iov_base[BUF_SIZE];
    size_t iov_len;
} iovec_trace_t;

typedef struct {
    iovec_trace_t iov[ARR_ENT_SIZE];
    int fd;
    int iovcnt;
} readv_args_t;

typedef struct {
    iovec_trace_t iov[ARR_ENT_SIZE];
    int fd;
    int iovcnt;
} writev_args_t;

typedef struct {
    u8 pathname[BUF_SIZE];
    int mode;
} access_args_t;

typedef struct {
    int pipefd[2];
} pipe_args_t;

/* FIXME: Is it possible to have this in vmlinux.h? */
struct timeval {
    long tv_sec;
    long tv_usec;
};

typedef struct {
    int nfds;
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    struct timeval timeout;

    bool is_readfds_exist;
    bool is_writefds_exist;
    bool is_exceptfds_exist;
    bool is_timeout_exist;
} select_args_t;

typedef struct {
} sched_yield_args_t;

typedef struct {
    void *old_address;
    void *new_address;
    size_t old_size;
    size_t new_size;
    int flags;
} mremap_args_t;

typedef struct {
} msync_args_t;
typedef struct {
} mincore_args_t;
typedef struct {
} madvise_args_t;
typedef struct {
} shmget_args_t;
typedef struct {
} shmat_args_t;
typedef struct {
} shmctl_args_t;
typedef struct {
} dup_args_t;
typedef struct {
} dup2_args_t;
typedef struct {
} pause_args_t;
typedef struct {
} nanosleep_args_t;
typedef struct {
} getitimer_args_t;
typedef struct {
} alarm_args_t;
typedef struct {
} setitimer_args_t;
typedef struct {
} getpid_args_t;
typedef struct {
} sendfile_args_t;
typedef struct {
} socket_args_t;
typedef struct {
} connect_args_t;
typedef struct {
} accept_args_t;
typedef struct {
} sendto_args_t;
typedef struct {
} recvfrom_args_t;
typedef struct {
} sendmsg_args_t;
typedef struct {
} recvmsg_args_t;
typedef struct {
} shutdown_args_t;
typedef struct {
} bind_args_t;
typedef struct {
} listen_args_t;
typedef struct {
} getsockname_args_t;
typedef struct {
} getpeername_args_t;
typedef struct {
} socketpair_args_t;
typedef struct {
} setsockopt_args_t;
typedef struct {
} getsockopt_args_t;
typedef struct {
} clone_args_t;
typedef struct {
} fork_args_t;
typedef struct {
} vfork_args_t;

typedef struct {
    u8 pathname[BUF_SIZE];
    u8 argv[ARR_ENT_SIZE][BUF_SIZE];
    size_t envp;
    u8 argc;
    u8 envp_cnt;
} execve_args_t;

typedef struct {
} exit_args_t;
typedef struct {
} wait4_args_t;
typedef struct {
} kill_args_t;
typedef struct {
} uname_args_t;
typedef struct {
} semget_args_t;
typedef struct {
} semop_args_t;
typedef struct {
} semctl_args_t;
typedef struct {
} shmdt_args_t;
typedef struct {
} msgget_args_t;
typedef struct {
} msgsnd_args_t;
typedef struct {
} msgrcv_args_t;
typedef struct {
} msgctl_args_t;
typedef struct {
} fcntl_args_t;
typedef struct {
} flock_args_t;
typedef struct {
} fsync_args_t;
typedef struct {
} fdatasync_args_t;
typedef struct {
} truncate_args_t;
typedef struct {
} ftruncate_args_t;
typedef struct {
} getdents_args_t;
typedef struct {
} getcwd_args_t;
typedef struct {
} chdir_args_t;
typedef struct {
} fchdir_args_t;
typedef struct {
} rename_args_t;
typedef struct {
} mkdir_args_t;
typedef struct {
} rmdir_args_t;
typedef struct {
} creat_args_t;
typedef struct {
} link_args_t;
typedef struct {
} unlink_args_t;
typedef struct {
} symlink_args_t;
typedef struct {
} readlink_args_t;
typedef struct {
} chmod_args_t;
typedef struct {
} fchmod_args_t;
typedef struct {
} chown_args_t;
typedef struct {
} fchown_args_t;
typedef struct {
} lchown_args_t;
typedef struct {
} umask_args_t;
typedef struct {
} gettimeofday_args_t;
typedef struct {
} getrlimit_args_t;
typedef struct {
} getrusage_args_t;
typedef struct {
} sysinfo_args_t;
typedef struct {
} times_args_t;
typedef struct {
} ptrace_args_t;
typedef struct {
} getuid_args_t;
typedef struct {
} syslog_args_t;
typedef struct {
} getgid_args_t;
typedef struct {
} setuid_args_t;
typedef struct {
} setgid_args_t;
typedef struct {
} geteuid_args_t;
typedef struct {
} getegid_args_t;
typedef struct {
} setpgid_args_t;
typedef struct {
} getppid_args_t;
typedef struct {
} getpgrp_args_t;
typedef struct {
} setsid_args_t;
typedef struct {
} setreuid_args_t;
typedef struct {
} setregid_args_t;
typedef struct {
} getgroups_args_t;
typedef struct {
} setgroups_args_t;
typedef struct {
} setresuid_args_t;
typedef struct {
} getresuid_args_t;
typedef struct {
} setresgid_args_t;
typedef struct {
} getresgid_args_t;
typedef struct {
} getpgid_args_t;
typedef struct {
} setfsuid_args_t;
typedef struct {
} setfsgid_args_t;
typedef struct {
} getsid_args_t;
typedef struct {
} capget_args_t;
typedef struct {
} capset_args_t;
typedef struct {
} rt_sigpending_args_t;
typedef struct {
} rt_sigtimedwait_args_t;
typedef struct {
} rt_sigqueueinfo_args_t;
typedef struct {
} rt_sigsuspend_args_t;
typedef struct {
} sigaltstack_args_t;
typedef struct {
} utime_args_t;
typedef struct {
} mknod_args_t;
typedef struct {
} uselib_args_t;
typedef struct {
} personality_args_t;
typedef struct {
} ustat_args_t;
typedef struct {
} statfs_args_t;
typedef struct {
} fstatfs_args_t;
typedef struct {
} sysfs_args_t;
typedef struct {
} getpriority_args_t;
typedef struct {
} setpriority_args_t;
typedef struct {
} sched_setparam_args_t;
typedef struct {
} sched_getparam_args_t;
typedef struct {
} sched_setscheduler_args_t;
typedef struct {
} sched_getscheduler_args_t;
typedef struct {
} sched_get_priority_max_args_t;
typedef struct {
} sched_get_priority_min_args_t;
typedef struct {
} sched_rr_get_interval_args_t;
typedef struct {
} mlock_args_t;
typedef struct {
} munlock_args_t;
typedef struct {
} mlockall_args_t;
typedef struct {
} munlockall_args_t;
typedef struct {
} vhangup_args_t;
typedef struct {
} modify_ldt_args_t;
typedef struct {
} pivot_root_args_t;
typedef struct {
} _sysctl_args_t;
typedef struct {
} prctl_args_t;
typedef struct {
} arch_prctl_args_t;
typedef struct {
} adjtimex_args_t;
typedef struct {
} setrlimit_args_t;
typedef struct {
} chroot_args_t;
typedef struct {
} sync_args_t;
typedef struct {
} acct_args_t;
typedef struct {
} settimeofday_args_t;
typedef struct {
} mount_args_t;
typedef struct {
} umount2_args_t;
typedef struct {
} swapon_args_t;
typedef struct {
} swapoff_args_t;
typedef struct {
} reboot_args_t;
typedef struct {
} sethostname_args_t;
typedef struct {
} setdomainname_args_t;
typedef struct {
} iopl_args_t;
typedef struct {
} ioperm_args_t;
typedef struct {
} create_module_args_t;
typedef struct {
} init_module_args_t;
typedef struct {
} delete_module_args_t;
typedef struct {
} get_kernel_syms_args_t;
typedef struct {
} query_module_args_t;
typedef struct {
} quotactl_args_t;
typedef struct {
} nfsservctl_args_t;
typedef struct {
} getpmsg_args_t;
typedef struct {
} putpmsg_args_t;
typedef struct {
} afs_syscall_args_t;
typedef struct {
} tuxcall_args_t;
typedef struct {
} security_args_t;
typedef struct {
} gettid_args_t;
typedef struct {
} readahead_args_t;
typedef struct {
} setxattr_args_t;
typedef struct {
} lsetxattr_args_t;
typedef struct {
} fsetxattr_args_t;
typedef struct {
} getxattr_args_t;
typedef struct {
} lgetxattr_args_t;
typedef struct {
} fgetxattr_args_t;
typedef struct {
} listxattr_args_t;
typedef struct {
} llistxattr_args_t;
typedef struct {
} flistxattr_args_t;
typedef struct {
} removexattr_args_t;
typedef struct {
} lremovexattr_args_t;
typedef struct {
} fremovexattr_args_t;
typedef struct {
} tkill_args_t;
typedef struct {
} time_args_t;
typedef struct {
} futex_args_t;
typedef struct {
} sched_setaffinity_args_t;
typedef struct {
} sched_getaffinity_args_t;
typedef struct {
} set_thread_area_args_t;
typedef struct {
} io_setup_args_t;
typedef struct {
} io_destroy_args_t;
typedef struct {
} io_getevents_args_t;
typedef struct {
} io_submit_args_t;
typedef struct {
} io_cancel_args_t;
typedef struct {
} get_thread_area_args_t;
typedef struct {
} lookup_dcookie_args_t;
typedef struct {
} epoll_create_args_t;
typedef struct {
} epoll_ctl_old_args_t;
typedef struct {
} epoll_wait_old_args_t;
typedef struct {
} remap_file_pages_args_t;
typedef struct {
} getdents64_args_t;
typedef struct {
} set_tid_address_args_t;
typedef struct {
} restart_syscall_args_t;
typedef struct {
} semtimedop_args_t;
typedef struct {
} fadvise64_args_t;
typedef struct {
} timer_create_args_t;
typedef struct {
} timer_settime_args_t;
typedef struct {
} timer_gettime_args_t;
typedef struct {
} timer_getoverrun_args_t;
typedef struct {
} timer_delete_args_t;
typedef struct {
} clock_settime_args_t;
typedef struct {
} clock_gettime_args_t;
typedef struct {
} clock_getres_args_t;
typedef struct {
} clock_nanosleep_args_t;

typedef struct {
    int status;
} exit_group_args_t;

typedef struct {
} epoll_wait_args_t;
typedef struct {
} epoll_ctl_args_t;
typedef struct {
} tgkill_args_t;
typedef struct {
} utimes_args_t;
typedef struct {
} vserver_args_t;
typedef struct {
} mbind_args_t;
typedef struct {
} set_mempolicy_args_t;
typedef struct {
} get_mempolicy_args_t;
typedef struct {
} mq_open_args_t;
typedef struct {
} mq_unlink_args_t;
typedef struct {
} mq_timedsend_args_t;
typedef struct {
} mq_timedreceive_args_t;
typedef struct {
} mq_notify_args_t;
typedef struct {
} mq_getsetattr_args_t;
typedef struct {
} kexec_load_args_t;
typedef struct {
} waitid_args_t;
typedef struct {
} add_key_args_t;
typedef struct {
} request_key_args_t;
typedef struct {
} keyctl_args_t;
typedef struct {
} ioprio_set_args_t;
typedef struct {
} ioprio_get_args_t;
typedef struct {
} inotify_init_args_t;
typedef struct {
} inotify_add_watch_args_t;
typedef struct {
} inotify_rm_watch_args_t;
typedef struct {
} migrate_pages_args_t;

typedef struct {
    u8 pathname[BUF_SIZE];
    int dirfd;
    int flags;
    mode_t mode;
} openat_args_t;

typedef struct {
} mkdirat_args_t;
typedef struct {
} mknodat_args_t;
typedef struct {
} fchownat_args_t;
typedef struct {
} futimesat_args_t;

typedef struct {
    u8 pathname[BUF_SIZE];
    int dirfd;
    int flags;
    struct stat statbuf;
} newfstatat_args_t;

typedef struct {
} unlinkat_args_t;
typedef struct {
} renameat_args_t;
typedef struct {
} linkat_args_t;
typedef struct {
} symlinkat_args_t;
typedef struct {
} readlinkat_args_t;
typedef struct {
} fchmodat_args_t;
typedef struct {
} faccessat_args_t;
typedef struct {
} pselect6_args_t;
typedef struct {
} ppoll_args_t;
typedef struct {
} unshare_args_t;
typedef struct {
} set_robust_list_args_t;
typedef struct {
} get_robust_list_args_t;
typedef struct {
} splice_args_t;
typedef struct {
} tee_args_t;
typedef struct {
} sync_file_range_args_t;
typedef struct {
} vmsplice_args_t;
typedef struct {
} move_pages_args_t;
typedef struct {
} utimensat_args_t;
typedef struct {
} epoll_pwait_args_t;
typedef struct {
} signalfd_args_t;
typedef struct {
} timerfd_create_args_t;
typedef struct {
} eventfd_args_t;
typedef struct {
} fallocate_args_t;
typedef struct {
} timerfd_settime_args_t;
typedef struct {
} timerfd_gettime_args_t;
typedef struct {
} accept4_args_t;
typedef struct {
} signalfd4_args_t;
typedef struct {
} eventfd2_args_t;
typedef struct {
} epoll_create1_args_t;
typedef struct {
} dup3_args_t;
typedef struct {
} pipe2_args_t;
typedef struct {
} inotify_init1_args_t;
typedef struct {
} preadv_args_t;
typedef struct {
} pwritev_args_t;
typedef struct {
} rt_tgsigqueueinfo_args_t;
typedef struct {
} perf_event_open_args_t;
typedef struct {
} recvmmsg_args_t;
typedef struct {
} fanotify_init_args_t;
typedef struct {
} fanotify_mark_args_t;
typedef struct {
} prlimit64_args_t;
typedef struct {
} name_to_handle_at_args_t;
typedef struct {
} open_by_handle_at_args_t;
typedef struct {
} clock_adjtime_args_t;
typedef struct {
} syncfs_args_t;
typedef struct {
} sendmmsg_args_t;
typedef struct {
} setns_args_t;
typedef struct {
} getcpu_args_t;
typedef struct {
} process_vm_readv_args_t;
typedef struct {
} process_vm_writev_args_t;
typedef struct {
} kcmp_args_t;
typedef struct {
} finit_module_args_t;
typedef struct {
} sched_setattr_args_t;
typedef struct {
} sched_getattr_args_t;
typedef struct {
} renameat2_args_t;
typedef struct {
} seccomp_args_t;
typedef struct {
} getrandom_args_t;
typedef struct {
} memfd_create_args_t;
typedef struct {
} kexec_file_load_args_t;
typedef struct {
} bpf_args_t;
typedef struct {
} execveat_args_t;
typedef struct {
} userfaultfd_args_t;
typedef struct {
} membarrier_args_t;
typedef struct {
} mlock2_args_t;
typedef struct {
} copy_file_range_args_t;
typedef struct {
} preadv2_args_t;
typedef struct {
} pwritev2_args_t;
typedef struct {
} pkey_mprotect_args_t;
typedef struct {
} pkey_alloc_args_t;
typedef struct {
} pkey_free_args_t;
typedef struct {
} statx_args_t;
typedef struct {
} io_pgetevents_args_t;
typedef struct {
} rseq_args_t;
typedef struct {
} pidfd_send_signal_args_t;
typedef struct {
} io_uring_setup_args_t;
typedef struct {
} io_uring_enter_args_t;
typedef struct {
} io_uring_register_args_t;
typedef struct {
} open_tree_args_t;
typedef struct {
} move_mount_args_t;
typedef struct {
} fsopen_args_t;
typedef struct {
} fsconfig_args_t;
typedef struct {
} fsmount_args_t;
typedef struct {
} fspick_args_t;
typedef struct {
} pidfd_open_args_t;
typedef struct {
} clone3_args_t;
typedef struct {
} close_range_args_t;
typedef struct {
} openat2_args_t;
typedef struct {
} pidfd_getfd_args_t;
typedef struct {
} faccessat2_args_t;
typedef struct {
} process_madvise_args_t;
typedef struct {
} epoll_pwait2_args_t;
typedef struct {
} mount_setattr_args_t;
typedef struct {
} quotactl_fd_args_t;
typedef struct {
} landlock_create_ruleset_args_t;
typedef struct {
} landlock_add_rule_args_t;
typedef struct {
} landlock_restrict_self_args_t;
typedef struct {
} memfd_secret_args_t;
typedef struct {
} process_mrelease_args_t;
typedef struct {
} futex_waitv_args_t;
typedef struct {
} set_mempolicy_home_node_args_t;

typedef struct {
    int signo;
    struct siginfo siginfo;
} signal_ent_t;

#endif
