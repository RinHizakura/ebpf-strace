use crate::common::*;

use libc::{
    ipc_perm, key_t, shmid_ds, IPC_CREAT, IPC_EXCL, IPC_INFO, IPC_PRIVATE, IPC_RMID, IPC_SET,
    IPC_STAT, SHM_EXEC, SHM_HUGETLB, SHM_LOCK, SHM_NORESERVE, SHM_RDONLY, SHM_REMAP, SHM_RND,
    SHM_UNLOCK,
};

#[repr(C)]
struct ShmgetArgs {
    key: key_t,
    size: usize,
    shmflg: c_int,
}
unsafe impl plain::Plain for ShmgetArgs {}

const SHM_HUGE_SHIFT: usize = 26;
const SHM_HUGE_MASK: usize = 0x3f;

const SHMGET_KEY_DESCS: &[Desc] = &[desc!(IPC_PRIVATE)];

const SHMGET_FLAGS_DESCS: &[Desc] = &[
    desc!(IPC_CREAT),
    desc!(IPC_EXCL),
    desc!(SHM_HUGETLB),
    desc!(SHM_NORESERVE),
];

pub(super) fn handle_shmget_args(args: &[u8]) -> String {
    let shmget = get_args::<ShmgetArgs>(args);

    let key = format_value(
        shmget.key as u32 as u64,
        None,
        &SHMGET_KEY_DESCS,
        Format::Hex,
    );
    let shmflg = shmget.shmflg as u32 as u64;

    let mask = (SHM_HUGE_MASK as u64) << SHM_HUGE_SHIFT;
    let flags = shmflg & !0o777 & !mask;
    let pflg = shmflg & 0o777;

    let mut flags_str;
    if flags != 0 {
        flags_str = format_flags(flags, '|', &SHMGET_FLAGS_DESCS, Format::Hex);
        flags_str.push('|');
    } else {
        flags_str = EMPTY_STR.to_owned();
    }

    /* FIXME: Consider the hugetlb_value of shmflg. */
    return format!("{}, {}, {}0{:o}", key, shmget.size, flags_str, pflg);
}

#[repr(C)]
struct ShmatArgs {
    shmid: c_int,
    shmaddr: usize,
    shmflg: c_int,
}
unsafe impl plain::Plain for ShmatArgs {}

const SHMAT_FLAGS_DESCS: &[Desc] = &[
    desc!(SHM_RDONLY),
    desc!(SHM_RND),
    desc!(SHM_REMAP),
    desc!(SHM_EXEC),
];

pub(super) fn handle_shmat_args(args: &[u8]) -> String {
    let shmat = get_args::<ShmatArgs>(args);
    let shmid = shmat.shmid;
    let shmaddr = format_addr(shmat.shmaddr);
    let shmflg = format_flags(
        shmat.shmflg as u32 as u64,
        '|',
        &SHMAT_FLAGS_DESCS,
        Format::Hex,
    );

    return format!("{}, {}, {}", shmid, shmaddr, shmflg);
}

#[repr(C)]
struct ShmctlArgs {
    shmid: c_int,
    cmd: c_int,
    buf: shmid_ds,
    buf_addr: usize,
}
unsafe impl plain::Plain for ShmctlArgs {}

/* TODO: Find these under rust libc library? */
const SHM_STAT: c_int = 13;
const SHM_INFO: c_int = 14;
const SHM_STAT_ANY: c_int = 15;

const SHMCTL_CMD_DESCS: &[Desc] = &[
    desc!(IPC_RMID),
    desc!(IPC_SET),
    desc!(IPC_STAT),
    desc!(IPC_INFO),
    desc!(SHM_LOCK),
    desc!(SHM_UNLOCK),
    desc!(SHM_STAT),
    desc!(SHM_INFO),
    desc!(SHM_STAT_ANY),
];

fn format_ipc_perm(ipc_perm: &ipc_perm) -> String {
    let uid = ipc_perm.uid;
    let gid = ipc_perm.gid;
    let mode = format!("0{:o}", ipc_perm.mode);
    let key = ipc_perm.__key;
    let cuid = ipc_perm.cuid;
    let cgid = ipc_perm.cgid;

    return format!(
        "{{uid={uid}, gid={gid}, mode={mode}, key={key}, \
                   cuid={cuid}, cgid={cgid}}}"
    );
}

fn format_shmid_ds(shmid_ds: &shmid_ds) -> String {
    let shm_perm = format_ipc_perm(&shmid_ds.shm_perm);
    let shm_segsz = shmid_ds.shm_segsz;
    let shm_cpid = shmid_ds.shm_cpid;
    let shm_lpid = shmid_ds.shm_lpid;
    let shm_nattch = shmid_ds.shm_nattch;
    let shm_atime = shmid_ds.shm_atime;
    let shm_dtime = shmid_ds.shm_dtime;
    let shm_ctime = shmid_ds.shm_ctime;

    return format!(
        "{{shm_perm={shm_perm}, shm_segsz={shm_segsz}, shm_cpid={shm_cpid}, \
                   shm_lpid={shm_lpid}, shm_nattch={shm_nattch}, \
                   shm_atime={shm_atime}, shm_dtime={shm_dtime}, shm_ctime={shm_ctime}}}"
    );
}

pub(super) fn handle_shmctl_args(args: &[u8]) -> String {
    let shmctl = get_args::<ShmctlArgs>(args);

    let cmd = format_value(
        shmctl.cmd as u32 as u64,
        Some("SHM_???"),
        &SHMCTL_CMD_DESCS,
        Format::Hex,
    );
    let buf;
    if shmctl.buf_addr != 0 {
        buf = match shmctl.cmd {
            IPC_SET => todo!(),
            IPC_STAT => format_shmid_ds(&shmctl.buf),
            SHM_STAT => todo!(),
            SHM_STAT_ANY => todo!(),
            IPC_INFO => todo!(),
            SHM_INFO => todo!(),
            _ => format_addr(shmctl.buf_addr),
        };
    } else {
        buf = NULL_STR.to_owned();
    }

    return format!("{}, {}, {}", shmctl.shmid, cmd, buf);
}
