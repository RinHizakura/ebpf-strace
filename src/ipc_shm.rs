use crate::common::*;

use libc::{
    key_t, shmid_ds, IPC_CREAT, IPC_EXCL, IPC_PRIVATE, SHM_EXEC, SHM_HUGETLB, SHM_NORESERVE,
    SHM_RDONLY, SHM_REMAP, SHM_RND,
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
    cmd: c_int,
    buf: shmid_ds,
}
unsafe impl plain::Plain for ShmctlArgs {}

pub(super) fn handle_shmctl_args(args: &[u8]) -> String {
    return format!("");
}
