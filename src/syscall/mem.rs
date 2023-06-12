use libc::{
    MAP_32BIT, MAP_ANONYMOUS, MAP_DENYWRITE, MAP_EXECUTABLE, MAP_FIXED, MAP_FIXED_NOREPLACE,
    MAP_GROWSDOWN, MAP_HUGETLB, MAP_LOCKED, MAP_NONBLOCK, MAP_NORESERVE, MAP_POPULATE, MAP_PRIVATE,
    MAP_SHARED, MAP_SHARED_VALIDATE, MAP_STACK, MAP_SYNC, PROT_EXEC, PROT_GROWSDOWN, PROT_GROWSUP,
    PROT_NONE, PROT_READ, PROT_WRITE,
};

use crate::syscall::common::*;

const MMAP_PROT_DESCS: &[FlagDesc] = &[
    flag_desc!(PROT_NONE),
    flag_desc!(PROT_READ),
    flag_desc!(PROT_WRITE),
    flag_desc!(PROT_EXEC),
    flag_desc!(PROT_GROWSDOWN),
    flag_desc!(PROT_GROWSUP),
];

const MMAP_FLAGS_DESCS: &[FlagDesc] = &[
    flag_desc!(MAP_SHARED),
    flag_desc!(MAP_PRIVATE),
    flag_desc!(MAP_SHARED_VALIDATE),
    flag_desc!(MAP_FIXED),
    flag_desc!(MAP_ANONYMOUS),
    flag_desc!(MAP_32BIT),
    flag_desc!(MAP_NORESERVE),
    flag_desc!(MAP_POPULATE),
    flag_desc!(MAP_NONBLOCK),
    flag_desc!(MAP_GROWSDOWN),
    flag_desc!(MAP_DENYWRITE),
    flag_desc!(MAP_EXECUTABLE),
    flag_desc!(MAP_LOCKED),
    flag_desc!(MAP_STACK),
    flag_desc!(MAP_HUGETLB),
    flag_desc!(MAP_SYNC),
    flag_desc!(MAP_FIXED_NOREPLACE),
];

#[repr(C)]
struct MmapArgs {
    addr: usize,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: libc::off_t,
}
unsafe impl plain::Plain for MmapArgs {}

pub(super) fn handle_mmap_args(args: &[u8]) -> String {
    let mmap = get_args::<MmapArgs>(args);

    let addr = format_addr(mmap.addr);
    let prot = format_flags(mmap.prot as u32, '|', &MMAP_PROT_DESCS);
    let flags = format_flags(mmap.flags as u32, '|', &MMAP_FLAGS_DESCS);
    return format!(
        "{}, {}, {}, {}, {}, 0x{:x}",
        addr, mmap.length, prot, flags, mmap.fd, mmap.offset
    );
}

#[repr(C)]
struct MprotectArgs {
    addr: usize,
    length: usize,
    prot: i32,
}
unsafe impl plain::Plain for MprotectArgs {}

pub(super) fn handle_mprotect_args(args: &[u8]) -> String {
    let mprotect = get_args::<MprotectArgs>(args);

    let addr = format_addr(mprotect.addr);
    let prot = format_flags(mprotect.prot as u32, '|', &MMAP_PROT_DESCS);
    return format!("{}, {}, {}", addr, mprotect.length, prot);
}

#[repr(C)]
struct MunmapArgs {
    addr: usize,
    length: usize,
}
unsafe impl plain::Plain for MunmapArgs {}

pub(super) fn handle_munmap_args(args: &[u8]) -> String {
    let munmap = get_args::<MunmapArgs>(args);

    let addr = format_addr(munmap.addr);
    return format!("{}, {}", addr, munmap.length);
}

#[repr(C)]
struct BrkArgs {
    addr: usize,
}
unsafe impl plain::Plain for BrkArgs {}

pub(super) fn handle_brk_args(args: &[u8]) -> String {
    let brk = get_args::<BrkArgs>(args);

    let addr = format_addr(brk.addr);
    return format!("{}", addr);
}