use std::ffi::c_int;

use libc::{
    MAP_32BIT, MAP_ANONYMOUS, MAP_DENYWRITE, MAP_EXECUTABLE, MAP_FIXED, MAP_FIXED_NOREPLACE,
    MAP_GROWSDOWN, MAP_HUGETLB, MAP_LOCKED, MAP_NONBLOCK, MAP_NORESERVE, MAP_POPULATE, MAP_PRIVATE,
    MAP_SHARED, MAP_SHARED_VALIDATE, MAP_STACK, MAP_SYNC, PROT_EXEC, PROT_GROWSDOWN, PROT_GROWSUP,
    PROT_NONE, PROT_READ, PROT_WRITE,
};

use crate::common::*;

const MMAP_PROT_DESCS: &[Desc] = &[
    desc!(PROT_NONE),
    desc!(PROT_READ),
    desc!(PROT_WRITE),
    desc!(PROT_EXEC),
    desc!(PROT_GROWSDOWN),
    desc!(PROT_GROWSUP),
];

const MMAP_FLAGS_DESCS: &[Desc] = &[
    desc!(MAP_SHARED),
    desc!(MAP_PRIVATE),
    desc!(MAP_SHARED_VALIDATE),
    desc!(MAP_FIXED),
    desc!(MAP_ANONYMOUS),
    desc!(MAP_32BIT),
    desc!(MAP_NORESERVE),
    desc!(MAP_POPULATE),
    desc!(MAP_NONBLOCK),
    desc!(MAP_GROWSDOWN),
    desc!(MAP_DENYWRITE),
    desc!(MAP_EXECUTABLE),
    desc!(MAP_LOCKED),
    desc!(MAP_STACK),
    desc!(MAP_HUGETLB),
    desc!(MAP_SYNC),
    desc!(MAP_FIXED_NOREPLACE),
];

#[repr(C)]
struct MmapArgs {
    addr: usize,
    length: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: libc::off_t,
}
unsafe impl plain::Plain for MmapArgs {}

pub(super) fn handle_mmap_args(args: &[u8]) -> String {
    let mmap = get_args::<MmapArgs>(args);

    let addr = format_addr(mmap.addr);
    let prot = format_flags(mmap.prot as u64, '|', &MMAP_PROT_DESCS);
    let flags = format_flags(mmap.flags as u64, '|', &MMAP_FLAGS_DESCS);
    return format!(
        "{}, {}, {}, {}, {}, 0x{:x}",
        addr, mmap.length, prot, flags, mmap.fd, mmap.offset
    );
}

#[repr(C)]
struct MprotectArgs {
    addr: usize,
    length: usize,
    prot: c_int,
}
unsafe impl plain::Plain for MprotectArgs {}

pub(super) fn handle_mprotect_args(args: &[u8]) -> String {
    let mprotect = get_args::<MprotectArgs>(args);

    let addr = format_addr(mprotect.addr);
    let prot = format_flags(mprotect.prot as u64, '|', &MMAP_PROT_DESCS);
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
