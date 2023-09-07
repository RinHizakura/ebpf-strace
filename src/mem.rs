use std::ffi::{c_int, c_uchar};

use libc::{
    sysconf, MAP_32BIT, MAP_ANONYMOUS, MAP_DENYWRITE, MAP_EXECUTABLE, MAP_FILE, MAP_FIXED,
    MAP_FIXED_NOREPLACE, MAP_GROWSDOWN, MAP_HUGETLB, MAP_LOCKED, MAP_NONBLOCK, MAP_NORESERVE,
    MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, MAP_SHARED_VALIDATE, MAP_STACK, MAP_SYNC,
    MREMAP_DONTUNMAP, MREMAP_FIXED, MREMAP_MAYMOVE, MS_ASYNC, MS_INVALIDATE, MS_SYNC, PROT_EXEC,
    PROT_GROWSDOWN, PROT_GROWSUP, PROT_NONE, PROT_READ, PROT_WRITE, _SC_PAGE_SIZE,
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
    desc!(MAP_FILE),
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
    let prot = format_flags(mmap.prot as u64, '|', &MMAP_PROT_DESCS, Format::Hex);
    let flags = format_flags(mmap.flags as u64, '|', &MMAP_FLAGS_DESCS, Format::Hex);
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
    let prot = format_flags(mprotect.prot as u64, '|', &MMAP_PROT_DESCS, Format::Hex);
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

#[repr(C)]
struct MremapArgs {
    old_address: usize,
    new_address: usize,
    old_size: usize,
    new_size: usize,
    flags: c_int,
}
unsafe impl plain::Plain for MremapArgs {}

const MREMAP_FLAGS_DESCS: &[Desc] = &[
    desc!(MREMAP_MAYMOVE),
    desc!(MREMAP_FIXED),
    desc!(MREMAP_DONTUNMAP),
];

pub(super) fn handle_mremap_args(args: &[u8]) -> String {
    let mremap = get_args::<MremapArgs>(args);

    let old_address = format_addr(mremap.old_address);
    let new_address = mremap.new_address;
    let flags = mremap.flags;

    let extra_new_address =
        if flags & (MREMAP_MAYMOVE | MREMAP_FIXED) == (MREMAP_MAYMOVE | MREMAP_FIXED) {
            format!(", {}", format_addr(new_address))
        } else {
            EMPTY_STR.to_owned()
        };

    let flags = format_flags(flags as u64, '|', &MREMAP_FLAGS_DESCS, Format::Hex);

    return format!(
        "{}, {}, {}, {}{}",
        old_address, mremap.old_size, mremap.new_size, flags, extra_new_address,
    );
}

#[repr(C)]
struct MsyncArgs {
    addr: usize,
    length: usize,
    flags: c_int,
}
unsafe impl plain::Plain for MsyncArgs {}

const MSYNC_FLAGS_DESCS: &[Desc] = &[desc!(MS_SYNC), desc!(MS_ASYNC), desc!(MS_INVALIDATE)];

pub(super) fn handle_msync_args(args: &[u8]) -> String {
    let msync = get_args::<MsyncArgs>(args);

    let addr = format_addr(msync.addr);
    let length = msync.length;
    let flags = format_flags(msync.flags as u64, '|', &MSYNC_FLAGS_DESCS, Format::Hex);

    return format!("{}, {}, {}", addr, length, flags);
}

#[repr(C)]
struct MincoreArgs {
    addr: usize,
    length: usize,
    vec: [c_uchar; ARR_ENT_SIZE],
}
unsafe impl plain::Plain for MincoreArgs {}

fn format_vec_entry(c: &c_uchar) -> String {
    return format!("{}", c);
}

pub(super) fn handle_mincore_args(args: &[u8]) -> String {
    let mincore = get_args::<MincoreArgs>(args);

    let addr = format_addr(mincore.addr);
    let length = mincore.length;

    let pagesize = unsafe { sysconf(_SC_PAGE_SIZE) as usize };
    let page_mask = pagesize - 1;
    let page_shift = pagesize.trailing_zeros();
    let vec_size = (length + page_mask) >> page_shift;
    let vec = format_arr(&mincore.vec, vec_size, format_vec_entry);

    return format!("{}, {}, {}", addr, length, vec);
}
