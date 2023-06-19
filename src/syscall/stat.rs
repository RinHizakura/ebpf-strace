use std::ffi::c_int;

use crate::syscall::common::*;
use chrono::{Local, TimeZone};
use libc::{
    AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_RECURSIVE, AT_REMOVEDIR, AT_SYMLINK_FOLLOW,
    AT_SYMLINK_NOFOLLOW, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFREG, S_IFSOCK, S_ISGID,
    S_ISUID, S_ISVTX,
};

#[repr(C)]
struct StatArgs {
    pathname: [u8; BUF_SIZE],
    statbuf: libc::stat,
}
unsafe impl plain::Plain for StatArgs {}

#[repr(C)]
struct FstatArgs {
    fd: c_int,
    statbuf: libc::stat,
}
unsafe impl plain::Plain for FstatArgs {}

#[repr(C)]
struct LstatArgs {
    pathname: [u8; BUF_SIZE],
    statbuf: libc::stat,
}
unsafe impl plain::Plain for LstatArgs {}

#[repr(C)]
struct NewfstatatArgs {
    pathname: [u8; BUF_SIZE],
    dirfd: c_int,
    flags: c_int,
    statbuf: libc::stat,
}
unsafe impl plain::Plain for NewfstatatArgs {}

const STAT_STMODE_DESCS: &[Desc] = &[
    desc!(S_IFREG),
    desc!(S_IFSOCK),
    desc!(S_IFIFO),
    desc!(S_IFLNK),
    desc!(S_IFDIR),
    desc!(S_IFBLK),
    desc!(S_IFCHR),
    desc!(S_ISUID),
    desc!(S_ISGID),
    desc!(S_ISVTX),
];

const AT_FLAGS_DESCS: &[Desc] = &[
    desc!(AT_SYMLINK_NOFOLLOW),
    desc!(AT_REMOVEDIR),
    desc!(AT_SYMLINK_FOLLOW),
    desc!(AT_NO_AUTOMOUNT),
    desc!(AT_EMPTY_PATH),
    desc!(AT_RECURSIVE),
];

fn format_dev(st_dev: u64) -> String {
    unsafe {
        return format!(
            "makedev(0x{:x}, 0x{:x})",
            libc::major(st_dev),
            libc::minor(st_dev)
        );
    }
}

fn format_timestamp(millis: i64) -> String {
    Local
        .timestamp_millis_opt(millis)
        .unwrap()
        .format("%FT%T%z")
        .to_string()
}

fn format_struct_stat(statbuf: &libc::stat) -> String {
    let st_dev = format_dev(statbuf.st_dev);
    let st_ino = statbuf.st_ino;
    let st_mode = format_flags(statbuf.st_mode as u64, '|', STAT_STMODE_DESCS);
    let st_nlink = statbuf.st_nlink;
    let st_uid = statbuf.st_uid;
    let st_gid = statbuf.st_gid;
    let st_blksize = statbuf.st_blksize;
    let st_blocks = statbuf.st_blocks;
    let st_size = statbuf.st_size;
    let st_atim = statbuf.st_atime;
    let st_mtim = statbuf.st_mtime;
    let st_ctim = statbuf.st_ctime;

    let adt = format_timestamp(st_atim * 1000);
    let mdt = format_timestamp(st_mtim * 1000);
    let cdt = format_timestamp(st_ctim * 1000);

    return format!(
        "{{st_dev={st_dev}, st_ino={st_ino}, st_mode={st_mode}, \
                   st_nlink={st_nlink}, st_uid={st_uid}, st_gid={st_gid}, \
                   st_blksize={st_blksize}, st_blocks={st_blocks}, st_size={st_size}, \
                   st_atim={st_atim} /* {adt} */, \
                   st_mtim={st_mtim} /* {mdt} */, \
                   st_ctim={st_ctim} /* {cdt} */}}"
    );
}

pub(super) fn handle_stat_args(args: &[u8]) -> String {
    let stat = get_args::<StatArgs>(args);

    let pathname = format_str(&stat.pathname);
    /* FIXME: Although we always take effort to parse the complete
     * struture, but we may also want an abbreviated string only. We
     * have to parse only a part of structure if the abbreviated output
     * is needed. */
    let statbuf = format_struct_stat(&stat.statbuf);
    return format!("{}, {}", pathname, statbuf);
}

pub(super) fn handle_fstat_args(args: &[u8]) -> String {
    let fstat = get_args::<FstatArgs>(args);

    let fd = fstat.fd;
    let statbuf = format_struct_stat(&fstat.statbuf);
    return format!("{}, {}", fd, statbuf);
}

pub(super) fn handle_lstat_args(args: &[u8]) -> String {
    let lstat = get_args::<LstatArgs>(args);

    let pathname = format_str(&lstat.pathname);
    let statbuf = format_struct_stat(&lstat.statbuf);
    return format!("{}, {}", pathname, statbuf);
}

pub(super) fn handle_newfstatat_args(args: &[u8]) -> String {
    let newfstatat = get_args::<NewfstatatArgs>(args);

    let dirfd = format_dirfd(newfstatat.dirfd);
    let pathname = format_str(&newfstatat.pathname);
    let statbuf = format_struct_stat(&newfstatat.statbuf);
    let flags = format_flags(newfstatat.flags as u64, '|', AT_FLAGS_DESCS);
    return format!("{}, {}, {}, {}", dirfd, pathname, statbuf, flags);
}
