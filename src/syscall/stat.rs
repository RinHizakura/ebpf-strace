use libc::{
    S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFREG, S_IFSOCK, S_ISGID, S_ISUID, S_ISVTX,
};

use crate::syscall::common::*;

#[repr(C)]
struct StatArgs {
    pathname: [u8; BUF_SIZE],
    statbuf: libc::stat,
}
unsafe impl plain::Plain for StatArgs {}

const STAT_FLAGS_DESCS: &[FlagDesc] = &[
    flag_desc!(S_IFREG),
    flag_desc!(S_IFSOCK),
    flag_desc!(S_IFIFO),
    flag_desc!(S_IFLNK),
    flag_desc!(S_IFDIR),
    flag_desc!(S_IFBLK),
    flag_desc!(S_IFCHR),
    flag_desc!(S_ISUID),
    flag_desc!(S_ISGID),
    flag_desc!(S_ISVTX),
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

fn format_struct_stat(statbuf: &libc::stat) -> String {
    /* TODO */
    let st_dev = format_dev(statbuf.st_dev);
    let st_ino = statbuf.st_ino;
    let st_mode = format_flags(statbuf.st_mode, '|', STAT_FLAGS_DESCS);
    //let st_mode = statbuf.st_mode;
    let st_nlink = statbuf.st_nlink;
    let st_uid = statbuf.st_uid;
    let st_gid = statbuf.st_gid;
    let st_blksize = statbuf.st_blksize;
    let st_blocks = statbuf.st_blocks;
    let st_size = statbuf.st_size;
    let st_atim = statbuf.st_atime;
    let st_mtim = statbuf.st_mtime;
    let st_ctim = statbuf.st_ctime;

    return format!("{{st_dev={st_dev}, st_ino={st_ino}, st_mode={st_mode}, st_nlink={st_nlink}, st_uid={st_uid}, st_gid={st_gid}, st_blksize={st_blksize}, st_blocks={st_blocks}, st_size={st_size}, st_atim={st_atim}, st_mtim={st_mtim}, st_ctim={st_ctim}}}");
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
