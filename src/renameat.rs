use crate::common::*;

#[repr(C)]
struct RenameArgs {
    old_path: [u8; BUF_SIZE],
    new_path: [u8; BUF_SIZE],
}
unsafe impl plain::Plain for RenameArgs {}

pub(super) fn handle_rename_args(args: &[u8]) -> String {
    let r = get_args::<RenameArgs>(args);
    format!("{}, {}", format_str(&r.old_path), format_str(&r.new_path))
}

#[repr(C)]
struct RenameatArgs {
    olddirfd: c_int,
    old_path: [u8; BUF_SIZE],
    newdirfd: c_int,
    new_path: [u8; BUF_SIZE],
}
unsafe impl plain::Plain for RenameatArgs {}

pub(super) fn handle_renameat_args(args: &[u8]) -> String {
    let r = get_args::<RenameatArgs>(args);
    format!(
        "{}, {}, {}, {}",
        format_dirfd(r.olddirfd),
        format_str(&r.old_path),
        format_dirfd(r.newdirfd),
        format_str(&r.new_path)
    )
}
