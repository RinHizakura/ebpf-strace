use crate::syscall::common::*;

#[repr(C)]
struct ExitGroupArgs {
    status: i32,
}
unsafe impl plain::Plain for ExitGroupArgs {}

pub(super) fn handle_exit_group_args(args: &[u8]) {
    let exit_group = get_args::<ExitGroupArgs>(args);

    eprint!("({})", exit_group.status);
}
