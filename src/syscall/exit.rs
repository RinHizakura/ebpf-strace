use crate::syscall::get_args;
use plain::Plain;

#[repr(C)]
struct ExitGroupArgs {
    status: i32,
}
unsafe impl Plain for ExitGroupArgs {}

pub(super) fn handle_exit_group_args(args: &[u8]) {
    let exit_group = get_args::<ExitGroupArgs>(args);

    eprint!("({})", exit_group.status);
}
