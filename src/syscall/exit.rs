use plain::Plain;

#[repr(C)]
struct ExitGroupArgs {
    status: i32,
}
unsafe impl Plain for ExitGroupArgs {}

pub(super) fn handle_exit_group_args(args: &[u8]) {
    let size = std::mem::size_of::<ExitGroupArgs>();
    let slice = &args[0..size];
    let exit_group =
        plain::from_bytes::<ExitGroupArgs>(slice).expect("Fail to cast bytes to ExitGroupArgs");

    eprint!("({})", exit_group.status);
}
