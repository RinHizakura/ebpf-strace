use crate::common::*;

#[repr(C)]
struct PrctlArgs {
    option: c_int,
    arg2: c_ulong,
}
unsafe impl plain::Plain for PrctlArgs {}

pub(super) fn handle_prctl_args(args: &[u8]) -> String {
    let prctl = get_args::<PrctlArgs>(args);
    format!("{}, 0x{:x}", prctl.option, prctl.arg2)
}
