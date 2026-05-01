use crate::common::*;
use libc::{
    PR_GET_DUMPABLE, PR_GET_KEEPCAPS, PR_GET_NAME, PR_GET_NO_NEW_PRIVS, PR_GET_PDEATHSIG,
    PR_SET_DUMPABLE, PR_SET_KEEPCAPS, PR_SET_NAME, PR_SET_NO_NEW_PRIVS, PR_SET_PDEATHSIG,
};

const PRCTL_OPTION_DESCS: &[Desc] = &[
    desc!(PR_GET_DUMPABLE),
    desc!(PR_SET_DUMPABLE),
    desc!(PR_GET_KEEPCAPS),
    desc!(PR_SET_KEEPCAPS),
    desc!(PR_GET_NAME),
    desc!(PR_SET_NAME),
    desc!(PR_GET_NO_NEW_PRIVS),
    desc!(PR_SET_NO_NEW_PRIVS),
    desc!(PR_GET_PDEATHSIG),
    desc!(PR_SET_PDEATHSIG),
];

#[repr(C)]
struct PrctlArgs {
    option: c_int,
    arg2: c_ulong,
}
unsafe impl plain::Plain for PrctlArgs {}

pub(super) fn handle_prctl_ret_aux(args: &[u8], ret: i64) -> String {
    let prctl = get_args::<PrctlArgs>(args);
    if prctl.option == PR_GET_DUMPABLE {
        return match ret {
            0 => " (SUID_DUMP_DISABLE)".to_owned(),
            1 => " (SUID_DUMP_USER)".to_owned(),
            2 => " (SUID_DUMP_ROOT)".to_owned(),
            _ => String::new(),
        };
    }
    String::new()
}

pub(super) fn handle_prctl_args(args: &[u8]) -> String {
    let prctl = get_args::<PrctlArgs>(args);
    let opt = format_value(
        prctl.option as u64,
        Some("PR_???"),
        PRCTL_OPTION_DESCS,
        Format::Hex,
    );
    match prctl.option {
        PR_GET_DUMPABLE | PR_GET_KEEPCAPS | PR_GET_NAME | PR_GET_NO_NEW_PRIVS
        | PR_GET_PDEATHSIG => format!("{}", opt),
        _ => format!("{}, 0x{:x}", opt, prctl.arg2),
    }
}
