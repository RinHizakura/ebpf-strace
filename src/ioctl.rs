use crate::common::*;

#[repr(C)]
struct IoctlArgs {
    fd: c_int,
    request: c_ulong,
    arg: c_ulong,
}
unsafe impl plain::Plain for IoctlArgs {}

/* FIXME: Consider different platform for these magic bits */
const IOC_NRBITS: c_ulong = 8;
const IOC_TYPEBITS: c_ulong = 8;

const IOC_TYPEMASK: c_ulong = (1 << IOC_TYPEBITS) - 1;

const IOC_NRSHIFT: c_ulong = 0;
const IOC_TYPESHIFT: c_ulong = IOC_NRSHIFT + IOC_NRBITS;

macro_rules! ioc_type {
    ( $nr:expr ) => {
        ((($nr) >> IOC_TYPESHIFT) & IOC_TYPEMASK) as u8
    };
}

fn random_ioctl(code: c_ulong, arg: c_ulong) -> String {
    // FIXME: miss in libc?
    let RNDGETENTCNT: c_ulong = 2147766784;
    match code {
        RNDGETENTCNT => format!("{}", arg & 0xFFFF_FFFF),
        _ => todo!(),
    }
}

fn ioctl_decode(code: c_ulong, arg: c_ulong) -> String {
    let ioc_type = ioc_type!(code);
    match ioc_type {
        b'R' => random_ioctl(code, arg),
        _ => "".to_string(),
    }
}

pub(super) fn handle_ioctl_args(args: &[u8]) -> String {
    let ioctl = get_args::<IoctlArgs>(args);

    let code = ioctl.request;
    let arg = ioctl.arg;
    let decode = ioctl_decode(code, arg);

    return format!("{}, {}, {}", ioctl.fd, code, decode);
}
