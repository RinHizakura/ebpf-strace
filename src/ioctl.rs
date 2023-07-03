use crate::common::*;
use std::sync::{Mutex, Once};

/* FIXME: Consider different platform for these magic bits */
const _IOC_NRBITS: c_ulong = 8;
const _IOC_TYPEBITS: c_ulong = 8;
const _IOC_SIZEBITS: c_ulong = 14;
const _IOC_DIRBITS: c_long = 2;

const _IOC_NRMASK: c_ulong = (1 << _IOC_NRBITS) - 1;
const _IOC_TYPEMASK: c_ulong = (1 << _IOC_TYPEBITS) - 1;
const _IOC_SIZEMASK: c_ulong = (1 << _IOC_SIZEBITS) - 1;
const _IOC_DIRMASK: c_ulong = (1 << _IOC_DIRBITS) - 1;

const _IOC_NRSHIFT: c_ulong = 0;
const _IOC_TYPESHIFT: c_ulong = _IOC_NRSHIFT + _IOC_NRBITS;
const _IOC_SIZESHIFT: c_ulong = _IOC_TYPESHIFT + _IOC_TYPEBITS;
const _IOC_DIRSHIFT: c_ulong = _IOC_SIZESHIFT + _IOC_SIZEBITS;

const _IOC_NONE: c_ulong = 0;
const _IOC_WRITE: c_ulong = 1;
const _IOC_READ: c_ulong = 2;

const RNDGETENTCNT: c_ulong = _IOR::<c_int>(b'R', 0x00);
const RNDADDTOENTCNT: c_ulong = _IOW::<c_int>(b'R', 0x01);
const RNDGETPOOL: c_ulong = _IOR::<[c_int; 2]>(b'R', 0x02);
const RNDADDENTROPY: c_ulong = _IOW::<[c_int; 2]>(b'R', 0x03);
const RNDZAPENTCNT: c_ulong = _IO(b'R', 0x04);
const RNDCLEARPOOL: c_ulong = _IO(b'R', 0x06);
const RNDRESEEDCRNG: c_ulong = _IO(b'R', 0x07);

/* These are originated from Linux. They don't follow snake case to
 * align definition in Linux.
 * https://github.com/torvalds/linux/blob/master/rust/kernel/ioctl.rs */
#[allow(non_snake_case)]
const fn _IOC(dir: c_ulong, ty: u8, nr: c_ulong, size: usize) -> c_ulong {
    (dir << _IOC_DIRSHIFT)
        | ((ty as c_ulong) << _IOC_TYPESHIFT)
        | (nr << _IOC_NRSHIFT)
        | ((size as c_ulong) << _IOC_SIZESHIFT)
}

#[allow(non_snake_case)]
const fn _IO(ty: u8, nr: c_ulong) -> c_ulong {
    _IOC(_IOC_NONE, ty, nr, 0)
}

#[allow(non_snake_case)]
const fn _IOR<T>(ty: u8, nr: c_ulong) -> c_ulong {
    _IOC(_IOC_READ, ty, nr, core::mem::size_of::<T>())
}

#[allow(non_snake_case)]
const fn _IOW<T>(ty: u8, nr: c_ulong) -> c_ulong {
    _IOC(_IOC_WRITE, ty, nr, core::mem::size_of::<T>())
}

#[allow(non_snake_case)]
fn _IOC_TYPE(nr: c_ulong) -> u8 {
    ((nr >> _IOC_TYPESHIFT) & _IOC_TYPEMASK) as u8
}

#[repr(C)]
struct IoctlArgs {
    fd: c_int,
    request: c_ulong,
    arg: c_ulong,
}
unsafe impl plain::Plain for IoctlArgs {}

static INIT_IOCTL_ENTS: Once = Once::new();
/* Note: this is not created as const because we would like to
 * sort it for better search time. */
lazy_static! {
    pub static ref IOCTL_ENTS: Mutex<Vec<Desc>> = Mutex::new(vec![
        desc!(RNDGETENTCNT),
        desc!(RNDADDTOENTCNT),
        desc!(RNDGETPOOL),
        desc!(RNDADDENTROPY),
        desc!(RNDZAPENTCNT),
        desc!(RNDCLEARPOOL),
        desc!(RNDRESEEDCRNG),
    ]);
}

fn ioctl_lookup(code: c_ulong) -> String {
    let mut ioctl_ents_raw = IOCTL_ENTS.lock().unwrap();

    INIT_IOCTL_ENTS.call_once(|| {
        ioctl_ents_raw.sort_by_key(|desc| desc.val);
    });

    format_value_sorted(code, "??", &ioctl_ents_raw)
}

fn random_ioctl(code: c_ulong, arg: c_ulong) -> Option<String> {
    let arg_int = (arg & 0xFFFF_FFFF) as u32 as i32;
    match code {
        RNDGETENTCNT | RNDADDTOENTCNT => Some(format!("{}", arg_int)),
        RNDGETPOOL | RNDADDENTROPY | RNDZAPENTCNT | RNDCLEARPOOL | RNDRESEEDCRNG => None, // TODO: support decoding of other request code
        _ => unreachable!(),
    }
}

fn ioctl_decode(code: c_ulong, arg: c_ulong) -> Option<String> {
    let ioc_type = _IOC_TYPE(code);
    let result = match ioc_type {
        b'R' => random_ioctl(code, arg),
        _ => None, // TODO: support decoding for other ioctl
    };

    result
}

pub(super) fn handle_ioctl_args(args: &[u8]) -> String {
    let ioctl = get_args::<IoctlArgs>(args);

    let code = ioctl_lookup(ioctl.request);
    let arg = ioctl.arg;
    let decode = ioctl_decode(ioctl.request, arg);

    let (comma, decode) = if decode.is_none() {
        ("".to_string(), "".to_string())
    } else {
        (", ".to_string(), decode.unwrap())
    };

    return format!("{}, {}{}{}", ioctl.fd, code, comma, decode);
}
