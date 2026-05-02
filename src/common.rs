use libc::timeval;

use crate::arch::*;
use crate::utils::*;
pub use std::ffi::{c_int, c_long, c_ulong};

pub const ARR_ENT_SIZE: usize = 31;
pub const BUF_SIZE: usize = 128;
pub const NULL_STR: &'static str = "NULL";
pub const EMPTY_STR: &'static str = "";

#[macro_export]
macro_rules! desc {
    ( $flag:expr ) => {
        Desc {
            val: $flag as u64,
            name: stringify!($flag),
        }
    };
}

#[macro_export]
macro_rules! format_or_null {
    ( $formatter: ident, $cond: expr, $($args: expr),+) => {
        if $cond {
            $formatter($($args,)+)
        } else {
            NULL_STR.to_owned()
        }
    }
}

pub(super) fn format_buf(buf: &[u8], count: usize) -> String {
    let len = buf.len();
    let extra = if count > len { "..." } else { EMPTY_STR };
    let count = count.min(len);

    let mut s = String::new();
    s.push('"');
    for byte in &buf[0..count] {
        let c = *byte;
        match c as char {
            '\n' => s.push_str("\\n"),
            '\t' => s.push_str("\\t"),
            '\r' => s.push_str("\\r"),
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            c if c.is_ascii_graphic() || c == ' ' => s.push(c),
            _ => s.push_str(&format!("\\x{:02x}", byte)),
        }
    }
    s.push_str(&format!("\"{}", extra));

    s
}

pub(super) fn format_buf_hex(buf: &[u8], count: usize) -> String {
    let len = buf.len();
    let extra = if count > len { "..." } else { EMPTY_STR };
    let count = count.min(len);

    let mut s = String::new();
    s.push('"');
    for byte in &buf[0..count] {
        let c = *byte;
        match c {
            b'\\' => s.push_str("\\\\"),
            b'"' => s.push_str("\\\""),
            _ => s.push_str(&format!("\\x{:02x}", c)),
        }
    }
    s.push_str(&format!("\"{}", extra));
    s
}

pub(super) fn format_str(buf: &[u8; BUF_SIZE]) -> String {
    let len = buf.len();
    let mut idx = 0;

    let mut s = String::new();
    s.push('"');
    while idx < len {
        let c = buf[idx];
        if c == 0 {
            break;
        } else {
            s.push(c as char);
        }

        idx += 1;
    }

    /* If we can't find the ended zero in the buffer, this is an incomplete string. */
    let extra = if idx >= len { "..." } else { EMPTY_STR };
    s.push_str(&format!("\"{}", extra));

    s
}

pub struct Desc {
    pub val: u64,
    pub name: &'static str,
}

pub enum Format {
    Octal,
    Hex,
}

pub(super) fn format_flags(mut flags: u64, sep: char, descs: &[Desc], format: Format) -> String {
    let mut output_str: String = String::new();

    let mut zero_flag_str = "0";
    for f in descs {
        if f.val == 0 {
            zero_flag_str = f.name;
            continue;
        }

        if (flags & f.val) == f.val {
            output_str.push_str(f.name);
            output_str.push(sep);
            flags &= !f.val;
        }
    }

    if flags != 0 {
        output_str.push_str(&match format {
            Format::Hex => format!("0x{:x}", flags),
            Format::Octal => format!("0{:o}", flags),
        });
    } else {
        if !output_str.is_empty() {
            /* Pop out the last seperator */
            output_str.pop();
        } else {
            output_str.push_str(zero_flag_str);
        }
    }

    output_str
}

pub(super) fn format_value(
    val: u64,
    default: Option<&str>,
    descs: &[Desc],
    format: Format,
) -> String {
    let result = descs.iter().find(|desc| desc.val == val);
    if let Some(desc) = result {
        return desc.name.to_owned();
    }

    /* Print the value directly if no hit */
    let mut s = match format {
        Format::Hex => format!("0x{:x}", val),
        Format::Octal => format!("0{:o}", val),
    };

    if let Some(def) = default {
        s.push_str(&format!(" /* {} */", def));
    }

    s
}

/* Note: the input descs should be sorted, otherwise the results
 * are undefined. */
pub(super) fn format_value_sorted(val: u64, default: &str, descs: &[Desc]) -> String {
    let result = descs.binary_search_by_key(&val, |desc| desc.val);
    if let Ok(idx) = result {
        return descs[idx].name.to_owned();
    }

    return format!("0x{:x} /* {} */", val, default);
}

pub(super) fn format_dirfd(fd: c_int) -> String {
    if fd == libc::AT_FDCWD {
        "AT_FDCWD".to_string()
    } else {
        fd.to_string()
    }
}

/* FIXME: We should make the implementation prettier if there's the way :( */
pub(super) fn format_arr<T, F>(arr: &[T], arr_size: usize, formatter: F) -> String
where
    F: Fn(&T) -> String,
{
    let mut list_str = String::new();

    list_str.push('[');

    /* Note that arr_size is not equal to arr.len(). */
    let printed_argc = (arr_size as usize).min(ARR_ENT_SIZE);
    for idx in 0..printed_argc {
        if idx > 0 {
            list_str.push_str(", ");
        }
        list_str.push_str(&formatter(&arr[idx]));
    }

    if arr_size > ARR_ENT_SIZE {
        if printed_argc > 0 {
            list_str.push_str(", ");
        }
        list_str.push_str("...");
    }

    list_str.push(']');

    list_str
}

pub(super) fn format_addr(addr: usize) -> String {
    if addr == 0 {
        NULL_STR.to_owned()
    } else {
        format!("0x{:x}", addr)
    }
}

pub(super) fn format_signum(signum: c_int) -> String {
    let signum = signum as usize;
    if signum > 0 {
        if signum < SIGRTMIN {
            return SIGNAL_NAME[signum].to_string();
        } else if signum >= SIGRTMIN && signum <= SIGRTMAX {
            return format!("SIGRT_{}", signum - SIGRTMIN);
        }
    }

    return signum.to_string();
}

pub(super) fn format_sigset(sig_mask: &KernlSigset) -> String {
    let mut s = String::new();
    s.push('[');

    let bitsize = sig_mask.sig.len() as c_int * LONG_BIT;

    let mut i = next_set_bit(&sig_mask.sig, 0, bitsize);
    while i >= 0 {
        i += 1;
        if i < SIGRTMIN as c_int {
            s.push_str(&SIGNAL_NAME[i as usize][3..]);
        } else if i >= SIGRTMIN as c_int && i <= SIGRTMAX as c_int {
            s.push_str(&format!("RT_{}", i - SIGRTMIN as c_int));
        }
        s.push(' ');
        i = next_set_bit(&sig_mask.sig, i, bitsize);
    }
    /* It means we don't just put the first '[' in the string. Pop
     * the last space. */
    if s.len() != 1 {
        s.pop();
    }
    s.push(']');
    return s;
}

pub(super) fn format_timeval(timeval: &timeval) -> String {
    return format!("{{tv_sec={}, tv_usec={}}}", timeval.tv_sec, timeval.tv_usec);
}

pub(super) fn format_errno(errno: i32) -> String {
    let name = match errno {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
        6 => "ENXIO",
        7 => "E2BIG",
        8 => "ENOEXEC",
        9 => "EBADF",
        10 => "ECHILD",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        15 => "ENOTBLK",
        16 => "EBUSY",
        17 => "EEXIST",
        18 => "EXDEV",
        19 => "ENODEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        25 => "ENOTTY",
        26 => "ETXTBSY",
        27 => "EFBIG",
        28 => "ENOSPC",
        29 => "ESPIPE",
        30 => "EROFS",
        31 => "EMLINK",
        32 => "EPIPE",
        33 => "EDOM",
        34 => "ERANGE",
        35 => "EDEADLK",
        36 => "ENAMETOOLONG",
        37 => "ENOLCK",
        38 => "ENOSYS",
        39 => "ENOTEMPTY",
        40 => "ELOOP",
        42 => "ENOMSG",
        43 => "EIDRM",
        44 => "ECHRNG",
        45 => "EL2NSYNC",
        46 => "EL3HLT",
        47 => "EL3RST",
        48 => "ELNRNG",
        49 => "EUNATCH",
        50 => "ENOCSI",
        51 => "EL2HLT",
        52 => "EBADE",
        53 => "EBADR",
        54 => "EXFULL",
        55 => "ENOANO",
        56 => "EBADRQC",
        57 => "EBADSLT",
        59 => "EBFONT",
        60 => "ENOSTR",
        61 => "ENODATA",
        62 => "ETIME",
        63 => "ENOSR",
        64 => "ENONET",
        65 => "ENOPKG",
        66 => "EREMOTE",
        67 => "ENOLINK",
        68 => "EADV",
        69 => "ESRMNT",
        70 => "ECOMM",
        71 => "EPROTO",
        72 => "EMULTIHOP",
        73 => "EDOTDOT",
        74 => "EBADMSG",
        75 => "EOVERFLOW",
        76 => "ENOTUNIQ",
        77 => "EBADFD",
        78 => "EREMCHG",
        79 => "ELIBACC",
        80 => "ELIBBAD",
        81 => "ELIBSCN",
        82 => "ELIBMAX",
        83 => "ELIBEXEC",
        84 => "EILSEQ",
        85 => "ERESTART",
        86 => "ESTRPIPE",
        87 => "EUSERS",
        88 => "ENOTSOCK",
        89 => "EDESTADDRREQ",
        90 => "EMSGSIZE",
        91 => "EPROTOTYPE",
        92 => "ENOPROTOOPT",
        93 => "EPROTONOSUPPORT",
        94 => "ESOCKTNOSUPPORT",
        95 => "EOPNOTSUPP",
        96 => "EPFNOSUPPORT",
        97 => "EAFNOSUPPORT",
        98 => "EADDRINUSE",
        99 => "EADDRNOTAVAIL",
        100 => "ENETDOWN",
        101 => "ENETUNREACH",
        102 => "ENETRESET",
        103 => "ECONNABORTED",
        104 => "ECONNRESET",
        105 => "ENOBUFS",
        106 => "EISCONN",
        107 => "ENOTCONN",
        108 => "ESHUTDOWN",
        109 => "ETOOMANYREFS",
        110 => "ETIMEDOUT",
        111 => "ECONNREFUSED",
        112 => "EHOSTDOWN",
        113 => "EHOSTUNREACH",
        114 => "EALREADY",
        115 => "EINPROGRESS",
        116 => "ESTALE",
        117 => "EUCLEAN",
        118 => "ENOTNAM",
        119 => "ENAVAIL",
        120 => "EISNAM",
        121 => "EREMOTEIO",
        122 => "EDQUOT",
        123 => "ENOMEDIUM",
        124 => "EMEDIUMTYPE",
        125 => "ECANCELED",
        126 => "ENOKEY",
        127 => "EKEYEXPIRED",
        128 => "EKEYREVOKED",
        129 => "EKEYREJECTED",
        130 => "EOWNERDEAD",
        131 => "ENOTRECOVERABLE",
        132 => "ERFKILL",
        133 => "EHWPOISON",
        _ => "",
    };

    let description = unsafe {
        let ptr = libc::strerror(errno);
        std::ffi::CStr::from_ptr(ptr).to_string_lossy().to_string()
    };

    if name.is_empty() {
        format!("ERRNO({}) ({})", errno, description)
    } else {
        format!("{} ({})", name, description)
    }
}

pub fn get_args<T: plain::Plain>(args: &[u8]) -> &T {
    let size = std::mem::size_of::<T>();
    let slice = &args[0..size];
    return plain::from_bytes::<T>(slice).expect("Fail to cast bytes to Args");
}
