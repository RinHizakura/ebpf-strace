use std::ffi::{c_int, c_long};

pub const ARR_ENT_SIZE: usize = 4;
pub const BUF_SIZE: usize = 32;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[repr(C)]
pub struct KernlSigset {
    pub sig: [c_long; 1],
}

#[macro_export]
macro_rules! desc {
    ( $flag:expr ) => {
        Desc {
            val: $flag as u64,
            name: stringify!($flag),
        }
    };
}

pub(super) fn format_buf(buf: &[u8], count: usize) -> String {
    let len = buf.len();
    let extra = if count > len { "..." } else { "" };
    let count = count.min(len);

    let mut s = String::new();
    s.push('"');
    for byte in &buf[0..count] {
        let c = *byte;
        /* TODO: cover all possible special character */
        if (c as char).is_ascii_graphic() || (c as char) == ' ' {
            s.push(c as char);
        } else if (c as char) == '\n' {
            s.push_str("\\n");
        } else if (c as char) == '\t' {
            s.push_str("\\t");
        } else {
            /* Print it as octal(base-8) like what
             * strace do by default */
            s.push_str(&format!("\\{:o}", c));
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
    let extra = if idx >= len { "..." } else { "" };
    s.push_str(&format!("\"{}", extra));

    s
}

pub struct Desc {
    pub val: u64,
    pub name: &'static str,
}

pub fn format_flags(mut flags: u64, sep: char, descs: &[Desc]) -> String {
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
        /* FIXME: The format(base, width) should be specified by caller */
        output_str.push_str(&format!("{:o}", flags));
    } else {
        if output_str.is_empty() {
            output_str.push_str(zero_flag_str);
        } else {
            // Pop out the last seperator if there's any
            output_str.pop();
        }
    }

    output_str
}

pub fn format_value(val: u64, default: &str, descs: &[Desc]) -> String {
    for v in descs {
        if val == v.val {
            return v.name.to_owned();
        }
    }

    /* Print the value directly if no hit */
    return format!("0x{:x} /* {} */", val, default);
}

pub fn format_dirfd(fd: c_int) -> String {
    if fd == libc::AT_FDCWD {
        "AT_FDCWD".to_string()
    } else {
        fd.to_string()
    }
}

/* FIXME: We should make the implementation prettier if there's the way :( */
pub fn format_arr<T, F>(arr: &[T], arr_size: usize, formatter: F) -> String
where
    F: Fn(&T) -> String,
{
    let mut list_str = String::new();

    list_str.push('[');

    /* Note that arr_size is not equal to arr.len(). */
    let printed_argc = (arr_size as usize).min(ARR_ENT_SIZE);
    for idx in 0..printed_argc {
        list_str.push_str(&formatter(&arr[idx]));
        list_str.push(',');
    }
    // Pop out the last ','
    list_str.pop();

    if arr_size > ARR_ENT_SIZE {
        list_str.push_str("...");
    }

    list_str.push(']');

    list_str
}

pub(super) fn format_addr(addr: usize) -> String {
    if addr == 0 {
        "NULL".to_string()
    } else {
        format!("0x{:x}", addr)
    }
}

/* FIXME: This could not correct for some architecture */
const SIGNUM_TOTAL: usize = 32;
const SIGNAL_NAME: &[&'static str; SIGNUM_TOTAL + 1] = &[
    "0",         /* 0 */
    "SIGHUP",    /* 1 */
    "SIGINT",    /* 2 */
    "SIGQUIT",   /* 3 */
    "SIGILL",    /* 4 */
    "SIGTRAP",   /* 5 */
    "SIGABRT",   /* 6 */
    "SIGBUS",    /* 7 */
    "SIGFPE",    /* 8 */
    "SIGKILL",   /* 9 */
    "SIGUSR1",   /* 10 */
    "SIGSEGV",   /* 11 */
    "SIGUSR2",   /* 12 */
    "SIGPIPE",   /* 13 */
    "SIGALRM",   /* 14 */
    "SIGTERM",   /* 15 */
    "SIGSTKFLT", /* 16 */
    "SIGCHLD",   /* 17 */
    "SIGCONT",   /* 18 */
    "SIGSTOP",   /* 19 */
    "SIGTSTP",   /* 20 */
    "SIGTTIN",   /* 21 */
    "SIGTTOU",   /* 22 */
    "SIGURG",    /* 23 */
    "SIGXCPU",   /* 24 */
    "SIGXFSZ",   /* 25 */
    "SIGVTALRM", /* 26 */
    "SIGPROF",   /* 27 */
    "SIGWINCH",  /* 28 */
    "SIGIO",     /* 29 */
    "SIGPWR",    /* 30 */
    "SIGSYS",    /* 31 */
    "SIGRTMIN",  /* 32 */
];

pub(super) fn format_signum(signum: c_int) -> String {
    if signum < 0 || signum > SIGNUM_TOTAL as c_int {
        return signum.to_string();
    }

    return SIGNAL_NAME[signum as usize].to_string();
}

fn next_set_bit(sig_mask: &[c_long], mut cur_bit: c_int) -> c_int {
    /* FIXME: Just simply implement this for correctness. Consider
     * https://github.com/strace/strace/blob/master/src/util.c#LL274C1-L274C74
     * if we want some optimization */
    let ent_bitsize = std::mem::size_of::<c_long>() as c_int * 8;
    let total_bitsize = sig_mask.len() as c_int * ent_bitsize;

    while cur_bit < total_bitsize {
        let slot = (cur_bit / ent_bitsize) as usize;
        let pos = cur_bit % ent_bitsize;

        if ((sig_mask[slot] >> pos) & 1) == 1 {
            return cur_bit;
        }

        cur_bit += 1;
    }
    return -1;
}

pub(super) fn format_sigset(sig_mask: &KernlSigset) -> String {
    let mut s = String::new();
    s.push('[');

    let mut i = next_set_bit(&sig_mask.sig, 0);
    while i >= 0 && i < SIGNUM_TOTAL as c_int {
        i += 1;
        s.push_str(&SIGNAL_NAME[i as usize][3..]);
        s.push(' ');
        i = next_set_bit(&sig_mask.sig, i);
    }
    /* It means we don't just put the first '[' in the string. Pop
     * the last space. */
    if s.len() != 1 {
        s.pop();
    }
    s.push(']');
    return s;
}

pub fn get_args<T: plain::Plain>(args: &[u8]) -> &T {
    let size = std::mem::size_of::<T>();
    let slice = &args[0..size];
    return plain::from_bytes::<T>(slice).expect("Fail to cast bytes to Args");
}
