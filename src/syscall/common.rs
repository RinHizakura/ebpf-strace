use std::ffi::c_int;

pub const ARR_ENT_SIZE: usize = 4;
pub const BUF_SIZE: usize = 32;

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

pub fn get_args<T: plain::Plain>(args: &[u8]) -> &T {
    let size = std::mem::size_of::<T>();
    let slice = &args[0..size];
    return plain::from_bytes::<T>(slice).expect("Fail to cast bytes to Args");
}
