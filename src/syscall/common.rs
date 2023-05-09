pub const BUF_SIZE: usize = 32;

#[macro_export]
macro_rules! flag_desc {
    ( $flag:expr ) => {
        FlagDesc {
            val: $flag as u32,
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

pub(super) fn format_str(buf: &[u8]) -> String {
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

pub struct FlagDesc {
    pub val: u32,
    pub name: &'static str,
}

pub fn format_flags(mut flags: u32, sep: char, flags_descs: &[FlagDesc]) -> String {
    let mut output_str: String = String::new();

    for f in flags_descs {
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
        // Pop out the last seperator if there's any
        output_str.pop();
    }

    output_str
}

pub fn get_args<T: plain::Plain>(args: &[u8]) -> &T {
    let size = std::mem::size_of::<T>();
    let slice = &args[0..size];
    return plain::from_bytes::<T>(slice).expect("Fail to cast bytes to Args");
}
