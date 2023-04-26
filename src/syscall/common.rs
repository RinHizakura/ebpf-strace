pub const BUF_SIZE: usize = 32;

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
    s.push_str(&format!("\"{}, ", extra));

    s
}

pub fn get_args<T: plain::Plain>(args: &[u8]) -> &T {
    let size = std::mem::size_of::<T>();
    let slice = &args[0..size];
    return plain::from_bytes::<T>(slice).expect("Fail to cast bytes to Args");
}
