pub const BUF_SIZE: usize = 32;

pub(super) fn format_buf(buf: &[u8], count: usize) {
    let len = buf.len();
    let extra = if count > len { "..." } else { "" };
    let count = count.min(len);

    eprint!("\"");
    for byte in &buf[0..count] {
        let c = *byte;
        /* TODO: cover all possible special character */
        if (c as char).is_ascii_graphic() || (c as char) == ' ' {
            eprint!("{}", c as char);
        } else if (c as char) == '\n' {
            eprint!("\\n");
        } else if (c as char) == '\t' {
            eprint!("\\n");
        } else {
            /* Print it as octal(base-8) like what
             * strace do by default */
            eprint!("\\{:o}", c);
        }
    }
    eprint!("\"{}, ", extra);
}

pub(super) fn format_str(buf: &[u8]) {
    let len = buf.len();
    let mut idx = 0;

    eprint!("\"");
    while idx < len {
        let c = buf[idx];
        if c == 0 {
            break;
        } else {
            eprint!("{}", c as char);
        }

        idx += 1;
    }

    /* If we can't find the ended zero in the buffer, this is an incomplete string. */
    let extra = if idx >= len { "..." } else { "" };
    eprint!("\"{}, ", extra);
}
