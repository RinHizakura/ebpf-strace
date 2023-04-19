pub const BUF_SIZE: usize = 32;

pub(super) fn format_buf(buf: &[u8; BUF_SIZE], count: usize) {
    let extra = if count > BUF_SIZE { "..." } else { "" };
    let count = count.min(BUF_SIZE);
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
