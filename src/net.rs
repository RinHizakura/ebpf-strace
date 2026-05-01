use std::ffi::c_uchar;

use crate::common::*;
use libc::{
    sa_family_t, socklen_t, AF_INET, AF_INET6, AF_UNIX, AF_UNSPEC, MSG_CMSG_CLOEXEC, MSG_CONFIRM,
    MSG_CTRUNC, MSG_DONTROUTE, MSG_DONTWAIT, MSG_EOR, MSG_ERRQUEUE, MSG_MORE, MSG_NOSIGNAL,
    MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_NONBLOCK, SOCK_RAW,
    SOCK_RDM, SOCK_SEQPACKET, SOCK_STREAM,
};

const SOCKADDR_BUF_SIZE: usize = 28;

const DOMAIN_DESCS: &[Desc] = &[
    desc!(AF_UNIX),
    desc!(AF_INET),
    desc!(AF_INET6),
    desc!(AF_UNSPEC),
];

const SOCK_TYPE_DESCS: &[Desc] = &[
    desc!(SOCK_STREAM),
    desc!(SOCK_DGRAM),
    desc!(SOCK_RAW),
    desc!(SOCK_RDM),
    desc!(SOCK_SEQPACKET),
];

const SOCK_TYPE_FLAGS_DESCS: &[Desc] = &[desc!(SOCK_NONBLOCK), desc!(SOCK_CLOEXEC)];

const MSG_FLAGS_DESCS: &[Desc] = &[
    desc!(MSG_OOB),
    desc!(MSG_PEEK),
    desc!(MSG_DONTROUTE),
    desc!(MSG_CTRUNC),
    desc!(MSG_TRUNC),
    desc!(MSG_DONTWAIT),
    desc!(MSG_EOR),
    desc!(MSG_WAITALL),
    desc!(MSG_NOSIGNAL),
    desc!(MSG_MORE),
    desc!(MSG_CONFIRM),
    desc!(MSG_ERRQUEUE),
    desc!(MSG_CMSG_CLOEXEC),
];

const ACCEPT4_FLAGS_DESCS: &[Desc] = &[desc!(SOCK_NONBLOCK), desc!(SOCK_CLOEXEC)];

fn format_sock_type(t: c_int) -> String {
    let raw = t as u64;
    let base = (raw & 0xff) as u64;
    let flags_part = raw & !0xff;

    let base_str = format_value(base, Some("SOCK_???"), SOCK_TYPE_DESCS, Format::Hex);
    if flags_part != 0 {
        let flags_str = format_flags(flags_part, '|', SOCK_TYPE_FLAGS_DESCS, Format::Hex);
        format!("{}|{}", base_str, flags_str)
    } else {
        base_str
    }
}

pub(super) fn format_sockaddr(addr: &[u8; SOCKADDR_BUF_SIZE], addrlen: u32) -> String {
    if addrlen < 2 {
        return "{}".to_owned();
    }
    let family = u16::from_ne_bytes([addr[0], addr[1]]) as sa_family_t;
    match family as i32 {
        AF_UNIX => {
            let path = &addr[2..];
            let s = path
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as char)
                .collect::<String>();
            format!("{{sa_family=AF_UNIX, sun_path=\"{}\"}}", s)
        }
        AF_INET => {
            if addrlen as usize >= 8 {
                let port = u16::from_be_bytes([addr[2], addr[3]]);
                let ip = format!("{}.{}.{}.{}", addr[4], addr[5], addr[6], addr[7]);
                format!(
                    "{{sa_family=AF_INET, sin_port=htons({}), sin_addr=\"{}\"}}",
                    port, ip
                )
            } else {
                "{sa_family=AF_INET, ...}".to_owned()
            }
        }
        AF_INET6 => {
            if addrlen as usize >= 24 {
                let port = u16::from_be_bytes([addr[2], addr[3]]);
                let ip = (8..24)
                    .step_by(2)
                    .map(|i| format!("{:02x}{:02x}", addr[i], addr[i + 1]))
                    .collect::<Vec<_>>()
                    .join(":");
                format!(
                    "{{sa_family=AF_INET6, sin6_port=htons({}), sin6_addr=\"{}\"}}",
                    port, ip
                )
            } else {
                "{sa_family=AF_INET6, ...}".to_owned()
            }
        }
        _ => format!("{{sa_family={}, ...}}", family),
    }
}

#[repr(C)]
struct SocketArgs {
    domain: c_int,
    type_: c_int,
    protocol: c_int,
}
unsafe impl plain::Plain for SocketArgs {}

pub(super) fn handle_socket_args(args: &[u8]) -> String {
    let s = get_args::<SocketArgs>(args);
    let domain = format_value(s.domain as u64, Some("AF_???"), DOMAIN_DESCS, Format::Hex);
    let typ = format_sock_type(s.type_);
    format!("{}, {}, {}", domain, typ, s.protocol)
}

#[repr(C)]
struct ConnectArgs {
    sockfd: c_int,
    addr: [c_uchar; SOCKADDR_BUF_SIZE],
    addrlen: socklen_t,
}
unsafe impl plain::Plain for ConnectArgs {}

pub(super) fn handle_connect_args(args: &[u8]) -> String {
    let c = get_args::<ConnectArgs>(args);
    format!(
        "{}, {}, {}",
        c.sockfd,
        format_sockaddr(&c.addr, c.addrlen),
        c.addrlen
    )
}

#[repr(C)]
struct AcceptArgs {
    sockfd: c_int,
    addr: [c_uchar; SOCKADDR_BUF_SIZE],
    addrlen: socklen_t,
}
unsafe impl plain::Plain for AcceptArgs {}

pub(super) fn handle_accept_args(args: &[u8]) -> String {
    let a = get_args::<AcceptArgs>(args);
    format!(
        "{}, {}, [{}]",
        a.sockfd,
        format_sockaddr(&a.addr, a.addrlen),
        a.addrlen
    )
}

#[repr(C)]
struct Accept4Args {
    sockfd: c_int,
    addr: [c_uchar; SOCKADDR_BUF_SIZE],
    addrlen: socklen_t,
    flags: c_int,
}
unsafe impl plain::Plain for Accept4Args {}

pub(super) fn handle_accept4_args(args: &[u8]) -> String {
    let a = get_args::<Accept4Args>(args);
    let flags = format_flags(a.flags as u64, '|', ACCEPT4_FLAGS_DESCS, Format::Hex);
    format!(
        "{}, {}, [{}], {}",
        a.sockfd,
        format_sockaddr(&a.addr, a.addrlen),
        a.addrlen,
        flags
    )
}

#[repr(C)]
struct SendtoArgs {
    sockfd: c_int,
    buf: [u8; BUF_SIZE],
    len: usize,
    flags: c_int,
    dest_addr: [c_uchar; SOCKADDR_BUF_SIZE],
    addrlen: socklen_t,
    is_addr_exist: bool,
}
unsafe impl plain::Plain for SendtoArgs {}

pub(super) fn handle_sendto_args(args: &[u8]) -> String {
    let s = get_args::<SendtoArgs>(args);
    let buf = format_buf(&s.buf, s.len);
    let flags = format_flags(s.flags as u64, '|', MSG_FLAGS_DESCS, Format::Hex);
    let addr = if s.is_addr_exist {
        format_sockaddr(&s.dest_addr, s.addrlen)
    } else {
        NULL_STR.to_owned()
    };
    format!(
        "{}, {}, {}, {}, {}, {}",
        s.sockfd, buf, s.len, flags, addr, s.addrlen
    )
}

#[repr(C)]
struct RecvfromArgs {
    sockfd: c_int,
    buf: [u8; BUF_SIZE],
    len: usize,
    flags: c_int,
    src_addr: [c_uchar; SOCKADDR_BUF_SIZE],
    src_addrlen: socklen_t,
    is_addr_exist: bool,
}
unsafe impl plain::Plain for RecvfromArgs {}

pub(super) fn handle_recvfrom_args(args: &[u8], ret: u64) -> String {
    let r = get_args::<RecvfromArgs>(args);
    let ret_len = ret as i64;
    let buf = if ret_len > 0 {
        format_buf(&r.buf, ret_len as usize)
    } else {
        format_buf(&r.buf, 0)
    };
    let flags = format_flags(r.flags as u64, '|', MSG_FLAGS_DESCS, Format::Hex);
    let addr = if r.is_addr_exist {
        format_sockaddr(&r.src_addr, r.src_addrlen)
    } else {
        NULL_STR.to_owned()
    };
    let alen = if r.is_addr_exist {
        format!("[{}]", r.src_addrlen)
    } else {
        NULL_STR.to_owned()
    };
    format!(
        "{}, {}, {}, {}, {}, {}",
        r.sockfd, buf, r.len, flags, addr, alen
    )
}
