use crate::sys::*;
use crate::syscall::*;
use anyhow::{anyhow, Result};
use libbpf_rs::RingBufferBuilder;
use plain::Plain;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use utils::bump_memlock_rlimit;

mod sys;
mod syscall;
mod syscall_desc;

#[path = "bpf/.output/strace.skel.rs"]
#[cfg_attr(rustfmt, rustfmt_skip)]
mod strace;
use strace::*;

#[macro_use]
extern crate lazy_static;

fn load_ebpf_prog() -> Result<StraceSkel<'static>> {
    /* We may have to bump RLIMIT_MEMLOCK for libbpf explicitly */
    if cfg!(bump_memlock_rlimit_manually) {
        bump_memlock_rlimit()?;
    }

    let builder = StraceSkelBuilder::default();
    /* Open BPF application */
    let open_skel = builder.open()?;
    /* Load & verify BPF programs */
    open_skel.load().map_err(anyhow::Error::msg)
}

/* This should be synchronized with the structure
 * syscall_ent_t in strace.bpf.c */
#[repr(C)]
struct SyscallEnt {
    id: u64,
}

unsafe impl Plain for SyscallEnt {}
fn syscall_ent_handler(bytes: &[u8]) -> i32 {
    let result = plain::from_bytes::<SyscallEnt>(bytes);
    if result.is_err() {
        return -1;
    }
    let ent = result.unwrap();

    let syscall = &SYSCALLS[ent.id as usize];
    eprintln!("{}", syscall.name);

    0
}

fn main() -> Result<()> {
    let mut skel = load_ebpf_prog()?;

    /* Spawn a thread to run the executable, and then trace it
     * in our eBPF code. */
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() == 0 {
        return Err(anyhow!("Command cannot be empty"));
    }
    let pid = spawn(args)?;
    skel.bss().select_pid = pid;

    /* Attach tracepoint handler */
    let _tracepoint = skel.progs_mut().sys_enter().attach()?;

    /* Run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to
     * see output of the BPF programs */

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    /* Access the ringbuffer in our ebpf code */
    let mut builder = RingBufferBuilder::new();
    builder.add(skel.maps().syscall_record(), syscall_ent_handler)?;
    let syscall_record = builder.build()?;

    while running.load(Ordering::SeqCst) {
        let result = syscall_record.poll(Duration::MAX);
        if let Err(r) = &result {
            if matches!(r, libbpf_rs::Error::System(libc::EINTR)) {
                break;
            }
            /* FIXME: Any better way to convert any Error to anyhow::Error? */
            return result.map_err(anyhow::Error::msg);
        }
    }

    Ok(())
}
