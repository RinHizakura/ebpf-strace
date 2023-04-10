use crate::sys::*;
use crate::syscall::syscall_ent_handler;
use anyhow::{anyhow, Result};
use libbpf_rs::RingBufferBuilder;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use utils::bump_memlock_rlimit;

mod sys;
mod syscall;

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

fn main() -> Result<()> {
    let mut skel = load_ebpf_prog()?;
    /* Attach tracepoint handler */
    let _tracepoint = skel.attach()?;

    /* Spawn a thread to run the executable, and then trace it
     * in our eBPF code. */
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() == 0 {
        return Err(anyhow!("Command cannot be empty"));
    }

    match fork() {
        0 => {
            let pid = getpid();
            /* We have to set select_pid by child process
             * itself because only it knows when it is going
             * to do execvp. */
            skel.bss().select_pid = pid;
            execvp(&args)?;
        }
        _ => {}
    };

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
