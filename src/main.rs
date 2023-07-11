use crate::bump_memlock_rlimit::*;
use crate::handler::msg_ent_handler;
use crate::sys::*;
use anyhow::{anyhow, Result};
use libbpf_rs::RingBufferBuilder;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[macro_use]
mod common;
mod access;
mod arch;
mod bump_memlock_rlimit;
mod execve;
mod exit;
mod handler;
mod io;
mod ioctl;
mod lseek;
mod mem;
mod open_close;
mod poll;
mod rt_sigreturn;
mod signal;
mod stat;
mod sys;
mod syscall;
mod utils;

#[path = "../bpf/.output/strace.skel.rs"]
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

    let child_pid = match fork() {
        0 => {
            let pid = getpid();
            /* We have to set select_pid by child process
             * itself because only it knows when it is going
             * to do execvp. */
            skel.bss().select_pid = pid;
            execvp(&args)?;
            unreachable!();
        }
        pid => pid,
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
    builder.add(skel.maps().msg_ringbuf(), msg_ent_handler)?;
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

    /* Wait the child process for its exit status */
    let result = waitpid(child_pid);
    if let Ok(WaitStatus::Exited(exit)) = result {
        eprintln!("+++ exited with {} +++", exit);
    }

    Ok(())
}
