use crate::bump_memlock_rlimit::*;
use crate::handler::{msg_ent_handler, time_msg_handler};
use crate::sys::*;
use anyhow::{anyhow, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[macro_use]
mod common;
mod access;
mod arch;
mod bump_memlock_rlimit;
mod desc;
mod dup;
mod execve;
mod exit;
mod handler;
mod io;
mod ioctl;
mod ipc_shm;
mod lseek;
mod mem;
mod net;
mod open;
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

fn open_ebpf_prog() -> Result<OpenStraceSkel<'static>> {
    /* We may have to bump RLIMIT_MEMLOCK for libbpf explicitly */
    if cfg!(bump_memlock_rlimit_manually) {
        bump_memlock_rlimit()?;
    }

    let builder = StraceSkelBuilder::default();
    /* Open BPF application */
    let open_skel = builder.open()?;
    Ok(open_skel)
}

#[derive(Parser)]
struct Cli {
    #[arg(
        short,
        long,
        default_value_t = false,
        help = "whether to focus on the time cost of syscall"
    )]
    time_mode: bool,

    #[arg(trailing_var_arg = true, help = "command to run for trace")]
    cmd: Vec<String>,
}

fn main() -> Result<()> {
    let mut open_skel = open_ebpf_prog()?;

    let cli = Cli::parse();
    let time_mode = cli.time_mode;
    open_skel.rodata_mut().time_mode = time_mode as i32;

    /* Load & verify BPF programs */
    let mut skel = open_skel.load()?;
    /* Attach tracepoint handler */
    let _tracepoint = skel.attach()?;

    /* Spawn a thread to run the executable, and then trace it
     * in our eBPF code. */
    let cmd = cli.cmd;
    if cmd.len() == 0 {
        return Err(anyhow!("Command cannot be empty"));
    }

    let child_pid = match fork() {
        0 => {
            let pid = getpid();
            /* We have to set select_pid by child process
             * itself because only it knows when it is going
             * to do execvp. */
            unsafe { (*skel.bss_mut_raw()).select_pid = pid };
            execvp(&cmd)?;
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
    let skel_maps = skel.maps();

    if time_mode {
        builder.add(skel_maps.msg_ringbuf(), time_msg_handler)?;
    } else {
        builder.add(skel_maps.msg_ringbuf(), msg_ent_handler)?;
    }

    let syscall_record = builder.build()?;
    while running.load(Ordering::SeqCst) {
        let result = syscall_record.poll(Duration::MAX);
        if let Err(r) = &result {
            if matches!(r.kind(), libbpf_rs::ErrorKind::Interrupted) {
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
