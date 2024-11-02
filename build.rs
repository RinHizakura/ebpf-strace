use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use libbpf_cargo::SkeletonBuilder;

const SKEL_SRC: &str = "bpf/strace.bpf.c";

fn open_read(path: &str) -> Result<File> {
    let file = OpenOptions::new().read(true).open(path)?;
    Ok(file)
}

fn open_write(path: &str) -> Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;

    Ok(file)
}

fn gen_syscall_tbl_h(target: &mut File, line: Vec<&str>) -> Result<()> {
    let syscall_name = line[0];
    target.write_all(
        format!(
            "__SYSCALL(SYS_{}, {})\n",
            syscall_name,
            syscall_name.to_lowercase()
        )
        .as_bytes(),
    )?;

    Ok(())
}

fn gen_syscall_h_prologue(target: &mut File) -> Result<()> {
    target.write_all(b"#ifndef SYSCALL_H\n")?;
    target.write_all(b"#define SYSCALL_H\n")?;
    Ok(())
}

fn gen_syscall_h(target: &mut File, line: Vec<&str>) -> Result<()> {
    let syscall_name = line[0];
    let syscall_id = line[1];
    target.write_all(format!("#define SYS_{syscall_name} {syscall_id}\n").as_bytes())?;
    Ok(())
}

fn gen_syscall_h_epilogue(target: &mut File) -> Result<()> {
    target.write_all(b"#endif\n")?;

    Ok(())
}

fn gen_syscall_tbl_rs_prologue(target: &mut File) -> Result<()> {
    let s4 = " ".repeat(4);

    target.write_all(b"use crate::syscall::syscall_desc::*;\n")?;
    target.write_all(b"lazy_static! {\n")?;
    target
        .write_all(format!("{s4}pub static ref SYSCALLS: Vec<SyscallDesc> = vec![\n").as_bytes())?;

    Ok(())
}

fn gen_syscall_tbl_rs(target: &mut File, line: Vec<&str>) -> Result<()> {
    let s8 = " ".repeat(8);
    let syscall_name = line[0];
    let syscall_id = line[1];

    target.write_all(
        format!(
            "{s8}SyscallDesc::new({}, \"{}\"),\n",
            syscall_id,
            syscall_name.to_lowercase()
        )
        .as_bytes(),
    )?;
    Ok(())
}

fn gen_syscall_tbl_rs_epilogue(target: &mut File) -> Result<()> {
    let s4 = " ".repeat(4);
    target.write_all(format!("{s4}];\n").as_bytes())?;
    target.write_all(b"}\n")?;

    Ok(())
}

fn gen_syscall_nr_rs_prologue(target: &mut File) -> Result<()> {
    target.write_all(b"#![allow(dead_code)]\n")?;
    Ok(())
}

fn gen_syscall_nr_rs(target: &mut File, line: Vec<&str>) -> Result<()> {
    let syscall_name = line[0];
    let syscall_id = line[1];

    target.write_all(
        format!("pub const SYS_{}: u64 = {};\n", syscall_name, syscall_id,).as_bytes(),
    )?;
    Ok(())
}

fn generate<F, F2, F3>(
    src: &str,
    path: &str,
    main_f: F,
    pro_f: Option<F2>,
    epi_f: Option<F3>,
) -> Result<()>
where
    F: Fn(&mut File, Vec<&str>) -> Result<()>,
    F2: Fn(&mut File) -> Result<()>,
    F3: Fn(&mut File) -> Result<()>,
{
    let src = open_read(src)?;
    let mut target = open_write(path)?;

    if let Some(f) = pro_f {
        f(&mut target)?;
    }

    let lines = BufReader::new(src).lines();
    for line in lines {
        let l = line.unwrap();
        main_f(&mut target, l.split(' ').collect::<Vec<&str>>())?;
    }

    if let Some(f) = epi_f {
        f(&mut target)?;
    }

    Ok(())
}

fn create_syscall_files(src: &str, arch: &str) -> Result<()> {
    generate(
        src,
        &format!("bpf/arch/{arch}/syscall_tbl.h"),
        gen_syscall_tbl_h,
        None::<Box<dyn Fn(&mut File) -> Result<()>>>,
        None::<Box<dyn Fn(&mut File) -> Result<()>>>,
    )?;
    generate(
        src,
        &format!("bpf/arch/{arch}/syscall_nr.h"),
        gen_syscall_h,
        Some(gen_syscall_h_prologue),
        Some(gen_syscall_h_epilogue),
    )?;
    generate(
        src,
        &format!("src/arch/{arch}/syscall_tbl.rs"),
        gen_syscall_tbl_rs,
        Some(gen_syscall_tbl_rs_prologue),
        Some(gen_syscall_tbl_rs_epilogue),
    )?;
    generate(
        src,
        &format!("src/arch/{arch}/syscall_nr.rs"),
        gen_syscall_nr_rs,
        Some(gen_syscall_nr_rs_prologue),
        None::<Box<dyn Fn(&mut File) -> Result<()>>>,
    )?;

    Ok(())
}

fn create_btf(vmlinx: &str, btf: &str) {
    if Path::new(&btf).exists() {
        return;
    }

    let output = Command::new("pahole")
        .arg("--btf_encode_detached")
        .arg(btf)
        .arg(vmlinx)
        .stdout(Stdio::piped())
        .output()
        .expect("Failed to build vmlinux.h");
    println!("{}", String::from_utf8(output.stderr).unwrap());
    assert!(output.status.success());
}

fn create_vmlinux_h(btf: &str, vmlinux_h: &str) {
    if Path::new(&vmlinux_h).exists() {
        return;
    }
    let f = File::create(vmlinux_h).expect("failed to open vmlinx.h");
    let output = Command::new("bpftool")
        .arg("btf")
        .arg("dump")
        .arg("file")
        .arg(btf)
        .arg("format")
        .arg("c")
        .stdout(f)
        .output()
        .expect("Failed to build vmlinux.h");
    println!("{}", String::from_utf8(output.stderr).unwrap());
    assert!(output.status.success());
}

fn main() -> Result<()> {
    // FIXME: Is it possible to output to env!("OUT_DIR")?
    std::env::set_var("BPF_OUT_DIR", "bpf/.output");
    create_dir_all("bpf/.output")?;

    let arch = build_target::target_arch().unwrap().to_string();
    let outdir = std::env::var_os("OUT_DIR")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let host = std::env::var_os("HOST")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    /* Create vmlinx.btf */
    let mut btf = "/sys/kernel/btf/vmlinux".to_string();
    if !host.contains(&arch) || !Path::new(&btf).exists() {
        if let Some(v) = std::env::var_os("VMLINUX") {
            let vmlinux = v.to_str().unwrap().to_string();
            btf = format!("{outdir}/vmlinux.btf");
            create_btf(&vmlinux, &btf);
        } else {
            return Err(anyhow!("Please specific vmlinux with VMLINUX="));
        }
    }

    /* Create vmlinx.h */
    let vmlinx_h = format!("{outdir}/vmlinux.h");
    create_vmlinux_h(&btf, &vmlinx_h);

    /* Create the syscall-related files automatically */
    let syscall_src = format!("src/arch/{arch}/syscall.tbl");
    create_syscall_files(&syscall_src, &arch)?;

    let skel = Path::new("bpf/.output/strace.skel.rs");
    let arch_dict = HashMap::from([
        ("x86_64".to_string(), "x86"),
        ("aarch64".to_string(), "arm64"),
    ]);
    let arch_flag = arch_dict.get(&arch).unwrap();
    let bpf_target_flag = format!("-D__TARGET_ARCH_{arch_flag}");
    SkeletonBuilder::new()
        .source(SKEL_SRC)
        .clang_args([
            &bpf_target_flag,
            "-I.",
            "-I",
            &outdir,
            "-Wextra",
            "-Wall",
            "-Werror",
            "-Wno-unused-function",
        ])
        .build_and_generate(&skel)?;

    println!("cargo:rerun-if-changed={}/{}", syscall_src, SKEL_SRC);

    Ok(())
}
