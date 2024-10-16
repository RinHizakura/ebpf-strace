use anyhow::Result;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use libbpf_cargo::SkeletonBuilder;

const SYSCALL_SRC: &str = "src/syscall/syscall.tbl";
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

fn generate<F, F2, F3>(path: &str, main_f: F, pro_f: Option<F2>, epi_f: Option<F3>) -> Result<()>
where
    F: Fn(&mut File, Vec<&str>) -> Result<()>,
    F2: Fn(&mut File) -> Result<()>,
    F3: Fn(&mut File) -> Result<()>,
{
    let src = open_read(SYSCALL_SRC)?;
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

fn main() -> Result<()> {
    // FIXME: Is it possible to output to env!("OUT_DIR")?
    std::env::set_var("BPF_OUT_DIR", "bpf/.output");

    create_dir_all("bpf/.output")?;

    // Generate the syscall-related file automatically
    generate(
        "bpf/syscall/syscall_tbl.h",
        gen_syscall_tbl_h,
        None::<Box<dyn Fn(&mut File) -> Result<()>>>,
        None::<Box<dyn Fn(&mut File) -> Result<()>>>,
    )?;
    generate(
        "bpf/syscall/syscall_nr.h",
        gen_syscall_h,
        Some(gen_syscall_h_prologue),
        Some(gen_syscall_h_epilogue),
    )?;
    generate(
        "src/syscall/syscall_tbl.rs",
        gen_syscall_tbl_rs,
        Some(gen_syscall_tbl_rs_prologue),
        Some(gen_syscall_tbl_rs_epilogue),
    )?;
    generate(
        "src/syscall/syscall_nr.rs",
        gen_syscall_nr_rs,
        Some(gen_syscall_nr_rs_prologue),
        None::<Box<dyn Fn(&mut File) -> Result<()>>>,
    )?;

    let skel = Path::new("bpf/.output/strace.skel.rs");
    SkeletonBuilder::new()
        .source(SKEL_SRC)
        .clang_args(["-I.", "-Wextra", "-Wall", "-Werror"])
        .build_and_generate(&skel)?;

    println!("cargo:rerun-if-changed={}/{}", SYSCALL_SRC, SKEL_SRC);

    Ok(())
}
