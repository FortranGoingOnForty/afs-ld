//! Audit L3: command-line input order must be preserved so archive symbol
//! resolution matches GNU ld left-to-right. `pmain.o -lb ./liba.a` must search
//! `libb` before `liba` even though `liba.a` is positional and `-lb` is a `-l`
//! request. The old arg parser drained all positional files before all `-l`,
//! so `liba` always won regardless of interleaving.

use std::path::PathBuf;
use std::process::Command;

fn gas() -> Option<PathBuf> {
    let cands: &[&str] = if cfg!(target_os = "freebsd") {
        &["/usr/local/bin/as"]
    } else if cfg!(target_os = "linux") {
        &["as"]
    } else {
        &[]
    };
    for c in cands {
        if let Ok(o) = Command::new(c).arg("--version").output() {
            if o.status.success() && String::from_utf8_lossy(&o.stdout).contains("GNU assembler") {
                return Some(PathBuf::from(c));
            }
        }
    }
    None
}

fn ar() -> Option<PathBuf> {
    for c in ["ar", "/usr/bin/ar", "/usr/local/bin/ar"] {
        if Command::new(c).arg("--version").output().is_ok()
            || Command::new(c).output().is_ok()
        {
            return Some(PathBuf::from(c));
        }
    }
    None
}

fn assemble(gas: &PathBuf, dir: &std::path::Path, name: &str, asm: &str) -> PathBuf {
    let s = dir.join(format!("{name}.s"));
    let o = dir.join(format!("{name}.o"));
    std::fs::write(&s, asm).unwrap();
    let out = Command::new(gas)
        .args(["--64", "-o"])
        .arg(&o)
        .arg(&s)
        .output()
        .unwrap();
    assert!(out.status.success(), "gas {name}: {}", String::from_utf8_lossy(&out.stderr));
    o
}

fn archive(ar: &PathBuf, dir: &std::path::Path, libname: &str, obj: &PathBuf) -> PathBuf {
    let a = dir.join(format!("lib{libname}.a"));
    let _ = std::fs::remove_file(&a);
    let out = Command::new(ar).arg("rcs").arg(&a).arg(obj).output().unwrap();
    assert!(out.status.success(), "ar {libname}: {}", String::from_utf8_lossy(&out.stderr));
    a
}

/// `foo` returns `ret`; `_start` calls it and exits with its return value.
fn foo_returns(ret: i32) -> String {
    format!(
        ".text\n.globl foo\n.type foo,@function\nfoo:\n    movl ${ret}, %eax\n    ret\n.size foo,.-foo\n"
    )
}

#[test]
fn archive_search_follows_command_line_order() {
    let (Some(gas), Some(ar)) = (gas(), ar()) else {
        eprintln!("\nHARNESS_SKIP suite=elf_lib_order test=archive_search_follows_command_line_order count=1 reason=\"no GNU assembler or ar on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_lib_order_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let exit_syscall = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let pmain = format!(
        ".text\n.globl _start\n.type _start,@function\n_start:\n    call foo\n    movl %eax, %edi\n    movl ${exit_syscall}, %eax\n    syscall\n.size _start,.-_start\n"
    );

    let pmain_o = assemble(&gas, &dir, "pmain", &pmain);
    let a_o = assemble(&gas, &dir, "a", &foo_returns(1));
    let b_o = assemble(&gas, &dir, "b", &foo_returns(2));
    let liba = archive(&ar, &dir, "a", &a_o);
    let libb = archive(&ar, &dir, "b", &b_o);

    // `pmain.o -L<dir> -lb <liba.a>`: command order is pmain, libb, liba.
    // libb is searched first, so foo() returns 2.
    let link_and_run = |args: &[&std::ffi::OsStr]| -> i32 {
        let out = dir.join("out");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_afs-ld"));
        cmd.arg("-o").arg(&out).args(args);
        let r = cmd.output().unwrap();
        assert!(r.status.success(), "afs-ld: {}", String::from_utf8_lossy(&r.stderr));
        Command::new(&out).status().unwrap().code().unwrap()
    };

    use std::ffi::OsStr;
    let ldir = OsStr::new("-L");
    let dir_os = dir.as_os_str();

    // libb first (via -lb), liba second (positional) => foo == 2.
    let code_b_first = link_and_run(&[
        pmain_o.as_os_str(),
        ldir,
        dir_os,
        OsStr::new("-lb"),
        liba.as_os_str(),
    ]);
    assert_eq!(code_b_first, 2, "libb precedes liba on the command line, so its foo wins");

    // liba first (via -la), libb second (positional) => foo == 1.
    let code_a_first = link_and_run(&[
        pmain_o.as_os_str(),
        ldir,
        dir_os,
        OsStr::new("-la"),
        libb.as_os_str(),
    ]);
    assert_eq!(code_a_first, 1, "liba precedes libb on the command line, so its foo wins");

    let _ = std::fs::remove_dir_all(&dir);
}
