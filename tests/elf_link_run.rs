//! x16 rung 1: afs-ld links a freestanding ELF object; the binary
//! runs with the same exit code as system-linker builds, and afs-ld's
//! output is byte-deterministic across runs.

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

#[test]
fn freestanding_exit42_matches_system_linkers() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=freestanding_exit42_matches_system_linkers count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_run_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let asm = format!(
        ".text\n.globl _start\n.type _start,@function\n_start:\n    movl $42, %edi\n    movl ${}, %eax\n    syscall\n.size _start,.-_start\n.data\nmsg:\n    .quad _start\n",
        exit_nr
    );
    let s = dir.join("x.s");
    let obj = dir.join("x.o");
    std::fs::write(&s, asm).unwrap();
    let out = Command::new(&gas)
        .args(["--64", "-o"])
        .arg(&obj)
        .arg(&s)
        .output()
        .unwrap();
    assert!(out.status.success(), "gas: {}", String::from_utf8_lossy(&out.stderr));

    // afs-ld link + run.
    let ours = dir.join("x_afsld");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&ours)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(r.status.success(), "afs-ld: {}", String::from_utf8_lossy(&r.stderr));
    let run = Command::new(&ours).output().unwrap();
    assert_eq!(run.status.code(), Some(42), "afs-ld binary exit code");

    // Determinism: second link byte-identical.
    let ours2 = dir.join("x_afsld2");
    let r2 = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&ours2)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(r2.status.success());
    assert_eq!(
        std::fs::read(&ours).unwrap(),
        std::fs::read(&ours2).unwrap(),
        "afs-ld ELF output must be byte-deterministic"
    );

    // Behavioral parity with every available system linker.
    for ld in ["/usr/bin/ld", "/usr/local/bin/ld"] {
        if !std::path::Path::new(ld).exists() {
            continue;
        }
        let theirs = dir.join(format!("x_{}", ld.replace('/', "_")));
        let r = Command::new(ld).arg("-o").arg(&theirs).arg(&obj).output().unwrap();
        assert!(r.status.success(), "{}: {}", ld, String::from_utf8_lossy(&r.stderr));
        let run = Command::new(&theirs).output().unwrap();
        assert_eq!(run.status.code(), Some(42), "{} binary exit code", ld);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn elf_mode_rejects_unsupported_flags_loudly() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=elf_mode_rejects_unsupported_flags_loudly count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_flags_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let s = dir.join("y.s");
    let obj = dir.join("y.o");
    std::fs::write(&s, ".text\n.globl _start\n_start:\n    ret\n").unwrap();
    assert!(Command::new(&gas).args(["--64", "-o"]).arg(&obj).arg(&s).output().unwrap().status.success());

    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--eh-frame-hdr", "-o"])
        .arg(dir.join("y_out"))
        .arg(&obj)
        .output()
        .unwrap();
    assert!(!r.status.success());
    let stderr = String::from_utf8_lossy(&r.stderr);
    assert!(stderr.contains("rung 2"), "must name the rung: {}", stderr);
    let _ = std::fs::remove_dir_all(&dir);
}
