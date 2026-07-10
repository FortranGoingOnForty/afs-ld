//! Audit L7: a GOTPCREL relocation against a linker-defined symbol
//! (`_end`, `__bss_start`, …) must link, not panic. The GOT slot for such a
//! symbol carries the `(LINKER_MARK, idx)` sentinel; `sym_vaddr` re-ran the
//! reference resolver on it, indexing `objects[LINKER_MARK]` (usize::MAX) and
//! panicking with index-out-of-bounds.

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
fn gotpcrel_against_linker_defined_end_links_and_runs() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_gotpcrel_linker_sym test=gotpcrel_against_linker_defined_end_links_and_runs count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_gotpcrel_lsym_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // Load &_end through the GOT, then exit 42. The GOTPCREL against the
    // linker-defined `_end` is the case that used to panic the linker.
    let exit_syscall = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let asm = format!(
        ".text\n.globl _start\n.type _start,@function\n_start:\n    movq _end@GOTPCREL(%rip), %rax\n    movl $42, %edi\n    movl ${exit_syscall}, %eax\n    syscall\n.size _start,.-_start\n"
    );
    let s = dir.join("g.s");
    let obj = dir.join("g.o");
    std::fs::write(&s, asm).unwrap();
    let out = Command::new(&gas)
        .args(["--64", "-o"])
        .arg(&obj)
        .arg(&s)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "gas: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bin = dir.join("g_afsld");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&bin)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld must link a GOTPCREL against _end, not panic: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let run = Command::new(&bin).status().unwrap();
    assert_eq!(run.code(), Some(42), "linked binary should exit 42");

    let _ = std::fs::remove_dir_all(&dir);
}
