//! Audit L9: a static ET_EXEC must carry a non-executable PT_GNU_STACK marker
//! (its absence makes Linux grant an executable stack via READ_IMPLIES_EXEC)
//! and must brand EI_OSABI for the host it will run on — not for whatever OS
//! afs-ld happened to be compiled for. On this dev box afs-ld is sometimes a
//! Linux binary under the FreeBSD linuxulator, so a compile-time cfg would
//! misbrand a FreeBSD-hosted output.

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

fn ru16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn ru32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn ru64(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// The OSABI the output should carry: FreeBSD (9) on a FreeBSD host (the
/// FreeBSD rtld is present even under the linuxulator), else SysV (0). This
/// mirrors the linker's own runtime probe, so the test asserts the same
/// host-driven outcome without hard-coding a single platform.
fn expected_osabi() -> u8 {
    if std::path::Path::new("/libexec/ld-elf.so.1").exists() {
        9
    } else {
        0
    }
}

#[test]
fn static_exe_has_nonexec_gnu_stack_and_host_osabi() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_static_gnu_stack_osabi test=static_exe_has_nonexec_gnu_stack_and_host_osabi count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_gnustack_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let asm = format!(
        ".text\n.globl _start\n.type _start,@function\n_start:\n    movl $42, %edi\n    movl ${exit_nr}, %eax\n    syscall\n.size _start,.-_start\n"
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
    assert!(
        out.status.success(),
        "gas: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bin = dir.join("x_afsld");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&bin)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let elf = std::fs::read(&bin).unwrap();

    // EI_OSABI matches the host the binary will run on.
    assert_eq!(
        elf[7],
        expected_osabi(),
        "EI_OSABI must match the host, got {}",
        elf[7]
    );

    // Exactly one PT_GNU_STACK, RW and never executable.
    let phoff = ru64(&elf, 32) as usize;
    let phentsize = ru16(&elf, 54) as usize;
    let phnum = ru16(&elf, 56) as usize;
    let mut gnu_stack = 0;
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        if ru32(&elf, p) == PT_GNU_STACK {
            gnu_stack += 1;
            let flags = ru32(&elf, p + 4);
            assert_eq!(
                flags & PF_X,
                0,
                "PT_GNU_STACK must not be executable (flags={flags:#x})"
            );
            assert_eq!(
                flags,
                PF_R | PF_W,
                "PT_GNU_STACK should be RW (flags={flags:#x})"
            );
        }
    }
    assert_eq!(
        gnu_stack, 1,
        "static exe must carry exactly one PT_GNU_STACK marker"
    );

    // Adding the marker phdr must not have disturbed the layout: it still runs.
    let run = Command::new(&bin).status().unwrap();
    assert_eq!(run.code(), Some(42), "static exe should still exit 42");

    let _ = std::fs::remove_dir_all(&dir);
}
