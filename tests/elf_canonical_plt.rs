//! Audit L6: canonical PLT. When a non-PIE executable takes the *address* of
//! a function defined in a shared object (as opposed to calling it through the
//! PLT), the psABI ("Function Addresses") requires the import's `.dynsym`
//! entry to stay `SHN_UNDEF` but carry a non-zero `st_value` equal to the
//! executable's own PLT stub for that function. That is what gives `&func` one
//! identity on both sides of the `.so` boundary. afs-ld previously left
//! `st_value` at 0, so another library taking the same address would bind to a
//! different value than the executable's own reference.

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

fn system_ld() -> Option<PathBuf> {
    for p in ["/usr/bin/ld", "/usr/local/bin/ld"] {
        if std::path::Path::new(p).exists() {
            return Some(PathBuf::from(p));
        }
    }
    if let Ok(o) = Command::new("ld").arg("--version").output() {
        if o.status.success() {
            return Some(PathBuf::from("ld"));
        }
    }
    None
}

fn rtld() -> Option<&'static str> {
    let cands: &[&str] = if cfg!(target_os = "freebsd") {
        &["/libexec/ld-elf.so.1"]
    } else if cfg!(target_os = "linux") {
        &["/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-x86-64.so.2"]
    } else {
        &[]
    };
    cands
        .iter()
        .copied()
        .find(|p| std::path::Path::new(p).exists())
}

fn assemble(gas: &PathBuf, asm: &str, dir: &std::path::Path, name: &str) -> PathBuf {
    let s = dir.join(format!("{name}.s"));
    let o = dir.join(format!("{name}.o"));
    std::fs::write(&s, asm).unwrap();
    let out = Command::new(gas)
        .args(["--64", "-o"])
        .arg(&o)
        .arg(&s)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "gas {name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    o
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
fn cstr(b: &[u8], o: usize) -> String {
    let end = b[o..]
        .iter()
        .position(|&c| c == 0)
        .map(|p| o + p)
        .unwrap_or(b.len());
    String::from_utf8_lossy(&b[o..end]).into_owned()
}

/// (sh_addr, sh_offset, sh_size, sh_link, sh_entsize) of the first section
/// whose name matches `want`, from a linked ELF image.
fn find_section(elf: &[u8], want: &str) -> Option<(u64, u64, u64, u32, u64)> {
    let shoff = ru64(elf, 40) as usize;
    let shentsize = ru16(elf, 58) as usize;
    let shnum = ru16(elf, 60) as usize;
    let shstrndx = ru16(elf, 62) as usize;
    let sh = |i: usize| &elf[shoff + i * shentsize..shoff + (i + 1) * shentsize];
    let shstr_off = ru64(sh(shstrndx), 24) as usize;
    for i in 0..shnum {
        let h = sh(i);
        let name = cstr(elf, shstr_off + ru32(h, 0) as usize);
        if name == want {
            return Some((
                ru64(h, 16),
                ru64(h, 24),
                ru64(h, 32),
                ru32(h, 40),
                ru64(h, 56),
            ));
        }
    }
    None
}

/// st_shndx and st_value of the named symbol in `.dynsym`.
fn dynsym_entry(elf: &[u8], want: &str) -> Option<(u16, u64)> {
    let (_, dsoff, dssz, dslink, dsent) = find_section(elf, ".dynsym")?;
    // .dynsym's linked string table (its sh_link) holds the names.
    let shoff = ru64(elf, 40) as usize;
    let shentsize = ru16(elf, 58) as usize;
    let strh = &elf[shoff + dslink as usize * shentsize..];
    let stroff = ru64(strh, 24) as usize;
    let ent = dsent as usize;
    for k in 0..(dssz as usize) / ent {
        let e = dsoff as usize + k * ent;
        let nm = cstr(elf, stroff + ru32(elf, e) as usize);
        if nm == want {
            return Some((ru16(elf, e + 6), ru64(elf, e + 8)));
        }
    }
    None
}

#[test]
fn address_taken_shared_func_gets_canonical_plt_value() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_canonical_plt test=address_taken_shared_func_gets_canonical_plt_value count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(ld) = system_ld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_canonical_plt test=address_taken_shared_func_gets_canonical_plt_value count=1 reason=\"no system ld to build the reference .so\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_canonical_plt test=address_taken_shared_func_gets_canonical_plt_value count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_canon_plt_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    // Reference .so exporting answer() -> 42.
    let answer_obj = assemble(
        &gas,
        ".text\n.globl answer\n.type answer,@function\nanswer:\n    movl $42, %eax\n    ret\n",
        &dir,
        "answer",
    );
    let so = dir.join("libanswer.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "libanswer.so.1", "-o"])
        .arg(&so)
        .arg(&answer_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "ld -shared: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    // main.o takes the *address* of answer (`.quad answer` => R_X86_64_64, a
    // direct address-take, not `call answer@plt`) and calls through it. The
    // address-take is what must trigger the canonical PLT.
    let main_obj = assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n_start:\n    movq ptr(%rip), %rax\n    call *%rax\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n.data\nptr:\n    .quad answer\n"
        ),
        &dir,
        "main",
    );

    let out = dir.join("canon");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&out)
        .arg(&main_obj)
        .arg(&so)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    // Structural check: answer's .dynsym entry is UNDEF with st_value inside
    // the executable's .plt — the canonical-PLT signature.
    let elf = std::fs::read(&out).unwrap();
    let (plt_addr, _, plt_size, _, _) =
        find_section(&elf, ".plt").expect("linked exe must have a .plt");
    let (shndx, value) = dynsym_entry(&elf, "answer").expect("answer must be in .dynsym");
    assert_eq!(
        shndx, 0,
        "canonical-PLT import must stay SHN_UNDEF, got shndx={shndx}"
    );
    assert!(
        value != 0,
        "canonical-PLT import must carry a non-zero st_value"
    );
    assert!(
        value >= plt_addr && value < plt_addr + plt_size,
        "st_value {value:#x} must point into .plt [{plt_addr:#x}, {:#x})",
        plt_addr + plt_size
    );

    // End-to-end: calling through the taken address resolves to answer().
    let run = Command::new(&out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(42),
        "call through &answer must reach answer(): {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}
