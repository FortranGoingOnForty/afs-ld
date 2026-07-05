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

    // The full bespoke chain: the same source assembled by afs-as
    // (sibling binary in the workspace target dir; crate independence
    // preserved — we shell out, never link against it), then linked
    // by afs-ld. Skip only when the sibling isn't built.
    let afs_as = ["../target/debug/afs-as", "target/debug/afs-as"]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists());
    if let Some(afs_as) = afs_as {
        let obj2 = dir.join("x_afsas.o");
        let r = Command::new(&afs_as)
            .args(["--64", "-o"])
            .arg(&obj2)
            .arg(&s)
            .output()
            .unwrap();
        assert!(
            r.status.success(),
            "afs-as: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        let ours3 = dir.join("x_allbespoke");
        let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-o")
            .arg(&ours3)
            .arg(&obj2)
            .output()
            .unwrap();
        assert!(
            r.status.success(),
            "afs-ld on afs-as object: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        let run = Command::new(&ours3).output().unwrap();
        assert_eq!(run.status.code(), Some(42), "all-bespoke binary exit code");
    } else {
        eprintln!("skipping: afs-as sibling binary not built (all-bespoke leg)");
    }

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

    // `-pie` is a dynamic-link request — rung 3, must be rejected loudly.
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["-pie", "-o"])
        .arg(dir.join("y_out"))
        .arg(&obj)
        .output()
        .unwrap();
    assert!(!r.status.success());
    let stderr = String::from_utf8_lossy(&r.stderr);
    assert!(stderr.contains("rung 3"), "must name the rung: {}", stderr);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Assemble `src` with gas into `obj`. Panics on failure.
fn assemble(gas: &std::path::Path, src: &str, s: &std::path::Path, obj: &std::path::Path) {
    std::fs::write(s, src).unwrap();
    let out = Command::new(gas)
        .args(["--64", "-o"])
        .arg(obj)
        .arg(s)
        .output()
        .unwrap();
    assert!(out.status.success(), "gas: {}", String::from_utf8_lossy(&out.stderr));
}

/// Archive selection is lazy: only members that satisfy an undefined
/// symbol are pulled. The archive carries a poison member that
/// references a never-defined strong symbol; a correct linker never
/// pulls it, so the link succeeds and the binary exits with the value
/// returned by the one member it did pull.
#[test]
fn archive_member_selection_links_only_used_members() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=archive_member_selection_links_only_used_members count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    // `ar` is needed to build the archive + symbol index.
    let ar = ["/usr/bin/ar", "/usr/local/bin/ar"]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists());
    let Some(ar) = ar else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=archive_member_selection_links_only_used_members count=1 reason=\"no ar on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_arsel_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    // main.o: exit(answer()).
    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n_start:\n    call answer\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"
        ),
        &dir.join("main.s"),
        &main_obj,
    );
    // used.o: answer() -> 42.
    let used_obj = dir.join("used.o");
    assemble(
        &gas,
        ".text\n.globl answer\nanswer:\n    movl $42, %eax\n    ret\n",
        &dir.join("used.s"),
        &used_obj,
    );
    // poison.o: defines an unused symbol but references a strong symbol
    // that nothing defines. Pulling it in would fail the link.
    let poison_obj = dir.join("poison.o");
    assemble(
        &gas,
        ".text\n.globl unused_sym\nunused_sym:\n    call nonexistent_dependency\n    ret\n",
        &dir.join("poison.s"),
        &poison_obj,
    );

    // Archive both library members (order: poison first, so a naive
    // linker that loads every member would hit the poison immediately).
    let archive = dir.join("libstuff.a");
    let _ = std::fs::remove_file(&archive);
    let r = Command::new(&ar)
        .arg("rcs")
        .arg(&archive)
        .arg(&poison_obj)
        .arg(&used_obj)
        .output()
        .unwrap();
    assert!(r.status.success(), "ar: {}", String::from_utf8_lossy(&r.stderr));

    // Positional-archive form: main.o libstuff.a.
    let out1 = dir.join("sel_positional");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&out1)
        .arg(&main_obj)
        .arg(&archive)
        .output()
        .unwrap();
    assert!(r.status.success(), "afs-ld positional archive: {}", String::from_utf8_lossy(&r.stderr));
    assert_eq!(Command::new(&out1).output().unwrap().status.code(), Some(42));

    // `-L <dir> -l stuff` form resolves the same archive by name.
    let out2 = dir.join("sel_dashl");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&out2)
        .arg(&main_obj)
        .arg("-L")
        .arg(&dir)
        .arg("-lstuff")
        .output()
        .unwrap();
    assert!(r.status.success(), "afs-ld -l form: {}", String::from_utf8_lossy(&r.stderr));
    assert_eq!(Command::new(&out2).output().unwrap().status.code(), Some(42));

    // Both forms are byte-identical (determinism + form equivalence).
    assert_eq!(std::fs::read(&out1).unwrap(), std::fs::read(&out2).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}
