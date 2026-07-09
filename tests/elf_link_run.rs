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
    assert!(
        out.status.success(),
        "gas: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // afs-ld link + run.
    let ours = dir.join("x_afsld");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&ours)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld: {}",
        String::from_utf8_lossy(&r.stderr)
    );
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
        let r = Command::new(ld)
            .arg("-o")
            .arg(&theirs)
            .arg(&obj)
            .output()
            .unwrap();
        assert!(
            r.status.success(),
            "{}: {}",
            ld,
            String::from_utf8_lossy(&r.stderr)
        );
        let run = Command::new(&theirs).output().unwrap();
        assert_eq!(run.status.code(), Some(42), "{} binary exit code", ld);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn static_ehdr_start_resolves_to_image_base() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=static_ehdr_start_resolves_to_image_base count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_ehdr_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let obj = dir.join("ehdr.o");
    assemble(
        &gas,
        &format!(".text\n.globl _start\n_start:\n    leaq __ehdr_start(%rip), %rax\n    movl $42, %edi\n    cmpq $0x400000, %rax\n    je 1f\n    movl $7, %edi\n1:  movl ${exit_nr}, %eax\n    syscall\n"),
        &dir.join("ehdr.s"),
        &obj,
    );
    let out = dir.join("ehdr");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&out)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(Command::new(&out).output().unwrap().status.code(), Some(42));
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
    assert!(Command::new(&gas)
        .args(["--64", "-o"])
        .arg(&obj)
        .arg(&s)
        .output()
        .unwrap()
        .status
        .success());

    // `-pie` is not yet supported (PIE lands in a later rung); reject loudly.
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["-pie", "-o"])
        .arg(dir.join("y_out"))
        .arg(&obj)
        .output()
        .unwrap();
    assert!(!r.status.success());
    let stderr = String::from_utf8_lossy(&r.stderr);
    assert!(
        stderr.contains("-pie") && stderr.contains("does not support"),
        "must name the unsupported flag: {}",
        stderr
    );

    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--gc-sections", "-o"])
        .arg(dir.join("gc_out"))
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "--gc-sections is part of the ELF driver contract: {}",
        String::from_utf8_lossy(&r.stderr)
    );
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
    assert!(
        out.status.success(),
        "gas: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// IFUNC: a `call` to an STT_GNU_IFUNC symbol routes through a
/// synthesized IPLT stub whose GOT.PLT slot is filled by the
/// R_X86_64_IRELATIVE table between __rela_iplt_start/end. The program
/// applies that table itself (as the static csu would), then calls the
/// ifunc, which resolves to an impl returning 42.
#[test]
fn ifunc_resolves_through_iplt_and_irelative() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=ifunc_resolves_through_iplt_and_irelative count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_ifunc_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let obj = dir.join("if.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n_start:\n    leaq __rela_iplt_start(%rip), %rbx\n    leaq __rela_iplt_end(%rip), %r12\n1:  cmpq %r12, %rbx\n    jae 2f\n    movq (%rbx), %r13\n    movq 16(%rbx), %rax\n    call *%rax\n    movq %rax, (%r13)\n    addq $24, %rbx\n    jmp 1b\n2:  call myfunc\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n.globl myfunc\n.type myfunc, @gnu_indirect_function\nmyfunc:\n    leaq impl(%rip), %rax\n    ret\nimpl:\n    movl $42, %eax\n    ret\n"
        ),
        &dir.join("if.s"),
        &obj,
    );
    let out = dir.join("if");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&out)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(Command::new(&out).output().unwrap().status.code(), Some(42));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Init-array bracketing and priority: __init_array_start/end cover
/// every .init_array contribution, ordered by numeric priority
/// (.init_array.00100 before the default .init_array). The program runs
/// the constructors itself: ctor@100 sets 2, default ctor adds 40 -> 42.
#[test]
fn init_array_priority_merge_and_brackets() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=init_array_priority_merge_and_brackets count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_ia_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let obj = dir.join("ia.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n_start:\n    leaq __init_array_start(%rip), %rbx\n    leaq __init_array_end(%rip), %r12\n1:  cmpq %r12, %rbx\n    jae 2f\n    call *(%rbx)\n    addq $8, %rbx\n    jmp 1b\n2:  movl code(%rip), %edi\n    movl ${exit_nr}, %eax\n    syscall\nctor2:\n    movl $2, code(%rip)\n    ret\nctor40:\n    addl $40, code(%rip)\n    ret\n.section .init_array.00100,\"aw\"\n    .quad ctor2\n.section .init_array,\"aw\"\n    .quad ctor40\n.data\ncode: .long 0\n"
        ),
        &dir.join("ia.s"),
        &obj,
    );
    let out = dir.join("ia");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&out)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(Command::new(&out).output().unwrap().status.code(), Some(42));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Symbol versioning: an archive whose only definitions of `real_answer`
/// carry version suffixes (`real_answer@@VERS_2.0`, `@VERS_1.0`) still
/// satisfies a plain `real_answer` reference — the default (`@@`) version
/// answers the base name, both in archive selection and resolution.
#[test]
fn versioned_symbol_answers_plain_reference() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=versioned_symbol_answers_plain_reference count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let ar = ["/usr/bin/ar", "/usr/local/bin/ar"]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists());
    let Some(ar) = ar else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=versioned_symbol_answers_plain_reference count=1 reason=\"no ar on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_ver_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let impl_obj = dir.join("impl.o");
    assemble(
        &gas,
        ".text\n.globl real_answer_impl\nreal_answer_impl:\n    movl $42, %eax\n    ret\n.symver real_answer_impl, real_answer@@VERS_2.0\n.symver real_answer_impl, real_answer@VERS_1.0\n",
        &dir.join("impl.s"),
        &impl_obj,
    );
    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(".text\n.globl _start\n_start:\n    call real_answer\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"),
        &dir.join("main.s"),
        &main_obj,
    );
    let archive = dir.join("libimpl.a");
    let _ = std::fs::remove_file(&archive);
    assert!(Command::new(&ar)
        .arg("rcs")
        .arg(&archive)
        .arg(&impl_obj)
        .output()
        .unwrap()
        .status
        .success());
    let out = dir.join("ver");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&out)
        .arg(&main_obj)
        .arg(&archive)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(Command::new(&out).output().unwrap().status.code(), Some(42));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Prologue that installs a thread pointer so freestanding TLS accesses
/// work: TP = &tcb+64 with a TCB self-pointer at [TP], then the
/// per-OS set-fsbase syscall. `%r15` holds TP on return.
fn tls_prologue() -> &'static str {
    if cfg!(target_os = "freebsd") {
        // sysarch(AMD64_SET_FSBASE=129, &tp); SYS_sysarch=165.
        "    leaq tcb(%rip), %r15\n    addq $64, %r15\n    movq %r15, (%r15)\n    movq %r15, -8(%rsp)\n    leaq -8(%rsp), %rsi\n    movq $129, %rdi\n    movq $165, %rax\n    syscall\n"
    } else {
        // arch_prctl(ARCH_SET_FS=0x1002, tp); syscall 158.
        "    leaq tcb(%rip), %r15\n    addq $64, %r15\n    movq %r15, (%r15)\n    movq %r15, %rsi\n    movq $0x1002, %rdi\n    movq $158, %rax\n    syscall\n"
    }
}

/// `.tdata tvar=0` + a 128-byte `tcb` scratch buffer, the fixture the
/// TLS prologue relies on.
const TLS_FIXTURE: &str = ".section .tdata,\"awT\",@progbits\n.globl tvar\ntvar: .long 0\n.bss\n.globl tcb\ntcb: .zero 128\n";

/// TLS local-exec (TPOFF32) store and initial-exec (GOTTPOFF) load hit
/// the same thread-local: store 42 via `%fs:tvar@tpoff`, read it back
/// through the GOT, exit with the value.
#[test]
fn tls_local_exec_and_initial_exec_read_back() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=tls_local_exec_and_initial_exec_read_back count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_tls_ie_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let obj = dir.join("t.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n_start:\n{}    movl $42, %fs:tvar@tpoff\n    movq tvar@gottpoff(%rip), %rax\n    movl %fs:(%rax), %edi\n    movl ${exit_nr}, %eax\n    syscall\n{}",
            tls_prologue(),
            TLS_FIXTURE
        ),
        &dir.join("t.s"),
        &obj,
    );
    let out = dir.join("t");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&out)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(Command::new(&out).output().unwrap().status.code(), Some(42));
    // Behavioral parity with the reference static linker, if present.
    for ld in ["/usr/bin/ld", "/usr/local/bin/ld"] {
        if !std::path::Path::new(ld).exists() {
            continue;
        }
        let theirs = dir.join(format!("t_{}", ld.replace('/', "_")));
        if Command::new(ld)
            .args(["-static", "-o"])
            .arg(&theirs)
            .arg(&obj)
            .output()
            .unwrap()
            .status
            .success()
        {
            assert_eq!(
                Command::new(&theirs).output().unwrap().status.code(),
                Some(42),
                "{ld} static TLS"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// TLS general-dynamic (TLSGD) and local-dynamic (TLSLD+DTPOFF32) call
/// sequences relax to local-exec in place — no `__tls_get_addr` needed.
/// Each computes &tvar, stores 42, reads it back.
#[test]
fn tls_general_and_local_dynamic_relax_to_local_exec() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=tls_general_and_local_dynamic_relax_to_local_exec count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_tls_gd_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    // General dynamic.
    let gd = dir.join("gd.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n_start:\n{}    .byte 0x66\n    leaq tvar@tlsgd(%rip), %rdi\n    .value 0x6666\n    rex64\n    call __tls_get_addr@plt\n    movl $42, (%rax)\n    movl (%rax), %edi\n    movl ${exit_nr}, %eax\n    syscall\n{}",
            tls_prologue(), TLS_FIXTURE
        ),
        &dir.join("gd.s"),
        &gd,
    );
    let gd_out = dir.join("gd");
    assert!(Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&gd_out)
        .arg(&gd)
        .output()
        .unwrap()
        .status
        .success());
    assert_eq!(
        Command::new(&gd_out).output().unwrap().status.code(),
        Some(42),
        "GD relax"
    );

    // Local dynamic.
    let ld = dir.join("ld.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n_start:\n{}    leaq tvar@tlsld(%rip), %rdi\n    call __tls_get_addr@plt\n    leaq tvar@dtpoff(%rax), %rax\n    movl $42, (%rax)\n    movl (%rax), %edi\n    movl ${exit_nr}, %eax\n    syscall\n{}",
            tls_prologue(), TLS_FIXTURE
        ),
        &dir.join("ld.s"),
        &ld,
    );
    let ld_out = dir.join("ld");
    assert!(Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&ld_out)
        .arg(&ld)
        .output()
        .unwrap()
        .status
        .success());
    assert_eq!(
        Command::new(&ld_out).output().unwrap().status.code(),
        Some(42),
        "LD relax"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// GOT synthesis: a `foo@GOTPCREL` load resolves through a synthesized
/// `.got` slot holding foo's final address, and an unsatisfied *weak*
/// GOTPCREL reference reads back 0. The program exits 42 only when both
/// hold.
#[test]
fn gotpcrel_loads_through_synthesized_got() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=gotpcrel_loads_through_synthesized_got count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_got_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let obj = dir.join("g.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n.weak missing\n_start:\n    movq missing@GOTPCREL(%rip), %rax\n    cmpq $0, %rax\n    jne 1f\n    movq val@GOTPCREL(%rip), %rax\n    movl (%rax), %edi\n    jmp 2f\n1:  movl $7, %edi\n2:  movl ${exit_nr}, %eax\n    syscall\n.data\n.globl val\nval:\n    .long 42\n"
        ),
        &dir.join("g.s"),
        &obj,
    );
    let out = dir.join("g");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&out)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(Command::new(&out).output().unwrap().status.code(), Some(42));

    // Determinism.
    let out2 = dir.join("g2");
    assert!(Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&out2)
        .arg(&obj)
        .output()
        .unwrap()
        .status
        .success());
    assert_eq!(std::fs::read(&out).unwrap(), std::fs::read(&out2).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
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
    assert!(
        r.status.success(),
        "ar: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    // Positional-archive form: main.o libstuff.a.
    let out1 = dir.join("sel_positional");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&out1)
        .arg(&main_obj)
        .arg(&archive)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld positional archive: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(
        Command::new(&out1).output().unwrap().status.code(),
        Some(42)
    );

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
    assert!(
        r.status.success(),
        "afs-ld -l form: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(
        Command::new(&out2).output().unwrap().status.code(),
        Some(42)
    );

    // Both forms are byte-identical (determinism + form equivalence).
    assert_eq!(std::fs::read(&out1).unwrap(), std::fs::read(&out2).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The FreeBSD C startup objects and shared libc, when all present.
fn freebsd_crt_libc() -> Option<(PathBuf, PathBuf, PathBuf, PathBuf)> {
    if !cfg!(target_os = "freebsd") {
        return None;
    }
    let paths = [
        PathBuf::from("/usr/lib/crt1.o"),
        PathBuf::from("/usr/lib/crti.o"),
        PathBuf::from("/usr/lib/crtn.o"),
        PathBuf::from("/lib/libc.so.7"),
    ];
    if paths.iter().all(|p| p.exists()) {
        let [a, b, c, d] = paths;
        Some((a, b, c, d))
    } else {
        None
    }
}

/// Full dynamic executable against the real system libc: afs-ld links
/// crt1/crti + a `main` that calls `write@plt` + libc.so.7 + crtn into a
/// running program. This exercises the whole 3d stack — the C startup
/// drives `main` via `__libc_start1`, the exe exports `environ`/
/// `__progname` back to libc, and `write` binds through a versioned PLT
/// slot. Output, determinism, and behavioral parity with the system
/// linker are all checked. FreeBSD-scoped; skips where the crt/libc
/// layout differs.
#[test]
fn dynamic_hello_links_against_system_libc() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_hello_links_against_system_libc count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some((crt1, crti, crtn, libc)) = freebsd_crt_libc() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_hello_links_against_system_libc count=1 reason=\"no FreeBSD crt/libc.so.7 layout on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_hello_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // main() { write(1, "hello afs-ld\n", 13); return 0; }
    let main_obj = dir.join("hi.o");
    assemble(
        &gas,
        ".text\n.globl main\n.type main,@function\nmain:\n    pushq %rbp\n    movq %rsp, %rbp\n    leaq msg(%rip), %rsi\n    movl $1, %edi\n    movl $13, %edx\n    call write@plt\n    xorl %eax, %eax\n    popq %rbp\n    ret\n.section .rodata\nmsg:\n    .ascii \"hello afs-ld\\n\"\n",
        &dir.join("hi.s"),
        &main_obj,
    );

    let link = |out: &std::path::Path, linker: &str| -> std::process::Output {
        Command::new(linker)
            .args(["--dynamic-linker", "/libexec/ld-elf.so.1", "-o"])
            .arg(out)
            .arg(&crt1)
            .arg(&crti)
            .arg(&main_obj)
            .arg(&libc)
            .arg(&crtn)
            .output()
            .unwrap()
    };

    let out = dir.join("hi");
    let r = link(&out, env!("CARGO_BIN_EXE_afs-ld"));
    assert!(
        r.status.success(),
        "afs-ld dynamic hello: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let run = Command::new(&out).output().unwrap();
    assert_eq!(
        run.status.code(),
        Some(0),
        "hello exit: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&run.stdout),
        "hello afs-ld\n",
        "hello stdout"
    );

    // Determinism.
    let out2 = dir.join("hi2");
    assert!(link(&out2, env!("CARGO_BIN_EXE_afs-ld")).status.success());
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(&out2).unwrap(),
        "dynamic hello must be deterministic"
    );

    // Behavioral parity with the system linker, if present.
    for ld in ["/usr/bin/ld", "/usr/local/bin/ld"] {
        if !std::path::Path::new(ld).exists() {
            continue;
        }
        let theirs = dir.join(format!("hi_{}", ld.replace('/', "_")));
        if link(&theirs, ld).status.success() {
            let run = Command::new(&theirs).output().unwrap();
            assert_eq!(run.status.code(), Some(0), "{ld} hello exit");
            assert_eq!(
                String::from_utf8_lossy(&run.stdout),
                "hello afs-ld\n",
                "{ld} hello stdout"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Data import through the GOT: afs-ld links against a `.so` exporting a
/// function `base()`->40 and a data object `extra`=2. `main` calls
/// `base@plt` (JUMP_SLOT) and reads `extra@GOTPCREL` (GLOB_DAT via .got +
/// .rela.dyn); the loader must resolve both for the program to exit 42.
/// A *direct* (non-GOT) reference to shared data is out of scope and must
/// fail loudly (it needs a COPY relocation).
#[test]
fn dynamic_data_import_binds_through_got_glob_dat() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_data_import_binds_through_got_glob_dat count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(ld) = system_ld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_data_import_binds_through_got_glob_dat count=1 reason=\"no system ld to build the reference .so\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_data_import_binds_through_got_glob_dat count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_globdat_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    // Reference .so: function base()->40, data object extra=2.
    let lib_obj = dir.join("lib.o");
    assemble(
        &gas,
        ".text\n.globl base\n.type base,@function\nbase:\n    movl $40, %eax\n    ret\n.data\n.globl extra\n.type extra,@object\n.size extra,4\nextra:\n    .long 2\n",
        &dir.join("lib.s"),
        &lib_obj,
    );
    let so = dir.join("libboth.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "libboth.so.1", "-o"])
        .arg(&so)
        .arg(&lib_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "ld -shared: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    // main.o: exit(base() + extra) = 42. base via PLT, extra via GOT.
    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(".text\n.globl _start\n_start:\n    call base@plt\n    movq extra@GOTPCREL(%rip), %rcx\n    addl (%rcx), %eax\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"),
        &dir.join("main.s"),
        &main_obj,
    );
    let out = dir.join("both");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&out)
        .arg(&main_obj)
        .arg(&so)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld func+data dynamic: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let run = Command::new(&out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(42),
        "func+data exe exit: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    // Determinism.
    let out2 = dir.join("both2");
    assert!(Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&out2)
        .arg(&main_obj)
        .arg(&so)
        .output()
        .unwrap()
        .status
        .success());
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(&out2).unwrap(),
        "func+data link must be deterministic"
    );

    // A direct (non-GOT) reference to shared data needs a COPY relocation
    // — out of scope, must fail loudly naming COPY.
    let direct_obj = dir.join("direct.o");
    assemble(
        &gas,
        &format!(".text\n.globl _start\n_start:\n    movl extra(%rip), %edi\n    movl ${exit_nr}, %eax\n    syscall\n"),
        &dir.join("direct.s"),
        &direct_obj,
    );
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(dir.join("direct_out"))
        .arg(&direct_obj)
        .arg(&so)
        .output()
        .unwrap();
    assert!(
        !r.status.success(),
        "direct data reference must fail (needs COPY)"
    );
    assert!(
        String::from_utf8_lossy(&r.stderr).contains("COPY"),
        "error must name the COPY relocation: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Versioned dynamic import: afs-ld links against a `.so` that exports
/// `answer@@VERS_2.0` (default) and `answer@VERS_1.0`. A plain `answer`
/// reference binds to the default; the exe must *declare* it needs
/// VERS_2.0 (a `.gnu.version_r` entry naming the version), not just bind
/// and run — that declaration is what keeps the binding stable when the
/// library later adds a newer default. Structural check: the version
/// string lands in the afs-ld output (rung-3a output never carried it).
#[test]
fn versioned_dynamic_import_declares_and_binds_default_version() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=versioned_dynamic_import_declares_and_binds_default_version count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(ld) = system_ld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=versioned_dynamic_import_declares_and_binds_default_version count=1 reason=\"no system ld to build the reference .so\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=versioned_dynamic_import_declares_and_binds_default_version count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_ver_dyn_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    // Reference .so: answer@@VERS_2.0 -> 42 (default), answer@VERS_1.0 -> 7.
    let lib_obj = dir.join("lib.o");
    assemble(
        &gas,
        ".text\n.globl answer_v2\n.type answer_v2,@function\nanswer_v2:\n    movl $42, %eax\n    ret\n.globl answer_v1\n.type answer_v1,@function\nanswer_v1:\n    movl $7, %eax\n    ret\n.symver answer_v2, answer@@VERS_2.0\n.symver answer_v1, answer@VERS_1.0\n",
        &dir.join("lib.s"),
        &lib_obj,
    );
    let vmap = dir.join("ver.map");
    std::fs::write(
        &vmap,
        "VERS_1.0 { global: answer; };\nVERS_2.0 { global: answer; } VERS_1.0;\n",
    )
    .unwrap();
    let so = dir.join("libver.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "libver.so.1", "--version-script"])
        .arg(&vmap)
        .arg("-o")
        .arg(&so)
        .arg(&lib_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "ld -shared --version-script: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    // main.o: exit(answer()) — plain reference binds the default version.
    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(".text\n.globl _start\n_start:\n    call answer@plt\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"),
        &dir.join("main.s"),
        &main_obj,
    );

    let out = dir.join("ver_dyn");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&out)
        .arg(&main_obj)
        .arg(&so)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld versioned dynamic: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    // Structural: the required version string is present in the output
    // (it reaches .dynstr only via the VERNEED path — rung-3a never
    // emitted it).
    let bytes = std::fs::read(&out).unwrap();
    assert!(
        bytes.windows(8).any(|w| w == b"VERS_2.0"),
        "exe must declare the required version VERS_2.0 (VERNEED)"
    );

    // Behavioral: binds the default (VERS_2.0 -> 42), not VERS_1.0 -> 7.
    let run = Command::new(&out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(42),
        "versioned exe exit: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    // Determinism.
    let out2 = dir.join("ver_dyn2");
    assert!(Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&out2)
        .arg(&main_obj)
        .arg(&so)
        .output()
        .unwrap()
        .status
        .success());
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(&out2).unwrap(),
        "versioned link must be deterministic"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// System `ld`, if present, for building the reference shared object.
/// Probes the usual FHS spots and then bare `ld` on PATH (NixOS keeps it
/// in the current-system profile, not /usr/bin).
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

/// The runtime dynamic loader for this OS, or None when its path is
/// nonstandard (e.g. NixOS) — the dynamic-run legs skip in that case.
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

/// Dynamic executable: afs-ld links a freestanding `_start` that calls
/// `answer()` from a shared object through the PLT. The output carries
/// PT_INTERP, a PT_DYNAMIC with DT_NEEDED=libanswer.so.1, and one
/// R_X86_64_JUMP_SLOT; the runtime loader binds it and the program exits
/// 42. Both the positional-`.so` and `-lanswer` input forms are exercised
/// and must produce byte-identical output.
#[test]
fn dynamic_executable_calls_shared_answer_through_plt() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_executable_calls_shared_answer_through_plt count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(ld) = system_ld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_executable_calls_shared_answer_through_plt count=1 reason=\"no system ld to build the reference .so\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_executable_calls_shared_answer_through_plt count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_dyn_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    // Reference shared object: answer() -> 42, soname libanswer.so.1.
    let answer_obj = dir.join("answer.o");
    assemble(
        &gas,
        ".text\n.globl answer\n.type answer,@function\nanswer:\n    movl $42, %eax\n    ret\n",
        &dir.join("answer.s"),
        &answer_obj,
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
    // Dev symlink libanswer.so -> libanswer.so.1 for the -lanswer form.
    let so_link = dir.join("libanswer.so");
    let _ = std::fs::remove_file(&so_link);
    #[cfg(unix)]
    std::os::unix::fs::symlink("libanswer.so.1", &so_link).unwrap();

    // main.o: exit(answer()) with answer imported through the PLT.
    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n_start:\n    call answer@plt\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"
        ),
        &dir.join("main.s"),
        &main_obj,
    );

    // Positional-.so form.
    let out1 = dir.join("dyn_positional");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&out1)
        .arg(&main_obj)
        .arg(&so)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld dynamic positional: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    // `-L <dir> -lanswer` form resolves libanswer.so on the search path.
    let out2 = dir.join("dyn_dashl");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&out2)
        .arg(&main_obj)
        .arg("-L")
        .arg(&dir)
        .arg("-lanswer")
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld dynamic -l form: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    // Both input forms name the same DT_NEEDED (the soname), so the
    // linked images are byte-identical.
    assert_eq!(
        std::fs::read(&out1).unwrap(),
        std::fs::read(&out2).unwrap(),
        "positional and -l forms must link identically"
    );

    // Run under the loader: LD_LIBRARY_PATH points at the .so's dir so
    // the loader resolves DT_NEEDED=libanswer.so.1.
    let run = Command::new(&out1)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(42),
        "dynamic exe exit code: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    // Determinism: a fresh link is byte-identical.
    let out3 = dir.join("dyn_again");
    assert!(Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&out3)
        .arg(&main_obj)
        .arg(&so)
        .output()
        .unwrap()
        .status
        .success());
    assert_eq!(
        std::fs::read(&out1).unwrap(),
        std::fs::read(&out3).unwrap(),
        "dynamic link must be byte-deterministic"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Dynamic mode consumes the glibc-style inputs the driver emits:
/// `--gc-sections`, linker-script-expanded `.so` groups, positional
/// archive members, `-l` archive fallback, and linker-defined
/// `__ehdr_start`.
#[test]
fn dynamic_mode_expands_scripts_and_archive_fallbacks() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_mode_expands_scripts_and_archive_fallbacks count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(ld) = system_ld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_mode_expands_scripts_and_archive_fallbacks count=1 reason=\"no system ld to build the reference .so\"");
        return;
    };
    let ar = ["/usr/bin/ar", "/usr/local/bin/ar"]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists());
    let Some(ar) = ar else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_mode_expands_scripts_and_archive_fallbacks count=1 reason=\"no ar on this host\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_mode_expands_scripts_and_archive_fallbacks count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_dyn_script_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    let dyn_obj = dir.join("dyn.o");
    assemble(
        &gas,
        ".text\n.globl shared_answer\n.type shared_answer,@function\nshared_answer:\n    movl $40, %eax\n    ret\n",
        &dir.join("dyn.s"),
        &dyn_obj,
    );
    let so = dir.join("libdyn.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "libdyn.so.1", "-o"])
        .arg(&so)
        .arg(&dyn_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "ld -shared: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let static_obj = dir.join("static.o");
    assemble(
        &gas,
        ".text\n.globl static_answer\n.type static_answer,@function\nstatic_answer:\n    movl $2, %eax\n    ret\n",
        &dir.join("static.s"),
        &static_obj,
    );
    let archive = dir.join("libstatic.a");
    let _ = std::fs::remove_file(&archive);
    let r = Command::new(&ar)
        .arg("rcs")
        .arg(&archive)
        .arg(&static_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "ar: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(".text\n.globl _start\n_start:\n    leaq __ehdr_start(%rip), %rcx\n    cmpq $0x200000, %rcx\n    jne 1f\n    call shared_answer@plt\n    movl %eax, %ebx\n    call static_answer\n    addl %ebx, %eax\n    movl %eax, %edi\n    jmp 2f\n1:  movl $7, %edi\n2:  movl ${exit_nr}, %eax\n    syscall\n"),
        &dir.join("main.s"),
        &main_obj,
    );

    let script = dir.join("libcombo.so");
    std::fs::write(
        &script,
        "/* GNU ld script */\nGROUP ( libdyn.so.1 AS_NEEDED ( libstatic.a ) )\n",
    )
    .unwrap();

    let script_out = dir.join("script");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--gc-sections", "--dynamic-linker", interp, "-o"])
        .arg(&script_out)
        .arg(&main_obj)
        .arg("-L")
        .arg(&dir)
        .arg("-lcombo")
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld script group: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let run = Command::new(&script_out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(42),
        "script-expanded dynamic exe: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let fallback_out = dir.join("fallback");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&fallback_out)
        .arg(&main_obj)
        .arg("-L")
        .arg(&dir)
        .arg("-lstatic")
        .arg(&so)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld -l archive fallback: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let run = Command::new(&fallback_out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(42),
        "-l archive fallback dynamic exe: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The ELF64 program header for a given `p_type`, or None. Returns
/// `(p_offset, p_vaddr, p_filesz)`.
fn find_phdr(img: &[u8], p_type: u32) -> Option<(u64, u64, u64)> {
    let rd32 = |o: usize| u32::from_le_bytes(img[o..o + 4].try_into().unwrap());
    let rd16 = |o: usize| u16::from_le_bytes(img[o..o + 2].try_into().unwrap());
    let rd64 = |o: usize| u64::from_le_bytes(img[o..o + 8].try_into().unwrap());
    let phoff = rd64(32) as usize;
    let phentsize = rd16(54) as usize;
    let phnum = rd16(56) as usize;
    for i in 0..phnum {
        let e = phoff + i * phentsize;
        if rd32(e) == p_type {
            return Some((rd64(e + 8), rd64(e + 16), rd64(e + 32)));
        }
    }
    None
}

/// The `sh_addr` of a named ELF64 section, or None.
fn section_addr(img: &[u8], name: &str) -> Option<u64> {
    let rd16 = |o: usize| u16::from_le_bytes(img[o..o + 2].try_into().unwrap());
    let rd32 = |o: usize| u32::from_le_bytes(img[o..o + 4].try_into().unwrap());
    let rd64 = |o: usize| u64::from_le_bytes(img[o..o + 8].try_into().unwrap());
    let shoff = rd64(40) as usize;
    let shentsize = rd16(58) as usize;
    let shnum = rd16(60) as usize;
    let shstrndx = rd16(62) as usize;
    let shstr_off = rd64(shoff + shstrndx * shentsize + 24) as usize;
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let noff = shstr_off + rd32(sh) as usize;
        let end = img[noff..].iter().position(|&b| b == 0).unwrap();
        if &img[noff..noff + end] == name.as_bytes() {
            return Some(rd64(sh + 16));
        }
    }
    None
}

/// Audit T1: `--eh-frame-hdr` must synthesize `.eh_frame_hdr` +
/// PT_GNU_EH_FRAME (it used to be silently ignored), and its absence must
/// not (GNU semantics). The header's `eh_frame_ptr` must point at the
/// retained `.eh_frame`, and the binary must still run.
#[test]
fn eh_frame_hdr_emitted_only_when_requested() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=eh_frame_hdr_emitted_only_when_requested count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_ehframe_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    // _start wrapped in CFI so gas emits `.eh_frame` with an FDE for it.
    let asm = format!(
        ".text\n.globl _start\n.type _start,@function\n_start:\n    .cfi_startproc\n    movl $42, %edi\n    movl ${exit_nr}, %eax\n    syscall\n    .cfi_endproc\n.size _start,.-_start\n"
    );
    let s = dir.join("cfi.s");
    let obj = dir.join("cfi.o");
    assemble(&gas, &asm, &s, &obj);

    let link = |flag: bool, out: &std::path::Path| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_afs-ld"));
        if flag {
            c.arg("--eh-frame-hdr");
        }
        c.arg("-o").arg(out).arg(&obj).output().unwrap()
    };

    // With the flag: header present, table well-formed and pointing at
    // `.eh_frame`, one FDE, and the binary runs.
    let with = dir.join("with");
    assert!(link(true, &with).status.success());
    let img = std::fs::read(&with).unwrap();
    let (fo, va, fsz) =
        find_phdr(&img, 0x6474_e550).expect("PT_GNU_EH_FRAME must be present with --eh-frame-hdr");
    let hdr = &img[fo as usize..(fo + fsz) as usize];
    assert_eq!(&hdr[0..4], &[1, 0x1b, 0x03, 0x3b], "eh_frame_hdr encodings");
    let eh_ptr = i32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let eh_frame_va = (va as i64 + 4 + eh_ptr as i64) as u64;
    assert_eq!(
        eh_frame_va,
        section_addr(&img, ".eh_frame").expect(".eh_frame section"),
        "eh_frame_ptr must point at the retained .eh_frame"
    );
    assert_eq!(
        u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
        1,
        "one FDE for _start"
    );
    assert_eq!(
        Command::new(&with).output().unwrap().status.code(),
        Some(42)
    );

    // Without the flag: no header (GNU default), still runs.
    let without = dir.join("without");
    assert!(link(false, &without).status.success());
    let img2 = std::fs::read(&without).unwrap();
    assert!(
        find_phdr(&img2, 0x6474_e550).is_none(),
        "no PT_GNU_EH_FRAME without --eh-frame-hdr"
    );
    assert_eq!(
        Command::new(&without).output().unwrap().status.code(),
        Some(42)
    );

    let _ = std::fs::remove_dir_all(&dir);
}
