//! x16 rung 1: afs-ld links a freestanding ELF object; the binary
//! runs with the same exit code as system-linker builds, and afs-ld's
//! output is byte-deterministic across runs.

use std::path::PathBuf;
use std::process::Command;

#[path = "common/artifacts.rs"]
mod artifacts;

use artifacts::workspace_binary;

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
    let afs_as = workspace_binary("afs-as");
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
fn common_symbols_allocate_zeroed_bss_in_static_and_dynamic_links() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=common_symbols_allocate_zeroed_bss_in_static_and_dynamic_links count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_common_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(
            ".comm shared,16,16\n\
             .text\n\
             .globl _start\n\
             .type _start,@function\n\
             _start:\n\
                 movl shared(%rip), %eax\n\
                 testl %eax, %eax\n\
                 jne 1f\n\
                 movl $42, shared(%rip)\n\
                 movl shared(%rip), %edi\n\
                 jmp 2f\n\
             1:  movl $7, %edi\n\
             2:  movl ${exit_nr}, %eax\n\
                 syscall\n\
             .size _start,.-_start\n"
        ),
        &dir.join("main.s"),
        &main_obj,
    );

    let static_out = dir.join("common_static");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(&static_out)
        .arg(&main_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld static COMMON: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let run = Command::new(&static_out).output().unwrap();
    assert_eq!(
        run.status.code(),
        Some(42),
        "static COMMON exe exit: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    if let Some(interp) = rtld() {
        let dynamic_out = dir.join("common_dynamic");
        let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .args(["--dynamic-linker", interp, "-o"])
            .arg(&dynamic_out)
            .arg(&main_obj)
            .output()
            .unwrap();
        assert!(
            r.status.success(),
            "afs-ld dynamic COMMON: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        let run = Command::new(&dynamic_out).output().unwrap();
        assert_eq!(
            run.status.code(),
            Some(42),
            "dynamic COMMON exe exit: {}",
            String::from_utf8_lossy(&run.stderr)
        );
    } else {
        eprintln!("skipping dynamic COMMON leg: no standard dynamic loader on this host");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn same_named_sections_preserve_distinct_flags_in_static_and_dynamic_links() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=same_named_sections_preserve_distinct_flags_in_static_and_dynamic_links count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_section_flags_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    let read_only_obj = dir.join("read-only.o");
    assemble(
        &gas,
        ".section .same,\"a\",@progbits\n.byte 0\n",
        &dir.join("read-only.s"),
        &read_only_obj,
    );
    let writable_obj = dir.join("writable.o");
    assemble(
        &gas,
        ".section .same,\"aw\",@progbits\n\
             .globl cell\n\
             .type cell,@object\n\
             cell: .long 0\n\
             .size cell,.-cell\n",
        &dir.join("writable.s"),
        &writable_obj,
    );
    let executable_obj = dir.join("executable.o");
    assemble(
        &gas,
        &format!(
            ".text\n\
             .globl _start\n\
             .type _start,@function\n\
             _start:\n\
                 call mixed_code\n\
                 movl %eax,%edi\n\
                 movl ${exit_nr},%eax\n\
                 syscall\n\
             .size _start,.-_start\n\
             .section .same,\"awx\",@progbits\n\
             .globl mixed_code\n\
             .type mixed_code,@function\n\
             mixed_code:\n\
                 movl $42,cell(%rip)\n\
                 movl $17,wx_cell(%rip)\n\
                 movl cell(%rip),%eax\n\
                 addl wx_cell(%rip),%eax\n\
                 subl $17,%eax\n\
                 ret\n\
             .size mixed_code,.-mixed_code\n\
             .p2align 2\n\
             wx_cell: .long 0\n"
        ),
        &dir.join("executable.s"),
        &executable_obj,
    );

    let link = |name: &str, dynamic_linker: Option<&str>| {
        let output = dir.join(name);
        let mut command = Command::new(env!("CARGO_BIN_EXE_afs-ld"));
        if let Some(interp) = dynamic_linker {
            command.args(["--dynamic-linker", interp]);
        }
        let result = command
            .arg("-o")
            .arg(&output)
            .arg(&read_only_obj)
            .arg(&writable_obj)
            .arg(&executable_obj)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "afs-ld {name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        output
    };

    let mut modes = vec![("static", None)];
    if let Some(interp) = rtld() {
        modes.push(("dynamic", Some(interp)));
    } else {
        eprintln!("skipping dynamic section-flags leg: no standard dynamic loader on this host");
    }

    for (name, interp) in modes {
        let output = link(name, interp);
        let image = std::fs::read(&output).unwrap();
        let mut flags = section_flags(&image, ".same");
        flags.sort_unstable();
        assert_eq!(
            flags,
            [0x2, 0x3, 0x7],
            "{name} output must retain each .same contribution's flags"
        );
        assert_eq!(
            Command::new(&output).output().unwrap().status.code(),
            Some(42),
            "{name} output must preserve writable and executable mappings"
        );

        let repeated = link(&format!("{name}-again"), interp);
        assert_eq!(image, std::fs::read(repeated).unwrap());
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

#[test]
fn gc_sections_discards_unreachable_static_sections() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=gc_sections_discards_unreachable_static_sections count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_gc_static_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let obj = dir.join("gc.o");
    assemble(
        &gas,
        &format!(
            ".section .text._start,\"ax\",@progbits\n\
             .globl _start\n\
             .type _start,@function\n\
             _start:\n\
                 .cfi_startproc\n\
                 call live\n\
                 movl %eax, %edi\n\
                 movl ${exit_nr}, %eax\n\
                 syscall\n\
                 .cfi_endproc\n\
             .section .text.dead,\"ax\",@progbits\n\
             .type dead,@function\n\
             dead:\n\
                 .cfi_startproc\n\
                 movl dead_data(%rip), %eax\n\
                 ret\n\
                 .cfi_endproc\n\
             .section .rodata.dead,\"a\",@progbits\n\
             dead_data: .asciz \"GC_DEAD_STATIC\"\n\
             .section .text.live,\"ax\",@progbits\n\
             .type live,@function\n\
             live:\n\
                 .cfi_startproc\n\
                 movl live_data(%rip), %eax\n\
                 ret\n\
                 .cfi_endproc\n\
             .section .rodata.live,\"a\",@progbits\n\
             live_data: .long 42\n"
        ),
        &dir.join("gc.s"),
        &obj,
    );

    let baseline = dir.join("baseline");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--gc-sections", "--no-gc-sections", "-o"])
        .arg(&baseline)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "baseline static link: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let baseline_image = std::fs::read(&baseline).unwrap();
    assert!(section_info(&baseline_image, ".text.dead").is_some());
    assert!(section_info(&baseline_image, ".rodata.dead").is_some());

    let collected = dir.join("collected");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--gc-sections", "--eh-frame-hdr", "-o"])
        .arg(&collected)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "GC static link: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let collected_image = std::fs::read(&collected).unwrap();
    for section in [".text._start", ".text.live", ".rodata.live"] {
        assert!(
            section_info(&collected_image, section).is_some(),
            "live section {section} was discarded"
        );
    }
    assert!(section_info(&collected_image, ".eh_frame").is_some());
    let (header_offset, _, header_size) = find_phdr(&collected_image, 0x6474_e550)
        .expect("GC must retain unwind metadata for live functions");
    let header = &collected_image[header_offset as usize..(header_offset + header_size) as usize];
    assert_eq!(
        u32::from_le_bytes(header[8..12].try_into().unwrap()),
        2,
        "only _start and live should retain FDEs"
    );
    for section in [".text.dead", ".rodata.dead"] {
        assert!(
            section_info(&collected_image, section).is_none(),
            "unreachable section {section} survived"
        );
    }
    assert_eq!(
        Command::new(&baseline).output().unwrap().status.code(),
        Some(42)
    );
    assert_eq!(
        Command::new(&collected).output().unwrap().status.code(),
        Some(42)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gc_sections_removes_dead_dynamic_import() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=gc_sections_removes_dead_dynamic_import count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(ld) = system_ld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=gc_sections_removes_dead_dynamic_import count=1 reason=\"no system ld to build the reference .so\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=gc_sections_removes_dead_dynamic_import count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_gc_dynamic_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    let live_obj = dir.join("live-import.o");
    assemble(
        &gas,
        ".text\n.globl live_import\n.type live_import,@function\nlive_import:\n    movl $42, %eax\n    ret\n",
        &dir.join("live-import.s"),
        &live_obj,
    );
    let live_so = dir.join("liblive.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "liblive.so.1", "-o"])
        .arg(&live_so)
        .arg(&live_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "ld -shared: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let dead_obj = dir.join("dead-import.o");
    assemble(
        &gas,
        ".text\n.globl live_import\n.type live_import,@function\nlive_import:\n    movl $99, %eax\n    ret\n.globl dead_import\n.type dead_import,@function\ndead_import:\n    movl $7, %eax\n    ret\n",
        &dir.join("dead-import.s"),
        &dead_obj,
    );
    let dead_so = dir.join("libdead.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "libdead.so.1", "-o"])
        .arg(&dead_so)
        .arg(&dead_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "ld -shared: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(
            ".section .text._start,\"ax\",@progbits\n\
             .globl _start\n\
             _start:\n\
                 call live_import@PLT\n\
                 movl %eax, %edi\n\
                 movl ${exit_nr}, %eax\n\
                 syscall\n\
             .section .text.dead,\"ax\",@progbits\n\
             dead:\n\
                 call dead_import@PLT\n\
                 ret\n"
        ),
        &dir.join("main.s"),
        &main_obj,
    );

    let link = |out: &std::path::Path, gc: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_afs-ld"));
        if gc {
            command.arg("--gc-sections");
        }
        command
            .args(["--dynamic-linker", interp, "--as-needed", "-o"])
            .arg(out)
            .arg(&main_obj)
            .arg(&live_so)
            .arg(&dead_so)
            .output()
            .unwrap()
    };
    let baseline = dir.join("baseline");
    let r = link(&baseline, false);
    assert!(
        r.status.success(),
        "baseline dynamic link: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let baseline_image = std::fs::read(&baseline).unwrap();
    assert!(section_info(&baseline_image, ".text.dead").is_some());
    assert_eq!(
        needed_libraries(&baseline_image),
        ["liblive.so.1", "libdead.so.1"]
    );

    let collected = dir.join("collected");
    let r = link(&collected, true);
    assert!(
        r.status.success(),
        "GC dynamic link: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let collected_image = std::fs::read(&collected).unwrap();
    assert!(section_info(&collected_image, ".text.dead").is_none());
    assert_eq!(needed_libraries(&collected_image), ["liblive.so.1"]);
    let dynstr = section_bytes(&collected_image, ".dynstr").unwrap();
    let has_dead_import = section_bytes(&collected_image, ".dynsym")
        .unwrap()
        .chunks_exact(24)
        .any(|symbol| {
            let offset = u32::from_le_bytes(symbol[0..4].try_into().unwrap()) as usize;
            let Some(length) = dynstr[offset..].iter().position(|&byte| byte == 0) else {
                return false;
            };
            &dynstr[offset..offset + length] == b"dead_import"
        });
    assert!(
        !has_dead_import,
        "a discarded reference created a dynamic import"
    );
    assert_eq!(
        Command::new(&baseline)
            .env("LD_LIBRARY_PATH", &dir)
            .output()
            .unwrap()
            .status
            .code(),
        Some(42)
    );
    assert_eq!(
        Command::new(&collected)
            .env("LD_LIBRARY_PATH", &dir)
            .output()
            .unwrap()
            .status
            .code(),
        Some(42)
    );

    let collected_again = dir.join("collected-again");
    assert!(link(&collected_again, true).status.success());
    assert_eq!(collected_image, std::fs::read(&collected_again).unwrap());
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
    let img = std::fs::read(&out).unwrap();
    let (_, section_type, _, _, size, align, entsize) =
        section_header_info(&img, ".init_array").expect("missing static .init_array");
    assert_eq!(section_type, 14);
    assert_eq!(size, 16);
    assert!(align >= 8);
    assert_eq!(entsize, 8);
    assert_eq!(Command::new(&out).output().unwrap().status.code(), Some(42));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dynamic_array_tags_drive_loader_initialization() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_array_tags_drive_loader_initialization count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_array_tags_drive_loader_initialization count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_array_tags_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let obj = dir.join("arrays.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n.type _start,@function\n_start:\n    movl code(%rip), %edi\n    movl ${exit_nr}, %eax\n    syscall\npreinit:\n    movl $2, code(%rip)\n    ret\ninit10:\n    addl $10, code(%rip)\n    ret\ninit30:\n    addl $30, code(%rip)\n    ret\nfini:\n    movl $99, code(%rip)\n    ret\n.section .preinit_array,\"aw\",@preinit_array\n    .quad preinit\n.section .init_array.00100,\"aw\",@init_array\n    .quad init10\n.section .init_array,\"aw\",@init_array\n    .quad init30\n.section .fini_array,\"aw\",@fini_array\n    .quad fini\n.data\ncode: .long 0\n"
        ),
        &dir.join("arrays.s"),
        &obj,
    );

    let link = |input: &std::path::Path, out: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .args(["--gc-sections", "--dynamic-linker", interp, "-o"])
            .arg(out)
            .arg(input)
            .output()
            .unwrap()
    };
    let out = dir.join("arrays");
    let r = link(&obj, &out);
    assert!(
        r.status.success(),
        "afs-ld dynamic arrays: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let img = std::fs::read(&out).unwrap();
    let tags: std::collections::HashMap<i64, u64> = dynamic_entries(&img).into_iter().collect();
    let expected = [
        (".preinit_array", 16u32, 32i64, 33i64, 8u64),
        (".init_array", 14u32, 25i64, 27i64, 16u64),
        (".fini_array", 15u32, 26i64, 28i64, 8u64),
    ];
    for (name, expected_type, address_tag, size_tag, expected_size) in expected {
        let (_, section_type, address, _, size, align, entsize) =
            section_header_info(&img, name).unwrap_or_else(|| panic!("missing {name}"));
        assert_eq!(section_type, expected_type, "{name} section type");
        assert_eq!(size, expected_size, "{name} size");
        assert!(align >= 8, "{name} alignment");
        assert_eq!(entsize, 8, "{name} entry size");
        assert_eq!(tags.get(&address_tag), Some(&address), "{name} address tag");
        assert_eq!(tags.get(&size_tag), Some(&size), "{name} size tag");
    }
    let dynamic = section_bytes(&img, ".dynamic").unwrap();
    assert_eq!(&dynamic[dynamic.len() - 16..], &[0u8; 16]);
    assert_eq!(
        Command::new(&out).output().unwrap().status.code(),
        Some(2),
        "the loader must run the main executable's preinit array before _start"
    );

    let out2 = dir.join("arrays2");
    assert!(link(&obj, &out2).status.success());
    assert_eq!(img, std::fs::read(&out2).unwrap());

    let empty_obj = dir.join("empty-array.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n_start:\n    xorl %edi, %edi\n    movl ${exit_nr}, %eax\n    syscall\n.section .init_array,\"aw\",@init_array\n"
        ),
        &dir.join("empty-array.s"),
        &empty_obj,
    );
    let empty_out = dir.join("empty-array");
    assert!(link(&empty_obj, &empty_out).status.success());
    let empty_img = std::fs::read(&empty_out).unwrap();
    let (_, section_type, address, _, size, _, entsize) =
        section_header_info(&empty_img, ".init_array").expect("missing empty .init_array");
    assert_eq!((section_type, size, entsize), (14, 0, 8));
    let empty_tags: std::collections::HashMap<i64, u64> =
        dynamic_entries(&empty_img).into_iter().collect();
    assert_eq!(empty_tags.get(&25), Some(&address));
    assert_eq!(empty_tags.get(&27), Some(&0));

    let absent_obj = dir.join("absent-array.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n_start:\n    xorl %edi, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"
        ),
        &dir.join("absent-array.s"),
        &absent_obj,
    );
    let absent_out = dir.join("absent-array");
    assert!(link(&absent_obj, &absent_out).status.success());
    let absent_img = std::fs::read(&absent_out).unwrap();
    let absent_tags: std::collections::HashMap<i64, u64> =
        dynamic_entries(&absent_img).into_iter().collect();
    for tag in [25, 26, 27, 28, 32, 33] {
        assert!(!absent_tags.contains_key(&tag));
    }
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

/// Relocations in the initialized TLS image are applied before PT_TLS is
/// emitted. glibc's static `malloc.o` has this shape: `.tdata` contains
/// an absolute pointer into `.rodata`.
#[test]
fn tls_initial_image_applies_absolute_relocations() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=tls_initial_image_applies_absolute_relocations count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_tls_rela_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let obj = dir.join("t.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n_start:\n    movl ${exit_nr}, %eax\n    xorl %edi, %edi\n    syscall\n.section .rodata,\"a\",@progbits\n.globl target\ntarget:\n    .quad 0x1122334455667788\n.section .tdata,\"awT\",@progbits\n.globl tptr\ntptr:\n    .quad target\n"
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

    let img = std::fs::read(&out).unwrap();
    let target = section_addr(&img, ".rodata").expect(".rodata section");
    let tdata = section_bytes(&img, ".tdata").expect(".tdata section");
    assert!(
        tdata.len() >= 8,
        ".tdata should hold relocated pointer, got {} bytes",
        tdata.len()
    );
    let got = u64::from_le_bytes(tdata[0..8].try_into().unwrap());
    assert_eq!(got, target, ".tdata pointer initializer");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Undefined weak TLS local-exec references resolve to offset zero.
/// glibc's static locale objects use this for optional per-category TLS
/// state, and GNU ld accepts the link.
#[test]
fn tls_undefined_weak_local_exec_links() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=tls_undefined_weak_local_exec_links count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_tls_weak_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let obj = dir.join("weak.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n.weak missing\n.type missing,@tls_object\n_start:\n    movl %fs:missing@tpoff, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"
        ),
        &dir.join("weak.s"),
        &obj,
    );

    let out = dir.join("weak");
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

/// An explicit non-default reference must select that exact DSO version,
/// describe it through VERSYM/VERNEED, and bind it at load time instead of
/// silently falling back to the default definition.
#[test]
fn versioned_dynamic_import_binds_explicit_non_default_version() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=versioned_dynamic_import_binds_explicit_non_default_version count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(ld) = system_ld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=versioned_dynamic_import_binds_explicit_non_default_version count=1 reason=\"no system ld to build the reference .so\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=versioned_dynamic_import_binds_explicit_non_default_version count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir =
        std::env::temp_dir().join(format!("afs_ld_elf_ver_nondefault_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

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

    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(
            ".symver answer_v1, answer@VERS_1.0\n.text\n.globl _start\n_start:\n    call answer_v1@PLT\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"
        ),
        &dir.join("main.s"),
        &main_obj,
    );

    let gnu_out = dir.join("gnu_nondefault");
    let r = Command::new(&ld)
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&gnu_out)
        .arg(&main_obj)
        .arg(&so)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "reference ld explicit version: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let run = Command::new(&gnu_out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(7),
        "reference linker must bind answer@VERS_1.0: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let out = dir.join("ver_nondefault");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&out)
        .arg(&main_obj)
        .arg(&so)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld explicit version: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let bytes = std::fs::read(&out).unwrap();
    assert!(
        bytes.windows(8).any(|w| w == b"VERS_1.0"),
        "exe must declare the explicit VERS_1.0 requirement"
    );
    let dynstr = section_bytes(&bytes, ".dynstr").expect("dynamic string table");
    assert!(
        dynstr.split(|&b| b == 0).any(|name| name == b"answer"),
        "dynsym must store the undecorated base name"
    );
    assert!(
        !dynstr
            .split(|&b| b == 0)
            .any(|name| name == b"answer@VERS_1.0"),
        "the version suffix belongs in VERSYM/VERNEED, not st_name"
    );
    let run = Command::new(&out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(7),
        "explicit version must bind answer@VERS_1.0: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    // Plain and explicit-default references describe the same import. Keep
    // that identity canonical while retaining the separately versioned V1
    // import through section collection and as-needed DSO selection.
    let mixed_obj = dir.join("mixed.o");
    assemble(
        &gas,
        &format!(
            ".symver answer_v1_ref, answer@VERS_1.0\n.symver answer_v2_ref, answer@VERS_2.0\n.text\n.globl _start\n_start:\n    call answer_v1_ref@PLT\n    movl %eax, %ebx\n    call answer_v2_ref@PLT\n    addl %eax, %ebx\n    call answer@PLT\n    addl %ebx, %eax\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"
        ),
        &dir.join("mixed.s"),
        &mixed_obj,
    );
    let mixed_out = dir.join("ver_mixed");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--gc-sections", "--dynamic-linker", interp, "-o"])
        .arg(&mixed_out)
        .arg(&mixed_obj)
        .arg("--as-needed")
        .arg(&so)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld mixed explicit versions: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let mixed = std::fs::read(&mixed_out).unwrap();
    assert_eq!(needed_libraries(&mixed), ["libver.so.1"]);
    let mixed_dynstr = section_bytes(&mixed, ".dynstr").expect("dynamic string table");
    assert!(mixed_dynstr
        .split(|&b| b == 0)
        .any(|name| name == b"VERS_1.0"));
    assert!(mixed_dynstr
        .split(|&b| b == 0)
        .any(|name| name == b"VERS_2.0"));
    let mixed_dynsym = section_bytes(&mixed, ".dynsym").expect("dynamic symbol table");
    let mixed_versym = section_bytes(&mixed, ".gnu.version").expect("version symbol table");
    assert_eq!(mixed_versym.len(), mixed_dynsym.len() / 12);
    let mut imported_versions = Vec::new();
    for (index, symbol) in mixed_dynsym.chunks_exact(24).enumerate() {
        let name_offset = u32::from_le_bytes(symbol[0..4].try_into().unwrap()) as usize;
        let section_index = u16::from_le_bytes(symbol[6..8].try_into().unwrap());
        if name_offset == 0 || section_index != 0 {
            continue;
        }
        let name_end = mixed_dynstr[name_offset..]
            .iter()
            .position(|&byte| byte == 0)
            .unwrap();
        assert_eq!(
            &mixed_dynstr[name_offset..name_offset + name_end],
            b"answer"
        );
        imported_versions.push(u16::from_le_bytes(
            mixed_versym[index * 2..index * 2 + 2].try_into().unwrap(),
        ));
    }
    assert_eq!(
        imported_versions.len(),
        2,
        "plain and explicit-default references must share one dynsym"
    );
    imported_versions.sort_unstable();
    imported_versions.dedup();
    assert_eq!(
        imported_versions.len(),
        2,
        "V1 and V2 imports must use distinct VERSYM indices"
    );
    assert!(imported_versions.iter().all(|&index| index >= 2));
    let run = Command::new(&mixed_out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(91),
        "mixed imports must bind V1 once and V2 twice: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let out2 = dir.join("ver_nondefault2");
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
        "explicit-version link must be deterministic"
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
        .arg("--as-needed")
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

    let before_demand = dir.join("before_demand");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "--as-needed", "-o"])
        .arg(&before_demand)
        .arg(&so)
        .arg(&main_obj)
        .output()
        .unwrap();
    assert!(
        !r.status.success(),
        "an as-needed DSO before its demand must not be retained"
    );
    assert!(
        String::from_utf8_lossy(&r.stderr).contains("undefined symbol 'answer'"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let script = dir.join("libanswer-script.so");
    std::fs::write(&script, "INPUT ( AS_NEEDED ( libanswer.so.1 ) )\n").unwrap();
    let script_after = dir.join("script_after");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&script_after)
        .arg(&main_obj)
        .arg(&script)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "script DSO after demand: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(
        std::fs::read(&out1).unwrap(),
        std::fs::read(&script_after).unwrap(),
        "script-wrapped as-needed input must select the same DSO"
    );

    let script_before = dir.join("script_before");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&script_before)
        .arg(&script)
        .arg(&main_obj)
        .output()
        .unwrap();
    assert!(
        !r.status.success(),
        "script-wrapped as-needed DSO before demand must be omitted"
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

#[test]
fn no_as_needed_retains_constructor_only_shared_library() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=no_as_needed_retains_constructor_only_shared_library count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(ld) = system_ld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=no_as_needed_retains_constructor_only_shared_library count=1 reason=\"no system ld to build the reference .so\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=no_as_needed_retains_constructor_only_shared_library count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_no_as_needed_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    let ctor_obj = dir.join("ctor.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl boom\n.type boom,@function\nboom:\n    movl $42, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"
        ),
        &dir.join("ctor.s"),
        &ctor_obj,
    );
    let so = dir.join("libctor.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "libctor.so.1", "-init", "boom", "-o"])
        .arg(&so)
        .arg(&ctor_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "ld -shared: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n.type _start,@function\n_start:\n    xorl %edi, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"
        ),
        &dir.join("main.s"),
        &main_obj,
    );

    let cases: &[(&str, &[&str], i32)] = &[
        ("default", &[], 42),
        ("no-as-needed", &["--no-as-needed"], 42),
        ("last-no-as-needed", &["--as-needed", "--no-as-needed"], 42),
        ("as-needed", &["--as-needed"], 0),
        ("last-as-needed", &["--no-as-needed", "--as-needed"], 0),
    ];
    for &(name, flags, expected) in cases {
        let out = dir.join(name);
        let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .args(["--dynamic-linker", interp, "-o"])
            .arg(&out)
            .arg(&main_obj)
            .args(flags)
            .arg(&so)
            .output()
            .unwrap();
        assert!(
            r.status.success(),
            "afs-ld {name}: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        let run = Command::new(&out)
            .env("LD_LIBRARY_PATH", &dir)
            .output()
            .unwrap();
        assert_eq!(
            run.status.code(),
            Some(expected),
            "{name} exit: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        let expected_needed = if expected == 42 {
            vec!["libctor.so.1".to_string()]
        } else {
            Vec::new()
        };
        assert_eq!(
            needed_libraries(&std::fs::read(&out).unwrap()),
            expected_needed
        );
    }

    let duplicate = dir.join("duplicate");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&duplicate)
        .arg(&main_obj)
        .arg(&so)
        .arg(&so)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld duplicate DSO: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(
        needed_libraries(&std::fs::read(&duplicate).unwrap()),
        ["libctor.so.1"]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn as_needed_propagates_demand_between_shared_libraries() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=as_needed_propagates_demand_between_shared_libraries count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(ld) = system_ld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=as_needed_propagates_demand_between_shared_libraries count=1 reason=\"no system ld to build reference shared objects\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=as_needed_propagates_demand_between_shared_libraries count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir =
        std::env::temp_dir().join(format!("afs_ld_elf_as_needed_chain_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    let provider_obj = dir.join("provider.o");
    assemble(
        &gas,
        ".text\n.globl helper\n.type helper,@function\nhelper:\n    movl $42, %eax\n    ret\n",
        &dir.join("provider.s"),
        &provider_obj,
    );
    let provider = dir.join("libprovider.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "libprovider.so.1", "-o"])
        .arg(&provider)
        .arg(&provider_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "provider link: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let consumer_obj = dir.join("consumer.o");
    assemble(
        &gas,
        ".text\n.globl answer\n.type answer,@function\nanswer:\n    jmp helper@plt\n",
        &dir.join("consumer.s"),
        &consumer_obj,
    );
    let consumer = dir.join("libconsumer.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "libconsumer.so.1", "-o"])
        .arg(&consumer)
        .arg(&consumer_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "consumer link: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n.type _start,@function\n_start:\n    call answer@plt\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"
        ),
        &dir.join("main.s"),
        &main_obj,
    );

    let out = dir.join("chain");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "--as-needed", "-o"])
        .arg(&out)
        .arg(&main_obj)
        .arg(&consumer)
        .arg(&provider)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld DSO chain: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(
        needed_libraries(&std::fs::read(&out).unwrap()),
        ["libconsumer.so.1", "libprovider.so.1"]
    );
    let run = Command::new(&out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(42),
        "transitive DSO demand: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let reverse = dir.join("reverse-chain");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "--as-needed", "-o"])
        .arg(&reverse)
        .arg(&main_obj)
        .arg(&provider)
        .arg(&consumer)
        .output()
        .unwrap();
    assert!(
        !r.status.success(),
        "a provider before DSO-origin demand must not be retained"
    );
    assert!(
        String::from_utf8_lossy(&r.stderr).contains("helper"),
        "unexpected reverse-order diagnostic: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let providers = dir.join("providers");
    std::fs::create_dir_all(&providers).unwrap();
    let nested_provider = providers.join("libprovider.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "libprovider.so.1", "-o"])
        .arg(&nested_provider)
        .arg(&provider_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "nested provider link: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let prelinked = dir.join("libprelinked.so.1");
    let r = Command::new(&ld)
        .args([
            "-shared",
            "-soname",
            "libprelinked.so.1",
            "-rpath",
            "$ORIGIN/providers",
            "-o",
        ])
        .arg(&prelinked)
        .arg(&consumer_obj)
        .arg(&nested_provider)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "prelinked consumer link: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(
        needed_libraries(&std::fs::read(&prelinked).unwrap()),
        ["libprovider.so.1"]
    );
    let prelinked_out = dir.join("prelinked-chain");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "--as-needed", "-o"])
        .arg(&prelinked_out)
        .arg(&main_obj)
        .arg(&prelinked)
        .arg(&nested_provider)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld prelinked DSO chain: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(
        needed_libraries(&std::fs::read(&prelinked_out).unwrap()),
        ["libprelinked.so.1"]
    );
    let run = Command::new(&prelinked_out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(42),
        "prelinked DSO demand: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let mixed_obj = dir.join("mixed.o");
    assemble(
        &gas,
        ".text\n.globl mixed_answer\n.type mixed_answer,@function\nmixed_answer:\n    jmp archive_helper@plt\n",
        &dir.join("mixed.s"),
        &mixed_obj,
    );
    let mixed = dir.join("libmixed.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "libmixed.so.1", "-o"])
        .arg(&mixed)
        .arg(&mixed_obj)
        .arg("--no-as-needed")
        .arg(&provider)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "mixed consumer link: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(
        needed_libraries(&std::fs::read(&mixed).unwrap()),
        ["libprovider.so.1"]
    );

    let mixed_main_obj = dir.join("mixed-main.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n.type _start,@function\n_start:\n    call mixed_answer@plt\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"
        ),
        &dir.join("mixed-main.s"),
        &mixed_main_obj,
    );
    let archive_helper_obj = dir.join("archive-helper.o");
    assemble(
        &gas,
        ".text\n.globl archive_helper\n.type archive_helper,@function\narchive_helper:\n    movl $42, %eax\n    ret\n",
        &dir.join("archive-helper.s"),
        &archive_helper_obj,
    );
    let ar = ["/usr/bin/ar", "/usr/local/bin/ar"]
        .iter()
        .map(std::path::PathBuf::from)
        .find(|path| path.exists());
    if let Some(ar) = ar {
        let archive = dir.join("libarchive-helper.a");
        let r = Command::new(ar)
            .arg("rcs")
            .arg(&archive)
            .arg(&archive_helper_obj)
            .output()
            .unwrap();
        assert!(
            r.status.success(),
            "archive helper build: {}",
            String::from_utf8_lossy(&r.stderr)
        );

        let mixed_out = dir.join("mixed-chain");
        let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .args(["--dynamic-linker", interp, "--as-needed", "-o"])
            .arg(&mixed_out)
            .arg(&mixed_main_obj)
            .arg(&mixed)
            .arg(&archive)
            .output()
            .unwrap();
        assert!(
            r.status.success(),
            "afs-ld mixed DSO chain: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        assert_eq!(
            needed_libraries(&std::fs::read(&mixed_out).unwrap()),
            ["libmixed.so.1"]
        );
        let run = Command::new(&mixed_out)
            .env("LD_LIBRARY_PATH", &dir)
            .output()
            .unwrap();
        assert_eq!(
            run.status.code(),
            Some(42),
            "mixed DSO demand: {}",
            String::from_utf8_lossy(&run.stderr)
        );
    } else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=as_needed_propagates_demand_between_shared_libraries count=1 reason=\"no ar on this host\"");
    }

    let mixed_missing = dir.join("mixed-missing");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "--as-needed", "-o"])
        .arg(&mixed_missing)
        .arg(&mixed_main_obj)
        .arg(&mixed)
        .output()
        .unwrap();
    assert!(
        !r.status.success(),
        "an unrelated DT_NEEDED must not hide a strong undefined symbol"
    );
    assert!(
        String::from_utf8_lossy(&r.stderr).contains("archive_helper"),
        "unexpected mixed-demand diagnostic: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let weak_consumer_obj = dir.join("weak-consumer.o");
    assemble(
        &gas,
        ".weak helper\n.data\n.quad helper\n.text\n.globl weak_answer\n.type weak_answer,@function\nweak_answer:\n    movl $43, %eax\n    ret\n",
        &dir.join("weak-consumer.s"),
        &weak_consumer_obj,
    );
    let weak_consumer = dir.join("libweak-consumer.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "libweak-consumer.so.1", "-o"])
        .arg(&weak_consumer)
        .arg(&weak_consumer_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "weak consumer link: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let weak_main_obj = dir.join("weak-main.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n.type _start,@function\n_start:\n    call weak_answer@plt\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"
        ),
        &dir.join("weak-main.s"),
        &weak_main_obj,
    );
    let weak_out = dir.join("weak-chain");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "--as-needed", "-o"])
        .arg(&weak_out)
        .arg(&weak_main_obj)
        .arg(&weak_consumer)
        .arg(&provider)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld weak DSO chain: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(
        needed_libraries(&std::fs::read(&weak_out).unwrap()),
        ["libweak-consumer.so.1"]
    );
    let run = Command::new(&weak_out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(43),
        "weak DSO demand: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let api_main = afs_ld::elf::parse_rel(
        &weak_main_obj.display().to_string(),
        &std::fs::read(&weak_main_obj).unwrap(),
    )
    .unwrap();
    let api_consumer = afs_ld::elf::parse_shared(
        &weak_consumer.display().to_string(),
        &std::fs::read(&weak_consumer).unwrap(),
    )
    .unwrap();
    let api_result = afs_ld::elf::link_dynamic(
        vec![
            afs_ld::elf::DynamicLinkInput::Object(api_main),
            afs_ld::elf::DynamicLinkInput::Shared(api_consumer),
        ],
        "_start",
        interp,
        false,
    );
    assert!(
        api_result.is_ok(),
        "metadata-free public API must preserve weak undefined behavior: {:?}",
        api_result.err()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// GNU IFUNC exports are callable function imports too. glibc exposes
/// optimized routines such as memcpy/memset this way; treating them as
/// data imports sends ordinary PLT calls down the COPY-relocation error
/// path.
#[test]
fn dynamic_executable_calls_shared_ifunc_through_plt() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_executable_calls_shared_ifunc_through_plt count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(ld) = system_ld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_executable_calls_shared_ifunc_through_plt count=1 reason=\"no system ld to build the reference .so\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_executable_calls_shared_ifunc_through_plt count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_elf_ifunc_dyn_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    let answer_obj = dir.join("answer.o");
    assemble(
        &gas,
        ".text\n\
         .type answer_impl,@function\n\
         answer_impl:\n\
             movl $42, %eax\n\
             ret\n\
         .globl answer\n\
         .type answer,@gnu_indirect_function\n\
         answer:\n\
             leaq answer_impl(%rip), %rax\n\
             ret\n",
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

    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(
            ".text\n.globl _start\n_start:\n    call answer@plt\n    movl %eax, %edi\n    movl ${exit_nr}, %eax\n    syscall\n"
        ),
        &dir.join("main.s"),
        &main_obj,
    );
    let out = dir.join("ifunc_dyn");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&out)
        .arg(&main_obj)
        .arg(&so)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld IFUNC dynamic: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let run = Command::new(&out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(42),
        "IFUNC exe exit: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An IFUNC defined by the executable is resolved by the loader before
/// `_start`: its IRELATIVE relocation fills an indirection slot with the
/// implementation address, so calls never enter the resolver as a function.
#[test]
fn dynamic_executable_resolves_local_ifunc_before_entry() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_executable_resolves_local_ifunc_before_entry count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(ld) = system_ld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_executable_resolves_local_ifunc_before_entry count=1 reason=\"no system ld to build the reference .so\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_executable_resolves_local_ifunc_before_entry count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir =
        std::env::temp_dir().join(format!("afs_ld_elf_local_ifunc_dyn_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };

    let dep_obj = dir.join("dep.o");
    assemble(
        &gas,
        ".text\n.globl dep\n.type dep,@function\ndep:\n    jmp pick@plt\n",
        &dir.join("dep.s"),
        &dep_obj,
    );
    let so = dir.join("libdep.so.1");
    let r = Command::new(&ld)
        .args(["-shared", "-soname", "libdep.so.1", "-o"])
        .arg(&so)
        .arg(&dep_obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "ld -shared: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let main_obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(
            ".text\n\
             .globl _start\n\
             _start:\n\
                 cmpb $1, resolved(%rip)\n\
                 jne 1f\n\
                 leaq __rela_iplt_start(%rip), %r8\n\
                 leaq __rela_iplt_end(%rip), %r9\n\
                 subq %r8, %r9\n\
                 cmpq $24, %r9\n\
                 jne 1f\n\
                 call dep@plt\n\
                 movl %eax, %edi\n\
                 jmp 2f\n\
             1:  movl $7, %edi\n\
             2:  movl ${exit_nr}, %eax\n\
                 syscall\n\
             .globl pick\n\
             .type pick,@gnu_indirect_function\n\
             pick:\n\
                 movb $1, resolved(%rip)\n\
                 leaq impl(%rip), %rax\n\
                 ret\n\
             impl:\n\
                 movl $42, %eax\n\
                 ret\n\
             .data\n\
             resolved: .byte 0\n"
        ),
        &dir.join("main.s"),
        &main_obj,
    );

    let link = |out: &std::path::Path| {
        let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .args(["--gc-sections", "--dynamic-linker", interp, "-o"])
            .arg(out)
            .arg(&main_obj)
            .arg(&so)
            .output()
            .unwrap();
        assert!(
            r.status.success(),
            "afs-ld local IFUNC dynamic: {}",
            String::from_utf8_lossy(&r.stderr)
        );
    };
    let out = dir.join("local_ifunc_dyn");
    link(&out);

    let image = std::fs::read(&out).unwrap();
    let rela = section_bytes(&image, ".rela.plt").expect("mixed PLT needs relocations");
    assert_eq!(
        rela.len(),
        48,
        "one import and one local IFUNC need two entries"
    );
    let jump_slot = u64::from_le_bytes(rela[0..8].try_into().unwrap());
    let jump_info = u64::from_le_bytes(rela[8..16].try_into().unwrap());
    let slot = u64::from_le_bytes(rela[24..32].try_into().unwrap());
    let info = u64::from_le_bytes(rela[32..40].try_into().unwrap());
    let resolver = u64::from_le_bytes(rela[40..48].try_into().unwrap());
    assert_eq!(jump_info as u32, afs_ld::elf::R_X86_64_JUMP_SLOT);
    assert_ne!(
        jump_info >> 32,
        0,
        "JUMP_SLOT must name its imported symbol"
    );
    assert_eq!(info as u32, afs_ld::elf::R_X86_64_IRELATIVE);
    assert_eq!(info >> 32, 0, "IRELATIVE must not name a dynamic symbol");
    let (got_addr, _, got_size) =
        section_info(&image, ".got.plt").expect("local IFUNC needs writable indirection storage");
    assert_eq!(
        jump_slot,
        got_addr + 24,
        "the imported function uses slot 3"
    );
    assert_eq!(
        slot,
        got_addr + 32,
        "the local IFUNC follows imported slots"
    );
    assert!(
        slot >= got_addr && slot.checked_add(8).unwrap() <= got_addr + got_size,
        "IRELATIVE target {slot:#x} must be in .got.plt"
    );
    assert_eq!((slot - got_addr) % 8, 0, "IFUNC slot must be aligned");
    let (text_addr, _, text_size) = section_info(&image, ".text").unwrap();
    assert!(
        (text_addr..text_addr + text_size).contains(&resolver),
        "IRELATIVE addend {resolver:#x} must name the resolver"
    );
    let (plt_index, _, plt_addr, _, plt_size, _, _) = section_header_info(&image, ".plt").unwrap();
    let dynstr = section_bytes(&image, ".dynstr").unwrap();
    let pick_export = section_bytes(&image, ".dynsym")
        .unwrap()
        .chunks_exact(24)
        .find_map(|symbol| {
            let name_offset = u32::from_le_bytes(symbol[0..4].try_into().unwrap()) as usize;
            let name_len = dynstr[name_offset..].iter().position(|&byte| byte == 0)?;
            (&dynstr[name_offset..name_offset + name_len] == b"pick").then(|| {
                (
                    symbol[4] & 0x0f,
                    u16::from_le_bytes(symbol[6..8].try_into().unwrap()),
                    u64::from_le_bytes(symbol[8..16].try_into().unwrap()),
                    u64::from_le_bytes(symbol[16..24].try_into().unwrap()),
                )
            })
        })
        .expect("the DSO reference must export pick");
    assert_eq!(pick_export.0, afs_ld::elf::STT_FUNC);
    assert_eq!(pick_export.1, plt_index);
    assert_eq!(pick_export.3, 0, "canonical PLT exports have no body size");
    assert!(
        (plt_addr..plt_addr + plt_size).contains(&pick_export.2),
        "the DSO must bind to the canonical PLT address"
    );
    assert_ne!(pick_export.2, resolver, "the resolver is not callable");

    let run = Command::new(&out)
        .env("LD_LIBRARY_PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(42),
        "local IFUNC exe exit: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let out2 = dir.join("local_ifunc_dyn_2");
    link(&out2);
    assert_eq!(
        image,
        std::fs::read(&out2).unwrap(),
        "local IFUNC output must be byte-deterministic"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dynamic_executable_resolves_local_ifunc_without_imports() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_executable_resolves_local_ifunc_without_imports count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let Some(interp) = rtld() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=dynamic_executable_resolves_local_ifunc_without_imports count=1 reason=\"no standard dynamic loader on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!(
        "afs_ld_elf_local_only_ifunc_dyn_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let obj = dir.join("main.o");
    assemble(
        &gas,
        &format!(
            ".text\n\
             .globl _start\n\
             _start:\n\
                 cmpb $1, resolved(%rip)\n\
                 jne 1f\n\
                 call pick\n\
                 cmpl $42, %eax\n\
                 jne 1f\n\
                 call *pick_addr(%rip)\n\
                 movl %eax, %edi\n\
                 jmp 2f\n\
             1:  movl $7, %edi\n\
             2:  movl ${exit_nr}, %eax\n\
                 syscall\n\
             .globl pick\n\
             .type pick,@gnu_indirect_function\n\
             pick:\n\
                 movb $1, resolved(%rip)\n\
                 leaq impl(%rip), %rax\n\
                 ret\n\
             impl:\n\
                 movl $42, %eax\n\
                 ret\n\
             .data\n\
             .p2align 3\n\
             pick_addr: .quad pick\n\
             resolved: .byte 0\n"
        ),
        &dir.join("main.s"),
        &obj,
    );

    let out = dir.join("local_only_ifunc_dyn");
    let r = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["--dynamic-linker", interp, "-o"])
        .arg(&out)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        r.status.success(),
        "afs-ld local-only IFUNC dynamic: {}",
        String::from_utf8_lossy(&r.stderr)
    );

    let image = std::fs::read(&out).unwrap();
    assert!(needed_libraries(&image).is_empty());
    let rela = section_bytes(&image, ".rela.plt").expect("local IFUNC needs .rela.plt");
    assert_eq!(rela.len(), 24, "one local IFUNC needs one relocation");
    let info = u64::from_le_bytes(rela[8..16].try_into().unwrap());
    assert_eq!(info >> 32, 0);
    assert_eq!(info as u32, afs_ld::elf::R_X86_64_IRELATIVE);
    let data = section_bytes(&image, ".data").unwrap();
    let pick_addr = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let (plt_addr, _, plt_size) = section_info(&image, ".plt").unwrap();
    assert!((plt_addr..plt_addr + plt_size).contains(&pick_addr));
    assert!(section_bytes(&image, ".got.plt").is_some());

    let run = Command::new(&out).output().unwrap();
    assert_eq!(
        run.status.code(),
        Some(42),
        "local-only IFUNC exe exit: {}",
        String::from_utf8_lossy(&run.stderr)
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

/// `(sh_addr, sh_offset, sh_size)` of a named ELF64 section, or None.
fn section_info(img: &[u8], name: &str) -> Option<(u64, u64, u64)> {
    section_header_info(img, name).map(|(_, _, addr, offset, size, _, _)| (addr, offset, size))
}

/// `(index, sh_type, sh_addr, sh_offset, sh_size, sh_addralign, sh_entsize)`.
fn section_header_info(img: &[u8], name: &str) -> Option<(u16, u32, u64, u64, u64, u64, u64)> {
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
            return Some((
                i as u16,
                rd32(sh + 4),
                rd64(sh + 16),
                rd64(sh + 24),
                rd64(sh + 32),
                rd64(sh + 48),
                rd64(sh + 56),
            ));
        }
    }
    None
}

fn section_flags(img: &[u8], name: &str) -> Vec<u64> {
    let rd16 = |o: usize| u16::from_le_bytes(img[o..o + 2].try_into().unwrap());
    let rd32 = |o: usize| u32::from_le_bytes(img[o..o + 4].try_into().unwrap());
    let rd64 = |o: usize| u64::from_le_bytes(img[o..o + 8].try_into().unwrap());
    let shoff = rd64(40) as usize;
    let shentsize = rd16(58) as usize;
    let shnum = rd16(60) as usize;
    let shstrndx = rd16(62) as usize;
    let shstr_off = rd64(shoff + shstrndx * shentsize + 24) as usize;
    let mut flags = Vec::new();
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let noff = shstr_off + rd32(sh) as usize;
        let end = img[noff..].iter().position(|&b| b == 0).unwrap();
        if &img[noff..noff + end] == name.as_bytes() {
            flags.push(rd64(sh + 8));
        }
    }
    flags
}

/// The `sh_addr` of a named ELF64 section, or None.
fn section_addr(img: &[u8], name: &str) -> Option<u64> {
    section_info(img, name).map(|(addr, _, _)| addr)
}

/// File-backed bytes of a named ELF64 section, or None.
fn section_bytes<'a>(img: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let (_, off, size) = section_info(img, name)?;
    let start = off as usize;
    let end = start.checked_add(size as usize)?;
    img.get(start..end)
}

fn needed_libraries(img: &[u8]) -> Vec<String> {
    let dynstr = section_bytes(img, ".dynstr").expect("linked image must have .dynstr");
    let mut needed = Vec::new();
    for (tag, value) in dynamic_entries(img) {
        if tag != 1 {
            continue;
        }
        let value = value as usize;
        let end = dynstr[value..]
            .iter()
            .position(|&byte| byte == 0)
            .expect("DT_NEEDED string must terminate");
        needed.push(String::from_utf8(dynstr[value..value + end].to_vec()).unwrap());
    }
    needed
}

fn dynamic_entries(img: &[u8]) -> Vec<(i64, u64)> {
    let dynamic = section_bytes(img, ".dynamic").expect("linked image must have .dynamic");
    let mut entries = Vec::new();
    for entry in dynamic.chunks_exact(16) {
        let tag = i64::from_le_bytes(entry[0..8].try_into().unwrap());
        let value = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        if tag == 0 {
            break;
        }
        entries.push((tag, value));
    }
    entries
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

/// A signal-frame CIE (gas `.cfi_signal_frame` -> augmentation "zRS")
/// must parse: 'S' carries no augmentation data. glibc's static libc.a
/// ships exactly one such CIE (the signal restorer), so before this
/// arm every static link against system glibc died at the merge.
#[test]
fn eh_frame_signal_frame_cie_links() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_link_run test=eh_frame_signal_frame_cie_links count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = std::env::temp_dir().join(format!("afs_ld_sigframe_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let asm = format!(
        ".text\n.globl _start\n.type _start,@function\n_start:\n    .cfi_startproc\n    .cfi_signal_frame\n    movl $42, %edi\n    movl ${exit_nr}, %eax\n    syscall\n    .cfi_endproc\n.size _start,.-_start\n"
    );
    let s = dir.join("sig.s");
    let obj = dir.join("sig.o");
    assemble(&gas, &asm, &s, &obj);

    let out = dir.join("sig");
    let res = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("--eh-frame-hdr")
        .arg("-o")
        .arg(&out)
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "signal-frame CIE must link: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    assert_eq!(Command::new(&out).output().unwrap().status.code(), Some(42));

    let _ = std::fs::remove_dir_all(&dir);
}
