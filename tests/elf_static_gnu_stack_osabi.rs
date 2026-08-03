//! Audit L9: a static ET_EXEC must carry a non-executable PT_GNU_STACK marker
//! (its absence makes Linux grant an executable stack via READ_IMPLIES_EXEC)
//! and must brand EI_OSABI for the host it will run on — not for whatever OS
//! afs-ld happened to be compiled for. On this dev box afs-ld is sometimes a
//! Linux binary under the FreeBSD linuxulator, so a compile-time cfg would
//! misbrand a FreeBSD-hosted output.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

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
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const DT_NULL: u64 = 0;
const DT_FLAGS: u64 = 30;
const DF_BIND_NOW: u64 = 0x8;

fn temp_dir(label: &str) -> PathBuf {
    let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "afs_ld_gnustack_{}_{}_{}",
        std::process::id(),
        label,
        id
    ))
}

fn assemble(gas: &PathBuf, dir: &std::path::Path, name: &str, source: &str) -> PathBuf {
    let asm = dir.join(format!("{name}.s"));
    let object = dir.join(format!("{name}.o"));
    std::fs::write(&asm, source).expect("write assembly fixture");
    let output = Command::new(gas)
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&asm)
        .output()
        .expect("run GNU assembler");
    assert!(
        output.status.success(),
        "gas: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    object
}

fn gnu_stack_flags(elf: &[u8]) -> u32 {
    let phoff = ru64(elf, 32) as usize;
    let phentsize = ru16(elf, 54) as usize;
    let phnum = ru16(elf, 56) as usize;
    let flags: Vec<u32> = (0..phnum)
        .filter_map(|index| {
            let header = phoff + index * phentsize;
            (ru32(elf, header) == PT_GNU_STACK).then(|| ru32(elf, header + 4))
        })
        .collect();
    assert_eq!(flags.len(), 1, "expected exactly one PT_GNU_STACK");
    flags[0]
}

fn binds_now(elf: &[u8]) -> bool {
    let phoff = ru64(elf, 32) as usize;
    let phentsize = ru16(elf, 54) as usize;
    let phnum = ru16(elf, 56) as usize;
    let (offset, size) = (0..phnum)
        .find_map(|index| {
            let header = phoff + index * phentsize;
            (ru32(elf, header) == PT_DYNAMIC).then(|| {
                (
                    ru64(elf, header + 8) as usize,
                    ru64(elf, header + 32) as usize,
                )
            })
        })
        .expect("expected PT_DYNAMIC");
    let dynamic = elf
        .get(offset..offset + size)
        .expect("PT_DYNAMIC must be in the file");
    for entry in dynamic.chunks_exact(16) {
        let tag = ru64(entry, 0);
        if tag == DT_NULL {
            break;
        }
        if tag == DT_FLAGS {
            return ru64(entry, 8) & DF_BIND_NOW != 0;
        }
    }
    false
}

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
    let dir = temp_dir("default");
    std::fs::create_dir_all(&dir).unwrap();

    let exit_nr = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let asm = format!(
        ".text\n.globl _start\n.type _start,@function\n_start:\n    movl $42, %edi\n    movl ${exit_nr}, %eax\n    syscall\n.size _start,.-_start\n"
    );
    let obj = assemble(&gas, &dir, "x", &asm);

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
    let flags = gnu_stack_flags(&elf);
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

    // Adding the marker phdr must not have disturbed the layout: it still runs.
    let run = Command::new(&bin).status().unwrap();
    assert_eq!(run.code(), Some(42), "static exe should still exit 42");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn executable_stack_requests_are_aggregated_across_objects() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_static_gnu_stack_osabi test=executable_stack_requests_are_aggregated_across_objects count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = temp_dir("aggregate");
    std::fs::create_dir_all(&dir).unwrap();

    let safe = assemble(
        &gas,
        &dir,
        "safe",
        ".text\n.globl _start\n.type _start,@function\n_start:\n    ret\n.size _start,.-_start\n.section .note.GNU-stack,\"\",@progbits\n",
    );
    let executable = assemble(
        &gas,
        &dir,
        "executable",
        ".text\n.globl helper\n.type helper,@function\nhelper:\n    ret\n.size helper,.-helper\n.section .note.GNU-stack,\"x\",@progbits\n",
    );

    let cases = [
        ("safe", vec![safe.clone()], PF_R | PF_W),
        (
            "exec_last",
            vec![safe.clone(), executable.clone()],
            PF_R | PF_W | PF_X,
        ),
        ("exec_first", vec![executable, safe], PF_R | PF_W | PF_X),
    ];
    for (case, objects, expected_flags) in cases {
        for dynamic in [false, true] {
            let mode = if dynamic { "dynamic" } else { "static" };
            let output = dir.join(format!("{case}_{mode}"));
            let mut command = Command::new(env!("CARGO_BIN_EXE_afs-ld"));
            command.arg("-o").arg(&output);
            if dynamic {
                command.args(["--dynamic-linker", "/nonexistent/ld.so"]);
            }
            command.args(&objects);
            let result = command.output().expect("run afs-ld");
            assert!(
                result.status.success(),
                "{case} {mode}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let elf = std::fs::read(&output).expect("read linked ELF");
            assert_eq!(
                gnu_stack_flags(&elf),
                expected_flags,
                "{case} {mode} stack flags"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn explicit_stack_policy_overrides_inputs_and_last_option_wins() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_static_gnu_stack_osabi test=explicit_stack_policy_overrides_inputs_and_last_option_wins count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = temp_dir("stack_policy");
    std::fs::create_dir_all(&dir).unwrap();

    let safe = assemble(
        &gas,
        &dir,
        "policy_safe",
        ".text\n.globl _start\n.type _start,@function\n_start:\n    ret\n.size _start,.-_start\n.section .note.GNU-stack,\"\",@progbits\n",
    );
    let executable = assemble(
        &gas,
        &dir,
        "policy_executable",
        ".text\n.globl _start\n.type _start,@function\n_start:\n    ret\n.size _start,.-_start\n.section .note.GNU-stack,\"x\",@progbits\n",
    );

    let cases = [
        (
            "separated_execstack",
            safe.clone(),
            vec!["-z", "execstack"],
            PF_R | PF_W | PF_X,
        ),
        (
            "separated_noexecstack",
            executable.clone(),
            vec!["-z", "noexecstack"],
            PF_R | PF_W,
        ),
        (
            "joined_last_noexecstack",
            executable,
            vec!["-zexecstack", "-znoexecstack"],
            PF_R | PF_W,
        ),
        (
            "joined_last_execstack",
            safe,
            vec!["-znoexecstack", "-zexecstack"],
            PF_R | PF_W | PF_X,
        ),
    ];

    for (case, object, policy_args, expected_flags) in cases {
        for dynamic in [false, true] {
            let mode = if dynamic { "dynamic" } else { "static" };
            let output = dir.join(format!("{case}_{mode}"));
            let mut command = Command::new(env!("CARGO_BIN_EXE_afs-ld"));
            command.arg("-o").arg(&output).args(&policy_args);
            if dynamic {
                command.args(["--dynamic-linker", "/nonexistent/ld.so"]);
            }
            let result = command.arg(&object).output().expect("run afs-ld");
            assert!(
                result.status.success(),
                "{case} {mode}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let elf = std::fs::read(&output).expect("read linked ELF");
            assert_eq!(
                gnu_stack_flags(&elf),
                expected_flags,
                "{case} {mode} stack flags"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dynamic_binding_policy_defaults_to_lazy_and_last_option_wins() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_static_gnu_stack_osabi test=dynamic_binding_policy_defaults_to_lazy_and_last_option_wins count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = temp_dir("binding_policy");
    std::fs::create_dir_all(&dir).unwrap();
    let object = assemble(
        &gas,
        &dir,
        "binding",
        ".text\n.globl _start\n.type _start,@function\n_start:\n    ret\n.size _start,.-_start\n.section .note.GNU-stack,\"\",@progbits\n",
    );

    let cases = [
        ("default_lazy", Vec::new(), false),
        ("separated_now", vec!["-z", "now"], true),
        ("joined_last_lazy", vec!["-znow", "-zlazy"], false),
        ("joined_last_now", vec!["-zlazy", "-znow"], true),
    ];
    for (case, policy_args, expected_bind_now) in cases {
        let output = dir.join(case);
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-o")
            .arg(&output)
            .args(&policy_args)
            .args(["--dynamic-linker", "/nonexistent/ld.so"])
            .arg(&object)
            .output()
            .expect("run afs-ld");
        assert!(
            result.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let elf = std::fs::read(&output).expect("read linked ELF");
        assert_eq!(binds_now(&elf), expected_bind_now, "{case} binding mode");
    }

    let _ = std::fs::remove_dir_all(&dir);
}
