use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn gas() -> Option<PathBuf> {
    let candidates: &[&str] = if cfg!(target_os = "freebsd") {
        &["/usr/local/bin/as"]
    } else if cfg!(target_os = "linux") {
        &["as"]
    } else {
        &[]
    };
    candidates.iter().find_map(|candidate| {
        let output = Command::new(candidate).arg("--version").output().ok()?;
        (output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("GNU assembler"))
        .then(|| PathBuf::from(candidate))
    })
}

fn ar() -> Option<PathBuf> {
    ["ar", "/usr/bin/ar", "/usr/local/bin/ar"]
        .into_iter()
        .find_map(|candidate| {
            (Command::new(candidate).arg("--version").output().is_ok()
                || Command::new(candidate).output().is_ok())
            .then(|| PathBuf::from(candidate))
        })
}

fn scratch(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "afs_ld_elf_mode_{name}_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn assemble(gas: &Path, dir: &Path, name: &str, asm: &str) -> PathBuf {
    let source = dir.join(format!("{name}.s"));
    let object = dir.join(format!("{name}.o"));
    std::fs::write(&source, asm).unwrap();
    let output = Command::new(gas)
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "gas {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    object
}

fn archive(ar: &Path, dir: &Path, name: &str, members: &[&Path]) -> PathBuf {
    let archive = dir.join(format!("lib{name}.a"));
    let output = Command::new(ar)
        .arg("rcs")
        .arg(&archive)
        .args(members)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ar {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    archive
}

fn thin_archive(ar: &Path, dir: &Path, name: &str, member: &Path) -> Option<PathBuf> {
    let archive = dir.join(format!("lib{name}.a"));
    let member_name = member.file_name()?;
    let output = Command::new(ar)
        .current_dir(dir)
        .arg("rcsT")
        .arg(&archive)
        .arg(member_name)
        .output()
        .ok()?;
    output.status.success().then_some(archive)
}

fn link(output: &Path, args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(output)
        .args(args)
        .output()
        .unwrap()
}

#[cfg(unix)]
fn link_with_small_file_limit(output: &Path, args: &[&OsStr]) -> Output {
    Command::new("/bin/sh")
        .args([
            "-c",
            "trap '' 25; ulimit -f 1; exec \"$@\"",
            "afs-ld-file-limit",
        ])
        .arg(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(output)
        .args(args)
        .output()
        .unwrap()
}

fn run(path: &Path) -> i32 {
    Command::new(path).status().unwrap().code().unwrap()
}

fn dynamic_loader() -> Option<&'static str> {
    let candidates: &[&str] = if cfg!(target_os = "freebsd") {
        &["/libexec/ld-elf.so.1"]
    } else if cfg!(target_os = "linux") {
        &["/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-x86-64.so.2"]
    } else {
        &[]
    };
    candidates
        .iter()
        .copied()
        .find(|candidate| Path::new(candidate).exists())
}

fn exit_asm(entry: &str, status: u32) -> String {
    let syscall = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    format!(
        ".text\n\
         .globl {entry}\n\
         .type {entry},@function\n\
         {entry}:\n\
             movl ${status}, %edi\n\
             movl ${syscall}, %eax\n\
             syscall\n\
         .size {entry},.-{entry}\n"
    )
}

fn assert_linked(output: &Output, executable: &Path, status: i32) {
    assert!(
        output.status.success(),
        "link failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(&std::fs::read(executable).unwrap()[..4], b"\x7fELF");
    assert_eq!(run(executable), status);
}

#[test]
fn archive_entry_is_an_extraction_root() {
    let (Some(gas), Some(ar)) = (gas(), ar()) else {
        eprintln!("\nHARNESS_SKIP suite=elf_mode_selection test=archive_entry_is_an_extraction_root count=1 reason=\"no GNU assembler or ar on this host\"");
        return;
    };
    let dir = scratch("api_entry");
    std::fs::create_dir_all(&dir).unwrap();
    let object = assemble(&gas, &dir, "custom_entry", &exit_asm("custom_entry", 43));
    let library = archive(&ar, &dir, "entry", &[&object]);

    let image = afs_ld::elf::link_static(
        vec![afs_ld::elf::LinkInput::Archive(afs_ld::elf::Library {
            name: library.display().to_string(),
            path: library.clone(),
            bytes: std::fs::read(&library).unwrap(),
        })],
        "custom_entry",
        false,
    )
    .unwrap();
    assert_eq!(&image[..4], b"\x7fELF");

    let linker_symbol_object = assemble(&gas, &dir, "linker_symbol", &exit_asm("_end", 47));
    let linker_symbol_library = archive(&ar, &dir, "linker-symbol", &[&linker_symbol_object]);
    let image = afs_ld::elf::link_static(
        vec![afs_ld::elf::LinkInput::Archive(afs_ld::elf::Library {
            name: linker_symbol_library.display().to_string(),
            path: linker_symbol_library.clone(),
            bytes: std::fs::read(&linker_symbol_library).unwrap(),
        })],
        "_end",
        false,
    )
    .unwrap();
    assert_eq!(&image[..4], b"\x7fELF");

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn archive_only_invocation_selects_elf_and_is_deterministic() {
    let (Some(gas), Some(ar)) = (gas(), ar()) else {
        eprintln!("\nHARNESS_SKIP suite=elf_mode_selection test=archive_only_invocation_selects_elf_and_is_deterministic count=1 reason=\"no GNU assembler or ar on this host\"");
        return;
    };
    let dir = scratch("archive_only");
    std::fs::create_dir_all(&dir).unwrap();
    let object = assemble(&gas, &dir, "entry", &exit_asm("_start", 42));
    let library = archive(&ar, &dir, "entry", &[&object]);
    let first = dir.join("first");
    let second = dir.join("second");

    let first_link = link(&first, &[library.as_os_str()]);
    assert_linked(&first_link, &first, 42);
    let second_link = link(&second, &[library.as_os_str()]);
    assert_linked(&second_link, &second, 42);
    assert_eq!(
        std::fs::read(&first).unwrap(),
        std::fs::read(&second).unwrap()
    );

    if let Some(thin_library) = thin_archive(&ar, &dir, "thin-entry", &object) {
        let thin_output = dir.join("thin");
        let thin_link = link(&thin_output, &[thin_library.as_os_str()]);
        assert_linked(&thin_link, &thin_output, 42);
    }

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn library_and_script_only_invocations_select_elf() {
    let (Some(gas), Some(ar)) = (gas(), ar()) else {
        eprintln!("\nHARNESS_SKIP suite=elf_mode_selection test=library_and_script_only_invocations_select_elf count=1 reason=\"no GNU assembler or ar on this host\"");
        return;
    };
    let dir = scratch("indirect_inputs");
    std::fs::create_dir_all(&dir).unwrap();
    let object = assemble(&gas, &dir, "entry", &exit_asm("_start", 44));
    let library = archive(&ar, &dir, "entry", &[&object]);

    let library_output = dir.join("library");
    let library_link = link(
        &library_output,
        &[OsStr::new("-L"), dir.as_os_str(), OsStr::new("-lentry")],
    );
    assert_linked(&library_link, &library_output, 44);

    let script = dir.join("entry.ld");
    std::fs::write(&script, format!("INPUT ( {} )\n", library.display())).unwrap();
    let script_output = dir.join("script");
    let script_link = link(&script_output, &[script.as_os_str()]);
    assert_linked(&script_link, &script_output, 44);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn script_group_rescans_archives_from_entry_demand() {
    let (Some(gas), Some(ar)) = (gas(), ar()) else {
        eprintln!("\nHARNESS_SKIP suite=elf_mode_selection test=script_group_rescans_archives_from_entry_demand count=1 reason=\"no GNU assembler or ar on this host\"");
        return;
    };
    let dir = scratch("script_group");
    std::fs::create_dir_all(&dir).unwrap();
    let syscall = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let entry_asm = format!(
        ".text\n\
         .globl _start\n\
         .type _start,@function\n\
         _start:\n\
             call helper\n\
             movl %eax, %edi\n\
             movl ${syscall}, %eax\n\
             syscall\n\
         .size _start,.-_start\n"
    );
    let helper_asm = ".text\n\
                      .globl helper\n\
                      .type helper,@function\n\
                      helper:\n\
                          movl $45, %eax\n\
                          ret\n\
                      .size helper,.-helper\n";
    let entry = assemble(&gas, &dir, "entry", &entry_asm);
    let helper = assemble(&gas, &dir, "helper", helper_asm);
    let entry_library = archive(&ar, &dir, "entry", &[&entry]);
    let helper_library = archive(&ar, &dir, "helper", &[&helper]);
    let script = dir.join("group.ld");
    std::fs::write(
        &script,
        format!(
            "GROUP ( {} {} )\n",
            helper_library.display(),
            entry_library.display()
        ),
    )
    .unwrap();

    let executable = dir.join("grouped");
    let output = link(&executable, &[script.as_os_str()]);
    assert_linked(&output, &executable, 45);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn explicit_emulation_and_entry_select_elf() {
    let (Some(gas), Some(ar)) = (gas(), ar()) else {
        eprintln!("\nHARNESS_SKIP suite=elf_mode_selection test=explicit_emulation_and_entry_select_elf count=1 reason=\"no GNU assembler or ar on this host\"");
        return;
    };
    let dir = scratch("explicit_mode");
    std::fs::create_dir_all(&dir).unwrap();
    let object = assemble(&gas, &dir, "custom", &exit_asm("custom_entry", 46));
    let library = archive(&ar, &dir, "custom", &[&object]);
    let executable = dir.join("custom");
    let output = link(
        &executable,
        &[
            OsStr::new("-melf_x86_64"),
            OsStr::new("-e"),
            OsStr::new("custom_entry"),
            library.as_os_str(),
        ],
    );
    assert_linked(&output, &executable, 46);

    let garbage = dir.join("garbage");
    std::fs::write(&garbage, b"not an object").unwrap();
    let bad_output = link(
        &dir.join("bad"),
        &[OsStr::new("-melf_x86_64"), garbage.as_os_str()],
    );
    assert!(!bad_output.status.success());
    let stderr = String::from_utf8_lossy(&bad_output.stderr);
    assert!(
        !stderr.contains("unknown option '-melf_x86_64'"),
        "{stderr}"
    );

    let separated = link(
        &dir.join("bad-separated"),
        &[
            OsStr::new("-m"),
            OsStr::new("elf_x86_64"),
            garbage.as_os_str(),
        ],
    );
    assert!(!separated.status.success());
    let stderr = String::from_utf8_lossy(&separated.stderr);
    assert!(!stderr.contains("unknown flag `-m`"), "{stderr}");

    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn primary_elf_output_preserves_previous_file_after_write_failure() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_mode_selection test=primary_elf_output_preserves_previous_file_after_write_failure count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    const SENTINEL: &[u8] = b"previous complete ELF output";

    let dir = scratch("atomic_primary_output");
    std::fs::create_dir_all(&dir).unwrap();
    let object = assemble(&gas, &dir, "entry", &exit_asm("_start", 42));
    let executable = dir.join("linked");
    std::fs::write(&executable, SENTINEL).unwrap();

    let result = link_with_small_file_limit(
        &executable,
        &[OsStr::new("-melf_x86_64"), object.as_os_str()],
    );

    assert!(!result.status.success(), "file-limited link must fail");
    assert_eq!(
        std::fs::read(&executable).unwrap(),
        SENTINEL,
        "failed ELF publication replaced the previous complete output"
    );
    assert!(
        std::fs::read_dir(&dir).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("afs-ld-tmp")),
        "failed ELF publication leaked a temporary output"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn response_file_selects_elf_before_format_routing() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_mode_selection test=response_file_selects_elf_before_format_routing count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = scratch("response_file");
    std::fs::create_dir_all(&dir).unwrap();
    let object = assemble(&gas, &dir, "entry", &exit_asm("_start", 47));
    let executable = dir.join("linked");
    let response = dir.join("link.rsp");
    std::fs::write(
        &response,
        format!(
            "-melf_x86_64\n-o\n{}\n{}\n",
            executable.display(),
            object.display()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg(format!("@{}", response.display()))
        .output()
        .unwrap();
    assert_linked(&output, &executable, 47);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn wl_wrapped_emulation_selects_elf_before_format_routing() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_mode_selection test=wl_wrapped_emulation_selects_elf_before_format_routing count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = scratch("wl_wrapped");
    std::fs::create_dir_all(&dir).unwrap();
    let object = assemble(&gas, &dir, "entry", &exit_asm("_start", 49));
    let direct = dir.join("direct");
    let wrapped = dir.join("wrapped");

    let direct_output = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(["-melf_x86_64", "-o"])
        .arg(&direct)
        .arg(&object)
        .output()
        .unwrap();
    assert_linked(&direct_output, &direct, 49);

    let wrapped_output = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg(format!("-Wl,-melf_x86_64,-o,{}", wrapped.display()))
        .arg(&object)
        .output()
        .unwrap();
    assert_linked(&wrapped_output, &wrapped, 49);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn dynamic_archive_only_invocation_extracts_entry() {
    let (Some(gas), Some(ar), Some(loader)) = (gas(), ar(), dynamic_loader()) else {
        eprintln!("\nHARNESS_SKIP suite=elf_mode_selection test=dynamic_archive_only_invocation_extracts_entry count=1 reason=\"no GNU assembler, ar, or standard dynamic loader on this host\"");
        return;
    };
    let dir = scratch("dynamic_archive");
    std::fs::create_dir_all(&dir).unwrap();
    let object = assemble(&gas, &dir, "dynamic_entry", &exit_asm("_start", 48));
    let library = archive(&ar, &dir, "dynamic-entry", &[&object]);
    let executable = dir.join("dynamic");
    let output = link(
        &executable,
        &[
            OsStr::new("--dynamic-linker"),
            OsStr::new(loader),
            library.as_os_str(),
        ],
    );
    assert_linked(&output, &executable, 48);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn missing_dynamic_linker_operand_never_falls_back_to_static_output() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_mode_selection test=missing_dynamic_linker_operand_never_falls_back_to_static_output count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    let dir = scratch("missing_dynamic_linker");
    std::fs::create_dir_all(&dir).unwrap();
    let object = assemble(&gas, &dir, "entry", &exit_asm("_start", 50));

    for (index, flag) in ["--dynamic-linker", "-dynamic-linker"]
        .into_iter()
        .enumerate()
    {
        let executable = dir.join(format!("missing-{index}"));
        let output = link(
            &executable,
            &[
                OsStr::new("-melf_x86_64"),
                object.as_os_str(),
                OsStr::new(flag),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "{flag} stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("flag `{flag}` requires a value")),
            "{flag} stderr:\n{stderr}"
        );
        assert!(
            !executable.exists(),
            "{flag} must not publish a static fallback"
        );
    }

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn invalid_z_policies_preserve_existing_output() {
    let Some(gas) = gas() else {
        eprintln!("\nHARNESS_SKIP suite=elf_mode_selection test=invalid_z_policies_preserve_existing_output count=1 reason=\"no GNU assembler on this host\"");
        return;
    };
    const SENTINEL: &[u8] = b"previous complete ELF output";

    let dir = scratch("invalid_z_policy");
    std::fs::create_dir_all(&dir).unwrap();
    let object = assemble(&gas, &dir, "entry", &exit_asm("_start", 51));
    let cases = [
        (
            "unknown_separated",
            vec!["-z", "mystery"],
            "flag `-z` got invalid value `mystery`",
        ),
        (
            "unknown_joined",
            vec!["-zmystery"],
            "flag `-z` got invalid value `mystery`",
        ),
        ("missing", vec!["-z"], "flag `-z` requires a value"),
    ];

    for (case, policy_args, expected_diagnostic) in cases {
        let executable = dir.join(case);
        std::fs::write(&executable, SENTINEL).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
            .arg("-o")
            .arg(&executable)
            .arg("-melf_x86_64")
            .arg(&object)
            .args(&policy_args)
            .output()
            .expect("run afs-ld");
        assert_eq!(
            result.status.code(),
            Some(2),
            "{case} stderr:\n{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains(expected_diagnostic),
            "{case} stderr:\n{stderr}"
        );
        assert_eq!(
            std::fs::read(&executable).unwrap(),
            SENTINEL,
            "{case} replaced the previous output"
        );
    }
    assert!(
        std::fs::read_dir(&dir).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("afs-ld-tmp")),
        "rejected -z policy leaked a temporary output"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn non_elf_archive_does_not_select_elf() {
    let Some(ar) = ar() else {
        eprintln!("\nHARNESS_SKIP suite=elf_mode_selection test=non_elf_archive_does_not_select_elf count=1 reason=\"no ar on this host\"");
        return;
    };
    let dir = scratch("non_elf_archive");
    std::fs::create_dir_all(&dir).unwrap();
    let member = dir.join("member.txt");
    std::fs::write(&member, b"not an object").unwrap();
    let library = archive(&ar, &dir, "text", &[&member]);
    let output = link(&dir.join("out"), &[library.as_os_str()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("ELF"), "{stderr}");

    let _ = std::fs::remove_dir_all(dir);
}
