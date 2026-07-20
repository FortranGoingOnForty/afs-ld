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
    for candidate in candidates {
        if let Ok(output) = Command::new(candidate).arg("--version").output() {
            if output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("GNU assembler")
            {
                return Some(PathBuf::from(candidate));
            }
        }
    }
    None
}

fn ar() -> Option<PathBuf> {
    for candidate in ["ar", "/usr/bin/ar", "/usr/local/bin/ar"] {
        if Command::new(candidate).arg("--version").output().is_ok()
            || Command::new(candidate).output().is_ok()
        {
            return Some(PathBuf::from(candidate));
        }
    }
    None
}

fn scratch(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("afs_ld_{name}_{}_{}", std::process::id(), nanos))
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

fn archive(ar: &Path, dir: &Path, name: &str, object: &Path) -> PathBuf {
    let archive = dir.join(format!("lib{name}.a"));
    let output = Command::new(ar)
        .arg("rcs")
        .arg(&archive)
        .arg(object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ar {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    archive
}

fn thin_archive(ar: &Path, dir: &Path, name: &str, object: &Path) -> Result<PathBuf, String> {
    let archive = dir.join(format!("lib{name}.a"));
    let object_name = object
        .file_name()
        .ok_or_else(|| format!("{} has no file name", object.display()))?;
    let output = Command::new(ar)
        .current_dir(dir)
        .arg("rcsT")
        .arg(&archive)
        .arg(object_name)
        .output()
        .map_err(|error| format!("spawn ar: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(archive)
}

fn link(output: &Path, args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .arg("-o")
        .arg(output)
        .args(args)
        .output()
        .unwrap()
}

fn run(path: &Path) -> i32 {
    Command::new(path).status().unwrap().code().unwrap()
}

#[test]
fn archive_search_is_left_to_right_unless_grouped() {
    let (Some(gas), Some(ar)) = (gas(), ar()) else {
        eprintln!("\nHARNESS_SKIP suite=elf_archive_scan test=archive_search_is_left_to_right_unless_grouped count=1 reason=\"no GNU assembler or ar on this host\"");
        return;
    };

    let dir = scratch("archive_scan");
    std::fs::create_dir_all(&dir).unwrap();

    let exit_syscall = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let main_asm = format!(
        ".text\n\
         .globl _start\n\
         .type _start,@function\n\
         _start:\n\
             call f\n\
             movl %eax, %edi\n\
             movl ${exit_syscall}, %eax\n\
             syscall\n\
         .size _start,.-_start\n"
    );
    let f_asm = ".text\n\
                 .globl f\n\
                 .type f,@function\n\
                 f:\n\
                     call g\n\
                     addl $1, %eax\n\
                     ret\n\
                 .size f,.-f\n";
    let g_asm = ".text\n\
                 .globl g\n\
                 .type g,@function\n\
                 g:\n\
                     movl $34, %eax\n\
                     ret\n\
                 .size g,.-g\n";

    let main_o = assemble(&gas, &dir, "main", &main_asm);
    let f_o = assemble(&gas, &dir, "fneedg", f_asm);
    let g_o = assemble(&gas, &dir, "gdef", g_asm);
    let libf = archive(&ar, &dir, "f", &f_o);
    let libg = archive(&ar, &dir, "g", &g_o);

    let forward = dir.join("forward");
    let forward_output = link(
        &forward,
        &[main_o.as_os_str(), libf.as_os_str(), libg.as_os_str()],
    );
    assert!(
        forward_output.status.success(),
        "forward link failed: {}",
        String::from_utf8_lossy(&forward_output.stderr)
    );
    assert_eq!(run(&forward), 35);

    let backward = dir.join("backward");
    let backward_output = link(
        &backward,
        &[main_o.as_os_str(), libg.as_os_str(), libf.as_os_str()],
    );
    assert!(
        !backward_output.status.success(),
        "backward archive order must not be globally rescanned"
    );
    let stderr = String::from_utf8_lossy(&backward_output.stderr);
    assert!(stderr.contains("undefined symbol 'g'"), "{stderr}");

    let grouped = dir.join("grouped");
    let grouped_output = link(
        &grouped,
        &[
            main_o.as_os_str(),
            OsStr::new("--start-group"),
            libg.as_os_str(),
            libf.as_os_str(),
            OsStr::new("--end-group"),
        ],
    );
    assert!(
        grouped_output.status.success(),
        "grouped link failed: {}",
        String::from_utf8_lossy(&grouped_output.stderr)
    );
    assert_eq!(run(&grouped), 35);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn thin_archive_loads_external_members() {
    let (Some(gas), Some(ar)) = (gas(), ar()) else {
        eprintln!("\nHARNESS_SKIP suite=elf_archive_scan test=thin_archive_loads_external_members count=1 reason=\"no GNU assembler or ar on this host\"");
        return;
    };

    let dir = scratch("thin_archive");
    std::fs::create_dir_all(&dir).unwrap();
    let exit_syscall = if cfg!(target_os = "freebsd") { 1 } else { 60 };
    let main_asm = format!(
        ".text\n\
         .globl _start\n\
         .type _start,@function\n\
         _start:\n\
             call thin_value\n\
             movl %eax, %edi\n\
             movl ${exit_syscall}, %eax\n\
             syscall\n\
         .size _start,.-_start\n"
    );
    let member_asm = ".text\n\
                      .globl thin_value\n\
                      .type thin_value,@function\n\
                      thin_value:\n\
                          movl $37, %eax\n\
                          ret\n\
                      .size thin_value,.-thin_value\n";
    let main_o = assemble(&gas, &dir, "thin_main", &main_asm);
    let member_o = assemble(&gas, &dir, "thin_member_with_a_long_name", member_asm);
    let direct_archive = match thin_archive(&ar, &dir, "thin", &member_o) {
        Ok(archive) => archive,
        Err(error) => {
            eprintln!("\nHARNESS_SKIP suite=elf_archive_scan test=thin_archive_loads_external_members count=1 reason=\"ar lacks thin-archive support: {error}\"");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
    };

    let executable = dir.join("thin-linked");
    let output = link(
        &executable,
        &[main_o.as_os_str(), direct_archive.as_os_str()],
    );
    assert!(
        output.status.success(),
        "thin archive link failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(run(&executable), 37);

    let inner_archive = archive(&ar, &dir, "thin-inner", &member_o);
    let nested_archive = match thin_archive(&ar, &dir, "thin-nested", &inner_archive) {
        Ok(archive) => archive,
        Err(error) => {
            eprintln!("\nHARNESS_SKIP suite=elf_archive_scan test=thin_archive_loads_external_members count=1 reason=\"ar cannot flatten archive members: {error}\"");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
    };
    let nested_executable = dir.join("thin-nested-linked");
    let nested = link(
        &nested_executable,
        &[main_o.as_os_str(), nested_archive.as_os_str()],
    );
    assert!(
        nested.status.success(),
        "nested thin archive link failed: {}",
        String::from_utf8_lossy(&nested.stderr)
    );
    assert_eq!(run(&nested_executable), 37);

    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::PermissionsExt;

        let non_utf8_member = dir.join(OsString::from_vec(b"thin-member-\xff.o".to_vec()));
        std::fs::copy(&member_o, &non_utf8_member).unwrap();
        let non_utf8_member_archive =
            thin_archive(&ar, &dir, "thin-nonutf8-member", &non_utf8_member).unwrap();
        let non_utf8_member_output = dir.join("thin-nonutf8-member-linked");
        let output = link(
            &non_utf8_member_output,
            &[main_o.as_os_str(), non_utf8_member_archive.as_os_str()],
        );
        assert!(
            output.status.success(),
            "non-UTF8 thin member link failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(run(&non_utf8_member_output), 37);

        let non_utf8_archive = dir.join(OsString::from_vec(b"libthin-\xff.a".to_vec()));
        std::fs::rename(&direct_archive, &non_utf8_archive).unwrap();
        let main_object =
            afs_ld::elf::parse_rel("display-main.o", &std::fs::read(&main_o).unwrap()).unwrap();
        let image = afs_ld::elf::link_static(
            vec![
                afs_ld::elf::LinkInput::Object(main_object),
                afs_ld::elf::LinkInput::Archive(afs_ld::elf::Library {
                    name: "display-only-thin-library".to_string(),
                    path: non_utf8_archive.clone(),
                    bytes: std::fs::read(&non_utf8_archive).unwrap(),
                }),
            ],
            "_start",
            false,
        )
        .unwrap();
        let api_output = dir.join("thin-api-linked");
        std::fs::write(&api_output, image).unwrap();
        let mut permissions = std::fs::metadata(&api_output).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&api_output, permissions).unwrap();
        assert_eq!(run(&api_output), 37);
        std::fs::rename(non_utf8_archive, &direct_archive).unwrap();
    }

    std::fs::remove_file(&member_o).unwrap();
    let missing_output = dir.join("thin-missing");
    let missing = link(
        &missing_output,
        &[main_o.as_os_str(), direct_archive.as_os_str()],
    );
    assert!(!missing.status.success());
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(
        stderr.contains("thin_member_with_a_long_name.o"),
        "{stderr}"
    );
    assert!(stderr.contains("thin archive member I/O"), "{stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}
