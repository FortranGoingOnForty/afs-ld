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
