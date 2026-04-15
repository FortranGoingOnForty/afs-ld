use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use afs_ld::macho::constants::*;
use afs_ld::macho::reader::{parse_commands, parse_header, LoadCommand};

fn have_xcrun() -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg("as")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn have_clang() -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg("clang")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("afs-ld-load-order-{}-{name}", std::process::id()))
}

fn assemble(src_text: &str, out: &Path) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-load-order-{}-{}.s",
        std::process::id(),
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("t")
    ));
    fs::write(&tmp, src_text).map_err(|e| format!("write .s: {e}"))?;
    let status = Command::new("xcrun")
        .args(["--sdk", "macosx", "as", "-arch", "arm64"])
        .arg(&tmp)
        .arg("-o")
        .arg(out)
        .output()
        .map_err(|e| format!("spawn xcrun as: {e}"))?;
    let _ = fs::remove_file(&tmp);
    if !status.status.success() {
        return Err(format!(
            "xcrun as failed: {}",
            String::from_utf8_lossy(&status.stderr)
        ));
    }
    Ok(())
}

fn build_test_dylib(src: &str, out: &Path, install_name: &str) -> Result<(), String> {
    let mut child = Command::new("xcrun")
        .args([
            "--sdk", "macosx", "clang", "-x", "c", "-arch", "arm64", "-shared", "-o",
        ])
        .arg(out)
        .arg("-install_name")
        .arg(install_name)
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn clang: {e}"))?;
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(src.as_bytes())
        .map_err(|e| format!("write clang stdin: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "clang failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn link_with_afs_ld(args: &[&str]) -> Result<(), String> {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .args(args)
        .output()
        .map_err(|e| format!("spawn afs-ld: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "afs-ld failed: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn command_ids(path: &Path) -> Vec<u32> {
    let bytes = fs::read(path).expect("read mach-o");
    let hdr = parse_header(&bytes).expect("parse header");
    parse_commands(&hdr, &bytes)
        .expect("parse commands")
        .into_iter()
        .map(|cmd| match cmd {
            LoadCommand::Raw { cmd, .. } => cmd,
            other => other.cmd(),
        })
        .collect()
}

fn normalize(ids: &[u32]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for token in ids.iter().filter_map(|cmd| match *cmd {
        LC_SEGMENT_64 => Some("SEGMENT"),
        LC_DYLD_INFO_ONLY | LC_DYLD_CHAINED_FIXUPS | LC_DYLD_EXPORTS_TRIE => Some("FIXUPS"),
        LC_SYMTAB => Some("SYMTAB"),
        LC_DYSYMTAB => Some("DYSYMTAB"),
        LC_LOAD_DYLINKER => Some("LOAD_DYLINKER"),
        LC_UUID => Some("UUID"),
        LC_BUILD_VERSION => Some("BUILD_VERSION"),
        LC_SOURCE_VERSION => Some("SOURCE_VERSION"),
        LC_MAIN => Some("MAIN"),
        LC_ID_DYLIB => Some("ID_DYLIB"),
        LC_LOAD_DYLIB => Some("LOAD_DYLIB"),
        LC_RPATH => Some("RPATH"),
        LC_FUNCTION_STARTS => Some("FUNCTION_STARTS"),
        LC_DATA_IN_CODE => Some("DATA_IN_CODE"),
        LC_CODE_SIGNATURE => Some("CODE_SIGNATURE"),
        _ => None,
    }) {
        if out.last().copied() == Some(token) && token == "FIXUPS" {
            continue;
        }
        out.push(token);
    }
    out
}

#[test]
fn executable_load_command_order_matches_apple_for_common_surface() {
    if !have_xcrun() || !have_clang() {
        eprintln!("skipping: xcrun as / clang unavailable");
        return;
    }

    let obj = scratch("main.o");
    let ours = scratch("ours-exec");
    let theirs = scratch("clang-exec");
    assemble(
        r#"
            .section __TEXT,__text,regular,pure_instructions
            .globl _main
            _main:
                ret
        "#,
        &obj,
    )
    .expect("assemble");
    link_with_afs_ld(&[obj.to_str().unwrap(), "-o", ours.to_str().unwrap()]).expect("afs-ld");
    let status = Command::new("xcrun")
        .args(["--sdk", "macosx", "clang", "-arch", "arm64"])
        .arg(&obj)
        .arg("-o")
        .arg(&theirs)
        .status()
        .expect("spawn clang");
    assert!(status.success(), "clang link failed");

    assert_eq!(
        normalize(&command_ids(&ours)),
        normalize(&command_ids(&theirs))
    );

    let _ = fs::remove_file(&obj);
    let _ = fs::remove_file(&ours);
    let _ = fs::remove_file(&theirs);
}

#[test]
fn dylib_load_command_order_matches_apple_for_common_surface() {
    if !have_xcrun() || !have_clang() {
        eprintln!("skipping: xcrun as / clang unavailable");
        return;
    }

    let obj = scratch("lib.o");
    let ours = scratch("ours.dylib");
    let theirs = scratch("clang.dylib");
    assemble(
        r#"
            .section __TEXT,__text,regular,pure_instructions
            .globl _answer
            _answer:
                ret
        "#,
        &obj,
    )
    .expect("assemble");
    link_with_afs_ld(&[
        "-dylib",
        obj.to_str().unwrap(),
        "-o",
        ours.to_str().unwrap(),
    ])
    .expect("afs-ld dylib");
    let status = Command::new("xcrun")
        .args(["--sdk", "macosx", "clang", "-shared", "-arch", "arm64"])
        .arg(&obj)
        .arg("-install_name")
        .arg("@rpath/libparity.dylib")
        .arg("-o")
        .arg(&theirs)
        .status()
        .expect("spawn clang");
    assert!(status.success(), "clang dylib link failed");

    assert_eq!(
        normalize(&command_ids(&ours)),
        normalize(&command_ids(&theirs))
    );

    let _ = fs::remove_file(&obj);
    let _ = fs::remove_file(&ours);
    let _ = fs::remove_file(&theirs);
}

#[test]
fn executable_load_command_order_with_dependency_and_rpath_matches_common_surface() {
    if !have_xcrun() || !have_clang() {
        eprintln!("skipping: xcrun as / clang unavailable");
        return;
    }

    let obj = scratch("dep-main.o");
    let dep = scratch("dep.dylib");
    let ours = scratch("ours-dep");
    let theirs = scratch("clang-dep");
    assemble(
        r#"
            .section __TEXT,__text,regular,pure_instructions
            .globl _main
            _main:
                ret
        "#,
        &obj,
    )
    .expect("assemble");
    build_test_dylib("int dep(void) { return 1; }\n", &dep, "@rpath/libdep.dylib")
        .expect("build dylib");
    link_with_afs_ld(&[
        obj.to_str().unwrap(),
        dep.to_str().unwrap(),
        "-rpath",
        "@executable_path/../lib",
        "-o",
        ours.to_str().unwrap(),
    ])
    .expect("afs-ld with dep");

    let status = Command::new("xcrun")
        .args(["--sdk", "macosx", "clang", "-arch", "arm64"])
        .arg(&obj)
        .arg(&dep)
        .arg("-Wl,-rpath,@executable_path/../lib")
        .arg("-o")
        .arg(&theirs)
        .status()
        .expect("spawn clang");
    assert!(status.success(), "clang dep link failed");

    assert_eq!(
        normalize(&command_ids(&ours)),
        normalize(&command_ids(&theirs))
    );

    let _ = fs::remove_file(&obj);
    let _ = fs::remove_file(&dep);
    let _ = fs::remove_file(&ours);
    let _ = fs::remove_file(&theirs);
}
