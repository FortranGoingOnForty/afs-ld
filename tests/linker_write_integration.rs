use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use afs_ld::macho::constants::{LC_LOAD_DYLIB, LC_SOURCE_VERSION, LC_UUID, MH_DYLIB, MH_EXECUTE};
use afs_ld::macho::reader::{parse_commands, parse_header, LoadCommand, Section64Header};

fn have_xcrun() -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg("as")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn have_tool(name: &str) -> bool {
    Command::new(name)
        .arg("-h")
        .output()
        .map(|_| true)
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

fn assemble(src_text: &str, out: &Path) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-link-write-{}-{}.s",
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

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("afs-ld-link-write-{}-{name}", std::process::id()))
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

fn section<'a>(cmds: &'a [LoadCommand], seg: &str, sect: &str) -> &'a Section64Header {
    cmds.iter()
        .find_map(|cmd| match cmd {
            LoadCommand::Segment64(segment) => segment
                .sections
                .iter()
                .find(|s| s.segname_str() == seg && s.sectname_str() == sect),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing section {seg},{sect}"))
}

fn run_otool_lv(path: &Path) -> Result<String, String> {
    let out = Command::new("otool")
        .arg("-lV")
        .arg(path)
        .output()
        .map_err(|e| format!("spawn otool -lV: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "otool -lV failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn fixture_source() -> &'static str {
    r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        .p2align 2
        _main:
            ret

        .section __TEXT,__cstring,cstring_literals
        _lit:
            .asciz "hi"

        .section __DATA,__data
        .globl _num
        .p2align 3
        _num:
            .quad 0x1122334455667788
    "#
}

#[test]
fn linker_writes_executable_with_real_section_bytes() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("fixture.o");
    let out = scratch("linked-exec");
    if let Err(e) = assemble(fixture_source(), &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }
    link_with_afs_ld(&[obj.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .expect("link executable");

    let bytes = fs::read(&out).expect("read executable");
    let hdr = parse_header(&bytes).expect("parse header");
    assert_eq!(hdr.filetype, MH_EXECUTE);
    let cmds = parse_commands(&hdr, &bytes).expect("parse commands");

    let text = section(&cmds, "__TEXT", "__text");
    assert_eq!(
        &bytes[text.offset as usize..text.offset as usize + text.size as usize],
        &[0xc0, 0x03, 0x5f, 0xd6]
    );

    let cstring = section(&cmds, "__TEXT", "__cstring");
    assert_eq!(
        &bytes[cstring.offset as usize..cstring.offset as usize + cstring.size as usize],
        b"hi\0"
    );

    let data = section(&cmds, "__DATA", "__data");
    assert_eq!(
        &bytes[data.offset as usize..data.offset as usize + data.size as usize],
        &0x1122_3344_5566_7788u64.to_le_bytes()
    );

    if have_tool("otool") {
        let dump = run_otool_lv(&out).expect("otool -lV");
        assert!(dump.contains("segname __TEXT"));
        assert!(dump.contains("sectname __cstring"));
        assert!(dump.contains("segname __DATA"));
    }

    let _ = fs::remove_file(&obj);
    let _ = fs::remove_file(&out);
}

#[test]
fn linker_writes_dylib_with_real_text_section() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("fixture-dylib.o");
    let out = scratch("libfixture.dylib");
    if let Err(e) = assemble(fixture_source(), &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }
    link_with_afs_ld(&["-dylib", obj.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .expect("link dylib");

    let bytes = fs::read(&out).expect("read dylib");
    let hdr = parse_header(&bytes).expect("parse header");
    assert_eq!(hdr.filetype, MH_DYLIB);
    let cmds = parse_commands(&hdr, &bytes).expect("parse commands");

    let text = section(&cmds, "__TEXT", "__text");
    assert_eq!(
        &bytes[text.offset as usize..text.offset as usize + text.size as usize],
        &[0xc0, 0x03, 0x5f, 0xd6]
    );

    let _ = fs::remove_file(&obj);
    let _ = fs::remove_file(&out);
}

#[test]
fn linker_emits_load_dylib_for_direct_dependency_input() {
    if !have_xcrun() || !have_clang() {
        eprintln!("skipping: xcrun as / clang unavailable");
        return;
    }

    let obj = scratch("dep-main.o");
    let dep = scratch("libdep.dylib");
    let out = scratch("dep-linked");
    if let Err(e) = assemble(
        r#"
            .section __TEXT,__text,regular,pure_instructions
            .globl _main
            _main:
                ret
        "#,
        &obj,
    ) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }
    if let Err(e) = build_test_dylib(
        "int afsld_dep(void) { return 7; }\n",
        &dep,
        "@rpath/libafslddep.dylib",
    ) {
        eprintln!("skipping: clang failed: {e}");
        return;
    }

    link_with_afs_ld(&[
        obj.to_str().unwrap(),
        dep.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ])
    .expect("link executable with dylib");

    let bytes = fs::read(&out).expect("read executable");
    let hdr = parse_header(&bytes).expect("parse header");
    let cmds = parse_commands(&hdr, &bytes).expect("parse commands");
    assert!(cmds.iter().any(|cmd| {
        matches!(
            cmd,
            LoadCommand::Dylib(d)
                if d.cmd == LC_LOAD_DYLIB && d.name == "@rpath/libafslddep.dylib"
        )
    }));

    let _ = fs::remove_file(&obj);
    let _ = fs::remove_file(&dep);
    let _ = fs::remove_file(&out);
}

#[test]
fn linker_emits_rpath_load_command() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("rpath-main.o");
    let out = scratch("rpath-linked");
    if let Err(e) = assemble(
        r#"
            .section __TEXT,__text,regular,pure_instructions
            .globl _main
            _main:
                ret
        "#,
        &obj,
    ) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    link_with_afs_ld(&[
        obj.to_str().unwrap(),
        "-rpath",
        "@executable_path/../lib",
        "-o",
        out.to_str().unwrap(),
    ])
    .expect("link executable with rpath");

    let bytes = fs::read(&out).expect("read executable");
    let hdr = parse_header(&bytes).expect("parse header");
    let cmds = parse_commands(&hdr, &bytes).expect("parse commands");
    assert!(cmds.iter().any(|cmd| {
        matches!(
            cmd,
            LoadCommand::Rpath(r) if r.path == "@executable_path/../lib"
        )
    }));

    let _ = fs::remove_file(&obj);
    let _ = fs::remove_file(&out);
}

#[test]
fn linker_emits_uuid_and_source_version_commands() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("uuid-main.o");
    let out = scratch("uuid-linked");
    if let Err(e) = assemble(
        r#"
            .section __TEXT,__text,regular,pure_instructions
            .globl _main
            _main:
                ret
        "#,
        &obj,
    ) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    link_with_afs_ld(&[obj.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .expect("link executable with metadata");

    let bytes = fs::read(&out).expect("read executable");
    let hdr = parse_header(&bytes).expect("parse header");
    let ids: Vec<u32> = parse_commands(&hdr, &bytes)
        .expect("parse commands")
        .into_iter()
        .map(|cmd| match cmd {
            LoadCommand::Raw { cmd, .. } => cmd,
            other => other.cmd(),
        })
        .collect();
    assert!(ids.contains(&LC_UUID));
    assert!(ids.contains(&LC_SOURCE_VERSION));

    let _ = fs::remove_file(&obj);
    let _ = fs::remove_file(&out);
}
