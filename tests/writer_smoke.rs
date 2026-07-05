use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use afs_ld::layout::Layout;
use afs_ld::macho::constants::{LC_ID_DYLIB, MH_DYLIB, MH_EXECUTE};
use afs_ld::macho::reader::{parse_commands, parse_header, LoadCommand};
use afs_ld::macho::writer::write;
use afs_ld::{LinkOptions, OutputKind};

fn have_tool(name: &str) -> bool {
    Command::new(name)
        .arg("-h")
        .output()
        .map(|_| true)
        .unwrap_or(false)
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("afs-ld-writer-{}-{name}", std::process::id()))
}

fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
    let path = scratch(name);
    fs::write(&path, bytes).expect("write temp mach-o");
    path
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

fn run_file(path: &Path) -> Result<String, String> {
    let out = Command::new("file")
        .arg(path)
        .output()
        .map_err(|e| format!("spawn file: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "file failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn empty_executable_writer_emits_parseable_macho() {
    let layout = Layout::empty(OutputKind::Executable, 0);
    let opts = LinkOptions::default();
    let mut bytes = Vec::new();
    write(&layout, OutputKind::Executable, &opts, &mut bytes).expect("write executable");

    let hdr = parse_header(&bytes).expect("header parses");
    assert_eq!(hdr.filetype, MH_EXECUTE);
    let cmds = parse_commands(&hdr, &bytes).expect("commands parse");
    assert!(
        cmds.iter()
            .any(|cmd| matches!(cmd, LoadCommand::Segment64(seg) if seg.segname_str() == "__TEXT"))
    );

    let path = write_temp("empty-exec", &bytes);
    if have_tool("otool") {
        let dump = run_otool_lv(&path).expect("otool -lV");
        assert!(dump.contains("LC_MAIN"));
        assert!(dump.contains("segname __TEXT"));
    }
    if have_tool("file") {
        let desc = run_file(&path).expect("file");
        // Token order varies by `file` implementation: macOS says
        // "…executable arm64", FreeBSD's file-5.46 says "…arm64
        // executable". Assert the tokens, not the order.
        assert!(macho_desc_matches(&desc, "executable"), "unexpected file desc: {desc}");
    }
    let _ = fs::remove_file(path);
}

/// True when `desc` names a Mach-O 64-bit arm64 image of the given kind
/// ("executable" or "dynamically linked shared library"), tolerant of
/// the token ordering different `file` builds emit.
fn macho_desc_matches(desc: &str, kind: &str) -> bool {
    desc.contains("Mach-O")
        && desc.contains("64-bit")
        && desc.contains("arm64")
        && desc.contains(kind)
}

#[test]
fn empty_dylib_writer_emits_parseable_macho() {
    let layout = Layout::empty(OutputKind::Dylib, 0);
    let mut opts = LinkOptions {
        kind: OutputKind::Dylib,
        ..LinkOptions::default()
    };
    opts.output = Some(PathBuf::from("libempty.dylib"));

    let mut bytes = Vec::new();
    write(&layout, OutputKind::Dylib, &opts, &mut bytes).expect("write dylib");

    let hdr = parse_header(&bytes).expect("header parses");
    assert_eq!(hdr.filetype, MH_DYLIB);
    let cmds = parse_commands(&hdr, &bytes).expect("commands parse");
    assert!(cmds.iter().any(|cmd| {
        matches!(cmd, LoadCommand::Dylib(d) if d.cmd == LC_ID_DYLIB && d.name == "@rpath/libempty.dylib")
    }));

    let path = write_temp("empty-dylib.dylib", &bytes);
    if have_tool("otool") {
        let dump = run_otool_lv(&path).expect("otool -lV");
        assert!(dump.contains("LC_ID_DYLIB"));
        assert!(dump.contains("@rpath/libempty.dylib"));
    }
    if have_tool("file") {
        let desc = run_file(&path).expect("file");
        assert!(
            macho_desc_matches(&desc, "dynamically linked shared library"),
            "unexpected file desc: {desc}"
        );
    }
    let _ = fs::remove_file(path);
}
