//! Sprint 10 integration gate: minimal executable/dylib outputs are accepted
//! by the platform inspection tools.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use afs_ld::layout::Layout;
use afs_ld::macho::writer;
use afs_ld::{LinkOptions, OutputKind};

fn have_xcrun_tool(tool: &str) -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn have_file() -> bool {
    Command::new("file")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("afs-ld-sprint10-{}-{name}", std::process::id()))
}

fn write_image(path: &Path, kind: OutputKind) {
    let mut bytes = Vec::new();
    let opts = LinkOptions {
        output: Some(path.to_path_buf()),
        kind,
        ..LinkOptions::default()
    };
    writer::write(&Layout::empty(kind, 0), kind, &opts, &mut bytes).unwrap();
    fs::write(path, bytes).unwrap();
}

#[test]
fn minimal_outputs_pass_otool_and_file() {
    if !have_xcrun_tool("otool") || !have_file() {
        eprintln!("skipping: xcrun otool or file unavailable");
        return;
    }

    let exe = scratch("tiny");
    let dylib = scratch("libtiny.dylib");
    write_image(&exe, OutputKind::Executable);
    write_image(&dylib, OutputKind::Dylib);

    for (path, expected) in [
        (&exe, "Mach-O 64-bit executable arm64"),
        (
            &dylib,
            "Mach-O 64-bit dynamically linked shared library arm64",
        ),
    ] {
        let otool = Command::new("xcrun")
            .args(["otool", "-lV"])
            .arg(path)
            .output()
            .unwrap();
        assert!(
            otool.status.success(),
            "otool failed for {}:\nstdout:\n{}\nstderr:\n{}",
            path.display(),
            String::from_utf8_lossy(&otool.stdout),
            String::from_utf8_lossy(&otool.stderr)
        );

        let file = Command::new("file").arg(path).output().unwrap();
        assert!(file.status.success(), "file failed for {}", path.display());
        let text = String::from_utf8_lossy(&file.stdout);
        assert!(
            text.contains(expected),
            "expected `{expected}` in file output for {} but got:\n{text}",
            path.display()
        );
    }

    let _ = fs::remove_file(exe);
    let _ = fs::remove_file(dylib);
}
