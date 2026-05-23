use std::fs;
use std::path::PathBuf;
use std::process::Command;

use afs_ld::macho::constants::{
    CPU_TYPE_ARM64, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE, LC_SEGMENT_64, LC_UUID,
    MH_MAGIC_64, MH_OBJECT,
};
use afs_ld::macho::reader::{parse_commands, parse_header, LoadCommand};

const EXPECTED_HELP: &str = include_str!("snapshots/help.txt");
const EXPECTED_BAD_FLAG: &str = include_str!("snapshots/bad_flag.stderr");
const EXPECTED_DUPLICATE_SYMBOL: &str = include_str!("snapshots/duplicate_symbol.stderr");
const EXPECTED_MALFORMED_INPUT: &str = include_str!("snapshots/malformed_input.stderr");
const EXPECTED_MISSING_LIBRARY: &str = include_str!("snapshots/missing_library.stderr");
const EXPECTED_UNDEFINED_SYMBOL: &str = include_str!("snapshots/undefined_symbol.stderr");

fn have_xcrun() -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg("as")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn sdk_path() -> Option<String> {
    let out = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn minimal_main_src() -> &'static str {
    r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#
}

fn assemble(src: &str, out: &PathBuf) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-cli-diag-{}-{}.s",
        std::process::id(),
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("t")
    ));
    fs::write(&tmp, src).map_err(|e| format!("write: {e}"))?;
    let output = Command::new("xcrun")
        .args(["--sdk", "macosx", "as", "-arch", "arm64"])
        .arg(&tmp)
        .arg("-o")
        .arg(out)
        .output()
        .map_err(|e| format!("spawn xcrun as: {e}"))?;
    let _ = fs::remove_file(&tmp);
    if !output.status.success() {
        return Err(format!(
            "xcrun as failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("afs-ld-cli-diag-{}-{name}", std::process::id()))
}

fn normalize_stderr(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let scratch_prefix = std::env::temp_dir()
        .join(format!("afs-ld-cli-diag-{}-", std::process::id()))
        .display()
        .to_string();
    text.replace(&scratch_prefix, "<TMP>/")
}

fn assert_stderr_snapshot(stderr: &[u8], expected: &str) {
    assert_eq!(normalize_stderr(stderr), expected);
}

fn assemble_minimal_main(name: &str) -> Result<PathBuf, String> {
    let obj = scratch(name);
    assemble(minimal_main_src(), &obj)?;
    Ok(obj)
}

fn malformed_segment_object() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    bytes.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&MH_OBJECT.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&72u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    bytes.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    bytes.extend_from_slice(&72u32.to_le_bytes());
    bytes.extend_from_slice(&[0; 16]);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

fn assert_flag_errors(flag: &str, expected: &str, name: &str) {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = match assemble_minimal_main(&format!("{name}.o")) {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    };
    let out_path = scratch(&format!("{name}.out"));
    let out = Command::new(exe)
        .arg(flag)
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(!out.status.success(), "{flag} should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(expected),
        "missing expected `{expected}` in stderr:\n{stderr}"
    );
    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

fn archive(objects: &[&PathBuf], out: &PathBuf) -> Result<(), String> {
    let output = Command::new("libtool")
        .arg("-static")
        .arg("-o")
        .arg(out)
        .args(objects)
        .output()
        .map_err(|e| format!("spawn libtool: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "libtool failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn nm_defined_names(path: &PathBuf) -> Result<Vec<String>, String> {
    let output = Command::new("xcrun")
        .args(["nm", "-gj"])
        .arg(path)
        .output()
        .map_err(|e| format!("spawn xcrun nm: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "xcrun nm failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

#[test]
fn help_flag_prints_usage_and_exits_successfully() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .arg("--help")
        .output()
        .expect("afs-ld should run");
    assert!(out.status.success(), "help should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.as_ref(), EXPECTED_HELP);
    assert!(
        out.stderr.is_empty(),
        "help should not write to stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn version_flag_prints_version_and_exits_successfully() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .arg("--version")
        .output()
        .expect("afs-ld should run");
    assert!(out.status.success(), "version should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let expected_prefix = format!(
        "afs-ld {}\n\
         Bespoke ARM64 Mach-O linker for armfortas\n\
         Target: arm64-apple-macos\n\
         Commit: ",
        env!("CARGO_PKG_VERSION")
    );
    assert!(
        stdout.starts_with(&expected_prefix),
        "unexpected version output:\n{stdout}"
    );
    let commit = stdout
        .strip_prefix(&expected_prefix)
        .and_then(|rest| rest.strip_suffix('\n'))
        .expect("commit line");
    assert!(!commit.is_empty(), "commit hash should not be empty");
}

#[test]
fn verbose_flag_prints_summary_and_continues_to_link() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .args(["--color=never", "-v"])
        .output()
        .expect("afs-ld should run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "-v alone should still require input"
    );
    assert!(
        out.stdout.is_empty(),
        "-v summary should not go to stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("afs-ld {}", env!("CARGO_PKG_VERSION"))),
        "missing version line:\n{stderr}"
    );
    assert!(
        stderr.contains("Target: arm64-apple-macos"),
        "missing target line:\n{stderr}"
    );
    assert!(
        stderr.contains("Mode: executable"),
        "missing output kind summary:\n{stderr}"
    );
    assert!(
        stderr.contains(
            "Flags: dead_strip=false icf=none thunks=safe fixups=auto trace=false verbose_deprecation=false color=never"
        ),
        "missing active flag summary:\n{stderr}"
    );
    assert!(
        stderr.contains("afs-ld: error: no input files"),
        "-v should continue into link validation:\n{stderr}"
    );
}

#[test]
fn mistyped_arch_suggests_arm64_and_exits_as_cli_misuse() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .args(["-arch", "arm86"])
        .output()
        .expect("afs-ld should run");
    assert_eq!(out.status.code(), Some(2), "bad -arch is CLI misuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("flag `-arch` got invalid value `arm86` (expected `arm64`)"),
        "missing invalid-arch diagnostic:\n{stderr}"
    );
    assert!(
        stderr.contains("did you mean `arm64`?"),
        "missing arm64 suggestion:\n{stderr}"
    );
}

#[test]
fn missing_input_exits_noinput_and_cites_path() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let missing = scratch("does-not-exist.o");
    let out_path = scratch("missing-input.out");
    let _ = fs::remove_file(&missing);
    let _ = fs::remove_file(&out_path);

    let out = Command::new(exe)
        .arg("-o")
        .arg(&out_path)
        .arg(&missing)
        .output()
        .expect("afs-ld should run");
    assert_eq!(
        out.status.code(),
        Some(66),
        "missing input should use EX_NOINPUT:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("afs-ld: error: {}", missing.display())),
        "missing path in diagnostic:\n{stderr}"
    );
    assert!(
        stderr.contains("No such file") || stderr.contains("not found"),
        "missing no-input reason:\n{stderr}"
    );
}

#[test]
fn color_always_colors_parse_errors() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .env_remove("NO_COLOR")
        .args(["--color=always", "-all_lod"])
        .output()
        .expect("afs-ld should run");
    assert_eq!(out.status.code(), Some(2), "bad flag is CLI misuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("\x1b[31mafs-ld: error:\x1b[0m"),
        "expected colored error prefix:\n{stderr:?}"
    );
    assert!(
        stderr.contains("did you mean `-all_load`?"),
        "missing did-you-mean diagnostic:\n{stderr}"
    );
}

#[test]
fn bad_flag_diagnostic_matches_snapshot() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .args(["--color=never", "-all_lod"])
        .output()
        .expect("afs-ld should run");
    assert_eq!(out.status.code(), Some(2), "bad flag is CLI misuse");
    assert_stderr_snapshot(&out.stderr, EXPECTED_BAD_FLAG);
}

#[test]
fn malformed_object_diagnostic_includes_hex_caret() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("bad-segment.o");
    fs::write(&obj, malformed_segment_object()).expect("write malformed object");

    let out = Command::new(exe)
        .args(["--color=never"])
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert_eq!(
        out.status.code(),
        Some(65),
        "malformed input should use EX_DATAERR"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("in {} at byte 0x60", obj.display())),
        "missing path and byte offset:\n{stderr}"
    );
    assert!(
        stderr.contains("nsects implies more bytes than cmdsize accommodates"),
        "missing structural reason:\n{stderr}"
    );
    assert!(
        stderr.contains("  0x0060: 01 00 00 00 00 00 00 00"),
        "missing hex dump:\n{stderr}"
    );
    assert!(stderr.contains("  ^^^^^^^^^^^"), "missing caret:\n{stderr}");

    let _ = fs::remove_file(obj);
}

#[test]
fn malformed_object_diagnostic_matches_snapshot() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("malformed-snapshot.o");
    fs::write(&obj, malformed_segment_object()).expect("write malformed object");

    let out = Command::new(exe)
        .args(["--color=never"])
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert_eq!(
        out.status.code(),
        Some(65),
        "malformed input should use EX_DATAERR"
    );
    assert_stderr_snapshot(&out.stderr, EXPECTED_MALFORMED_INPUT);

    let _ = fs::remove_file(obj);
}

#[test]
fn color_never_suppresses_parse_error_color() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .args(["--color=never", "-all_lod"])
        .output()
        .expect("afs-ld should run");
    assert_eq!(out.status.code(), Some(2), "bad flag is CLI misuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("\x1b["),
        "expected --color=never to suppress ANSI escapes:\n{stderr:?}"
    );
    assert!(
        stderr.contains("afs-ld: error: unknown flag `-all_lod`"),
        "missing plain error prefix:\n{stderr}"
    );
}

#[test]
fn no_color_env_suppresses_forced_color() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = Command::new(exe)
        .env("NO_COLOR", "1")
        .args(["--color=always", "-all_lod"])
        .output()
        .expect("afs-ld should run");
    assert_eq!(out.status.code(), Some(2), "bad flag is CLI misuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("\x1b["),
        "expected NO_COLOR to suppress ANSI escapes:\n{stderr:?}"
    );
    assert!(
        stderr.contains("afs-ld: error: unknown flag `-all_lod`"),
        "missing plain error prefix:\n{stderr}"
    );
}

#[test]
fn color_auto_colors_parse_errors_on_tty() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let out = match Command::new("script")
        .env_remove("NO_COLOR")
        .env("AFS_LD_EXE", exe)
        .arg("-q")
        .arg("/dev/null")
        .arg("sh")
        .arg("-c")
        .arg("\"$AFS_LD_EXE\" -all_lod 2>&1")
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            eprintln!("skipping: script PTY harness unavailable: {e}");
            return;
        }
    };
    assert_eq!(
        out.status.code(),
        Some(2),
        "script should propagate afs-ld CLI-misuse exit"
    );
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    assert!(
        combined.contains("\x1b[31mafs-ld: error:\x1b[0m"),
        "expected auto color on PTY stderr/stdout stream:\n{combined:?}"
    );
}

#[test]
fn missing_library_suggests_near_match() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let dir = scratch("library-suggestion-dir");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create library suggestion dir");
    fs::write(dir.join("libfoozle.a"), b"!<arch>\n").expect("write placeholder library");

    let out = Command::new(exe)
        .arg("-L")
        .arg(&dir)
        .arg("-lfoozl")
        .output()
        .expect("afs-ld should run");
    assert_eq!(
        out.status.code(),
        Some(1),
        "missing library is a link failure"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unable to find library `foozl`"),
        "missing library diagnostic:\n{stderr}"
    );
    assert!(
        stderr.contains("did you mean `-lfoozle`?"),
        "missing library suggestion:\n{stderr}"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn missing_library_diagnostic_matches_snapshot() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let dir = scratch("library-snapshot-dir");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create library snapshot dir");
    fs::write(dir.join("libfoozle.a"), b"!<arch>\n").expect("write placeholder library");

    let out = Command::new(exe)
        .args(["--color=never"])
        .arg("-L")
        .arg(&dir)
        .arg("-lfoozl")
        .output()
        .expect("afs-ld should run");
    assert_eq!(
        out.status.code(),
        Some(1),
        "missing library is a link failure"
    );
    assert_stderr_snapshot(&out.stderr, EXPECTED_MISSING_LIBRARY);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn missing_framework_suggests_case_near_match() {
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let sdk = scratch("framework-suggestion-sdk");
    let frameworks = sdk.join("System/Library/Frameworks");
    let framework = frameworks.join("Quartz.framework");
    let _ = fs::remove_dir_all(&sdk);
    fs::create_dir_all(&framework).expect("create framework suggestion dir");
    fs::write(framework.join("Quartz.tbd"), b"--- !tapi-tbd\n").expect("write placeholder tbd");

    let out = Command::new(exe)
        .arg("-syslibroot")
        .arg(&sdk)
        .args(["-framework", "Qurtz"])
        .output()
        .expect("afs-ld should run");
    assert_eq!(
        out.status.code(),
        Some(1),
        "missing framework is a link failure"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unable to find framework `Qurtz`"),
        "missing framework diagnostic:\n{stderr}"
    );
    assert!(
        stderr.contains("did you mean `-framework Quartz`?"),
        "missing framework suggestion:\n{stderr}"
    );

    let _ = fs::remove_dir_all(sdk);
}

#[test]
fn no_uuid_flag_omits_uuid_load_command() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = match assemble_minimal_main("no-uuid-main.o") {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    };
    let out_path = scratch("no-uuid.out");
    let out = Command::new(exe)
        .arg("-no_uuid")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-no_uuid link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bytes = fs::read(&out_path).expect("read linked output");
    let header = parse_header(&bytes).expect("parse header");
    let commands = parse_commands(&header, &bytes).expect("parse commands");
    assert!(
        commands.iter().all(|cmd| match cmd {
            LoadCommand::Raw { cmd, .. } => *cmd != LC_UUID,
            _ => true,
        }),
        "expected -no_uuid output to omit LC_UUID"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn no_loh_flag_warns_but_links_successfully() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = match assemble_minimal_main("no-loh-main.o") {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    };
    let out_path = scratch("no-loh.out");
    let out = Command::new(exe)
        .arg("-no_loh")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-no_loh link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: warning: `-no_loh` requested"),
        "expected -no_loh warning:\n{stderr}"
    );
    assert!(
        out_path.is_file(),
        "expected -no_loh link to produce {}",
        out_path.display()
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn strip_debug_flag_warns_but_links_successfully() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = match assemble_minimal_main("strip-debug-main.o") {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    };
    let out_path = scratch("strip-debug.out");
    let out = Command::new(exe)
        .arg("-S")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-S link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: warning: `-S` requested"),
        "expected -S warning:\n{stderr}"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn verbose_deprecation_warns_for_deprecated_compatibility_flags() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = match assemble_minimal_main("verbose-deprecation-main.o") {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    };
    let out_path = scratch("verbose-deprecation.out");
    let out = Command::new(exe)
        .arg("-verbose_deprecation")
        .arg("-S")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-verbose_deprecation link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("deprecated compatibility flag `-S` accepted"),
        "expected verbose deprecation warning:\n{stderr}"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn objc_flag_warns_but_links_successfully() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = match assemble_minimal_main("objc-main.o") {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    };
    let out_path = scratch("objc.out");
    let out = Command::new(exe)
        .arg("-ObjC")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-ObjC link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: warning: `-ObjC` requested"),
        "expected -ObjC warning:\n{stderr}"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn relocatable_flag_errors_loudly() {
    assert_flag_errors(
        "-r",
        "`-r` relocatable output is not yet supported",
        "relocatable",
    );
}

#[test]
fn bundle_flag_errors_loudly() {
    assert_flag_errors("-bundle", "`-bundle` output is not yet supported", "bundle");
}

#[test]
fn dead_strip_removes_unreferenced_symbols_and_reports_why_live() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let main_obj = scratch("dead-strip-main.o");
    let helper_obj = scratch("dead-strip-helper.o");
    let unused_obj = scratch("dead-strip-unused.o");
    let out_path = scratch("dead-strip.out");
    let main_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _helper
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    let helper_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _helper
        _helper:
            ret
        .subsections_via_symbols
    "#;
    let unused_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _unused
        _unused:
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(main_src, &main_obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }
    if let Err(e) = assemble(helper_src, &helper_obj) {
        eprintln!("skipping: assemble failed: {e}");
        let _ = fs::remove_file(main_obj);
        return;
    }
    if let Err(e) = assemble(unused_src, &unused_obj) {
        eprintln!("skipping: assemble failed: {e}");
        let _ = fs::remove_file(main_obj);
        let _ = fs::remove_file(helper_obj);
        return;
    }

    let out = Command::new(exe)
        .arg("-dead_strip")
        .arg("-why_live")
        .arg("_helper")
        .arg("-why_live")
        .arg("_unused")
        .arg("-o")
        .arg(&out_path)
        .arg(&main_obj)
        .arg(&helper_obj)
        .arg(&unused_obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-dead_strip link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_helper is live because:"));
    assert!(stdout.contains("_helper is reachable from _main"));
    assert!(stdout.contains("_main is in -e _main (GC root)"));
    assert!(stdout.contains("_unused is not live (dead-stripped)"));

    let symbols = match nm_defined_names(&out_path) {
        Ok(symbols) => symbols,
        Err(e) => {
            panic!("nm failed: {e}");
        }
    };
    assert!(symbols.contains(&"_main".to_string()));
    assert!(symbols.contains(&"_helper".to_string()));
    assert!(
        !symbols.contains(&"_unused".to_string()),
        "dead-stripped symbol still present:\n{}",
        symbols.join("\n")
    );

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(helper_obj);
    let _ = fs::remove_file(unused_obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn dead_strip_keeps_no_dead_strip_roots() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("dead-strip-no-dead-strip.o");
    let out_path = scratch("dead-strip-no-dead-strip.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret

        .globl _keep
        _keep:
            ret
        .desc _keep, 0x20

        .globl _drop
        _drop:
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let out = Command::new(exe)
        .arg("-dead_strip")
        .arg("-why_live")
        .arg("_keep")
        .arg("-why_live")
        .arg("_drop")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-dead_strip link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_keep is live because:"));
    assert!(stdout.contains("_keep is marked N_NO_DEAD_STRIP (GC root)"));
    assert!(stdout.contains("_drop is not live (dead-stripped)"));

    let symbols = match nm_defined_names(&out_path) {
        Ok(symbols) => symbols,
        Err(e) => {
            panic!("nm failed: {e}");
        }
    };
    assert!(symbols.contains(&"_main".to_string()));
    assert!(symbols.contains(&"_keep".to_string()));
    assert!(
        !symbols.contains(&"_drop".to_string()),
        "dead-stripped symbol still present:\n{}",
        symbols.join("\n")
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn icf_safe_flag_links_successfully() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = match assemble_minimal_main("icf-safe-main.o") {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    };
    let out_path = scratch("icf-safe.out");
    let out = Command::new(exe)
        .arg("-icf=safe")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-icf=safe link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out_path.is_file(),
        "expected -icf=safe link to produce {}",
        out_path.display()
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn icf_all_flag_errors_loudly() {
    assert_flag_errors(
        "-icf=all",
        "`-icf=all` is not yet supported; use `-icf=safe` or `-icf=none`",
        "icf-all",
    );
}

#[test]
fn fixup_chains_flag_emits_chained_load_commands() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }
    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = match assemble_minimal_main("fixup-chains.o") {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    };
    let out_path = scratch("fixup-chains.out");
    let out = Command::new(exe)
        .arg("-fixup_chains")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-fixup_chains link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bytes = fs::read(&out_path).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    assert!(commands
        .iter()
        .any(|cmd| matches!(cmd, LoadCommand::DyldChainedFixups(_))));
    assert!(commands
        .iter()
        .any(|cmd| matches!(cmd, LoadCommand::DyldExportsTrie(_))));
    assert!(!commands
        .iter()
        .any(|cmd| matches!(cmd, LoadCommand::DyldInfoOnly(_))));

    let command_ids: Vec<u32> = commands.iter().map(LoadCommand::cmd).collect();
    assert!(command_ids.contains(&LC_DYLD_CHAINED_FIXUPS));
    assert!(command_ids.contains(&LC_DYLD_EXPORTS_TRIE));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn undefined_symbol_diagnostic_is_not_double_prefixed() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("missing.o");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _missing
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let out = Command::new(exe)
        .arg("-o")
        .arg(scratch("missing.out"))
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: error: undefined symbol: _missing"),
        "missing expected undefined-symbol diagnostic:\n{stderr}"
    );
    assert!(
        !stderr.contains("afs-ld: error: afs-ld: error:"),
        "diagnostic was double-prefixed:\n{stderr}"
    );

    let _ = fs::remove_file(obj);
}

#[test]
fn undefined_symbol_diagnostic_matches_snapshot() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("undefined-snapshot.o");
    let out_path = scratch("undefined-snapshot.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _missing_snapshot
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let out = Command::new(exe)
        .args(["--color=never"])
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert_eq!(
        out.status.code(),
        Some(1),
        "undefined symbol is a link failure"
    );
    assert_stderr_snapshot(&out.stderr, EXPECTED_UNDEFINED_SYMBOL);

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn duplicate_symbol_diagnostic_matches_snapshot() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let first = scratch("duplicate-a.o");
    let second = scratch("duplicate-b.o");
    let out_path = scratch("duplicate.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _dup_snapshot
        _dup_snapshot:
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &first) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }
    if let Err(e) = assemble(src, &second) {
        eprintln!("skipping: assemble failed: {e}");
        let _ = fs::remove_file(first);
        return;
    }

    let out = Command::new(exe)
        .args(["--color=never"])
        .arg("-o")
        .arg(&out_path)
        .arg(&first)
        .arg(&second)
        .output()
        .expect("afs-ld should run");
    assert_eq!(
        out.status.code(),
        Some(1),
        "duplicate symbol is a link failure"
    );
    assert_stderr_snapshot(&out.stderr, EXPECTED_DUPLICATE_SYMBOL);

    let _ = fs::remove_file(first);
    let _ = fs::remove_file(second);
    let _ = fs::remove_file(out_path);
}

#[test]
fn undefined_warning_mode_links_and_warns_once() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("missing-warning.o");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _missing
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let out_path = scratch("missing-warning.out");
    let out = Command::new(exe)
        .arg("-undefined")
        .arg("warning")
        .arg("-syslibroot")
        .arg(&sdk)
        .arg("-lSystem")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-undefined warning should link successfully:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("afs-ld: warning: undefined symbol: _missing"),
        "missing expected undefined-symbol warning:\n{stderr}"
    );
    assert!(
        !stderr.contains("afs-ld: warning: afs-ld: warning:"),
        "warning diagnostic was double-prefixed:\n{stderr}"
    );
    assert!(out_path.exists(), "expected linked output to be written");

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn undefined_suppress_mode_links_silently() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("missing-suppress.o");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _missing
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let out_path = scratch("missing-suppress.out");
    let out = Command::new(exe)
        .arg("-undefined")
        .arg("suppress")
        .arg("-syslibroot")
        .arg(&sdk)
        .arg("-lSystem")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "-undefined suppress should link successfully:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("undefined symbol: _missing"),
        "expected -undefined suppress to omit undefined diagnostic:\n{stderr}"
    );
    assert!(out_path.exists(), "expected linked output to be written");

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn trace_flag_prints_loaded_inputs_and_archive_members() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let main_obj = scratch("trace-main.o");
    let helper_obj = scratch("trace-helper.o");
    let archive_path = scratch("libtracehelpers.a");
    let out_path = scratch("trace.out");
    let main_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _helper
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    let helper_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _helper
        _helper:
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(main_src, &main_obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }
    if let Err(e) = assemble(helper_src, &helper_obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }
    if let Err(e) = archive(&[&helper_obj], &archive_path) {
        eprintln!("skipping: archive failed: {e}");
        let _ = fs::remove_file(main_obj);
        let _ = fs::remove_file(helper_obj);
        return;
    }

    let out = Command::new(exe)
        .arg("--trace")
        .arg("-o")
        .arg(&out_path)
        .arg(&main_obj)
        .arg(&archive_path)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "trace link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("afs-ld: loading {}", main_obj.display())),
        "missing main object trace:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("afs-ld: loading {}", archive_path.display())),
        "missing archive trace:\n{stderr}"
    );
    assert!(
        stderr.contains("libtracehelpers.a("),
        "missing fetched archive member trace:\n{stderr}"
    );

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(helper_obj);
    let _ = fs::remove_file(archive_path);
    let _ = fs::remove_file(out_path);
}

#[test]
fn why_live_reports_root_entry_symbol() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let main_obj = scratch("why-live-root-main.o");
    let out_path = scratch("why-live-root.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &main_obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let out = Command::new(exe)
        .arg("-why_live")
        .arg("_main")
        .arg("-o")
        .arg(&out_path)
        .arg(&main_obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "why_live link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_main is live because:"));
    assert!(stdout.contains("-dead_strip was not requested"));
    assert!(stdout.contains("_main is in -e _main (GC root)"));

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn why_live_reports_transitive_symbol_chain() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let main_obj = scratch("why-live-main.o");
    let helper_obj = scratch("why-live-helper.o");
    let leaf_obj = scratch("why-live-leaf.o");
    let out_path = scratch("why-live.out");
    let main_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _helper
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    let helper_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _helper
        _helper:
            bl _leaf
            ret
        .subsections_via_symbols
    "#;
    let leaf_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _leaf
        _leaf:
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(main_src, &main_obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }
    if let Err(e) = assemble(helper_src, &helper_obj) {
        eprintln!("skipping: assemble failed: {e}");
        let _ = fs::remove_file(main_obj);
        return;
    }
    if let Err(e) = assemble(leaf_src, &leaf_obj) {
        eprintln!("skipping: assemble failed: {e}");
        let _ = fs::remove_file(main_obj);
        let _ = fs::remove_file(helper_obj);
        return;
    }

    let out = Command::new(exe)
        .arg("-why_live")
        .arg("_leaf")
        .arg("-o")
        .arg(&out_path)
        .arg(&main_obj)
        .arg(&helper_obj)
        .arg(&leaf_obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "why_live link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_leaf is live because:"));
    assert!(stdout.contains("-dead_strip was not requested"));
    assert!(stdout.contains("_leaf is reachable from _helper"));
    assert!(stdout.contains("_helper is reachable from _main"));
    assert!(stdout.contains("_main is in -e _main (GC root)"));

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(helper_obj);
    let _ = fs::remove_file(leaf_obj);
    let _ = fs::remove_file(out_path);
}

#[test]
fn why_live_reports_folded_symbol_winner_chain() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_afs-ld");
    let obj = scratch("why-live-folded.o");
    let out_path = scratch("why-live-folded.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            stp x29, x30, [sp, #-16]!
            mov x29, sp
            bl _helper1
            bl _helper2
            mov w0, #0
            ldp x29, x30, [sp], #16
            ret

        .private_extern _helper1
        _helper1:
            mov w0, #0
            ret

        .private_extern _helper2
        _helper2:
            mov w0, #0
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let out = Command::new(exe)
        .arg("-icf=safe")
        .arg("-why_live")
        .arg("_helper2")
        .arg("-o")
        .arg(&out_path)
        .arg(&obj)
        .output()
        .expect("afs-ld should run");
    assert!(
        out.status.success(),
        "why_live folded-symbol link should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("_helper2 was folded to _helper1 by -icf=safe"));
    assert!(stdout.contains("_helper1 is live because:"));
    assert!(stdout.contains("_helper1 is reachable from _main"));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out_path);
}
