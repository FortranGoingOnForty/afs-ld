//! End-to-end `Linker::run` coverage for Sprint 10's newly wired pipeline.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

mod common;

use afs_ld::macho::reader::{parse_commands, parse_header, LoadCommand};
use afs_ld::{LinkError, LinkOptions, Linker, OutputKind};
use common::harness::diff_macho;

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

fn sdk_version() -> Option<String> {
    let out = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-version"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn have_xcrun_tool(tool: &str) -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn assemble(src: &str, out: &PathBuf) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-linker-run-{}-{}.s",
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
    std::env::temp_dir().join(format!("afs-ld-linker-run-{}-{name}", std::process::id()))
}

fn output_section(bytes: &[u8], segname: &str, sectname: &str) -> Option<(u64, Vec<u8>)> {
    let header = parse_header(bytes).ok()?;
    let commands = parse_commands(&header, bytes).ok()?;
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            for section in seg.sections {
                if section.segname_str() == segname && section.sectname_str() == sectname {
                    let data = if section.offset == 0 {
                        Vec::new()
                    } else {
                        let start = section.offset as usize;
                        let end = start + section.size as usize;
                        bytes.get(start..end)?.to_vec()
                    };
                    return Some((section.addr, data));
                }
            }
        }
    }
    None
}

fn apple_link(
    obj: &PathBuf,
    out: &PathBuf,
    entry: &str,
    syslibroot: &str,
    platform_version: &str,
) -> Result<(), String> {
    let output = Command::new("xcrun")
        .args([
            "ld",
            "-arch",
            "arm64",
            "-platform_version",
            "macos",
            platform_version,
            platform_version,
            "-syslibroot",
            syslibroot,
            "-lSystem",
            "-e",
            entry,
            "-o",
        ])
        .arg(out)
        .arg(obj)
        .output()
        .map_err(|e| format!("spawn xcrun ld: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "xcrun ld failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct SectionCase {
    segname: &'static str,
    sectname: &'static str,
}

#[derive(Clone, Copy)]
enum PageRefKind {
    Add,
    Load,
}

enum ParityCheck {
    ExactSections(&'static [SectionCase]),
    PageRef {
        section: SectionCase,
        site_offset: u64,
        target_offset: u64,
        kind: PageRefKind,
    },
}

struct ParityCase {
    name: &'static str,
    src: &'static str,
    check: ParityCheck,
}

fn assert_case_matches_apple_ld(
    case: &ParityCase,
    sdk: &str,
    sdk_ver: &str,
) -> Result<(), String> {
    let obj = scratch(&format!("parity-{}.o", case.name));
    let our_out = scratch(&format!("parity-{}-ours.out", case.name));
    let apple_out = scratch(&format!("parity-{}-apple.out", case.name));

    assemble(case.src, &obj)?;

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(our_out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).map_err(|e| format!("afs-ld link failed for {}: {e}", case.name))?;
    apple_link(&obj, &apple_out, "_main", sdk, sdk_ver)?;

    let our_bytes = fs::read(&our_out).map_err(|e| format!("read our output: {e}"))?;
    let apple_bytes = fs::read(&apple_out).map_err(|e| format!("read apple output: {e}"))?;

    match case.check {
        ParityCheck::ExactSections(sections) => {
            for section in sections {
                let (_, ours) = output_section(&our_bytes, section.segname, section.sectname)
                    .ok_or_else(|| {
                        format!("missing our section {},{}", section.segname, section.sectname)
                    })?;
                let (_, theirs) = output_section(&apple_bytes, section.segname, section.sectname)
                    .ok_or_else(|| {
                        format!(
                            "missing apple section {},{}",
                            section.segname, section.sectname
                        )
                    })?;
                let diff = diff_macho(&ours, &theirs);
                if !diff.is_clean() {
                    return Err(format!(
                        "{}: section {},{} diverged from Apple ld: {:#?}",
                        case.name, section.segname, section.sectname, diff.critical
                    ));
                }
            }
        }
        ParityCheck::PageRef {
            section,
            site_offset,
            target_offset,
            kind,
        } => {
            let (our_addr, our_bytes_sec) = output_section(&our_bytes, section.segname, section.sectname)
                .ok_or_else(|| format!("missing our section {},{}", section.segname, section.sectname))?;
            let (apple_addr, apple_bytes_sec) =
                output_section(&apple_bytes, section.segname, section.sectname).ok_or_else(|| {
                    format!("missing apple section {},{}", section.segname, section.sectname)
                })?;
            let our_target = decode_page_reference(&our_bytes_sec, our_addr, site_offset, &kind)?;
            let apple_target =
                decode_page_reference(&apple_bytes_sec, apple_addr, site_offset, &kind)?;
            let our_offset = our_target - our_addr;
            let apple_offset = apple_target - apple_addr;
            if our_offset != target_offset || apple_offset != target_offset {
                return Err(format!(
                    "{}: decoded target offset mismatch (ours={our_offset:#x}, apple={apple_offset:#x}, expected={target_offset:#x})",
                    case.name,
                ));
            }
        }
    }

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(our_out);
    let _ = fs::remove_file(apple_out);
    Ok(())
}

fn decode_page_reference(
    bytes: &[u8],
    section_addr: u64,
    site_offset: u64,
    kind: &PageRefKind,
) -> Result<u64, String> {
    let start = site_offset as usize;
    let adrp = read_insn(bytes, start)?;
    let second = read_insn(bytes, start + 4)?;
    let place = section_addr + site_offset;
    let adrp_immlo = ((adrp >> 29) & 0x3) as i64;
    let adrp_immhi = ((adrp >> 5) & 0x7ffff) as i64;
    let adrp_pages = sign_extend_21((adrp_immhi << 2) | adrp_immlo);
    let adrp_base = ((place as i64) & !0xfff) + (adrp_pages << 12);
    let low = match kind {
        PageRefKind::Add => ((second >> 10) & 0xfff) as u64,
        PageRefKind::Load => {
            let shift = ((second >> 30) & 0b11) as u64;
            (((second >> 10) & 0xfff) as u64) << shift
        }
    };
    Ok((adrp_base as u64) + low)
}

fn read_insn(bytes: &[u8], start: usize) -> Result<u32, String> {
    let end = start + 4;
    let slice = bytes
        .get(start..end)
        .ok_or_else(|| format!("instruction read OOB at 0x{start:x}"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[test]
fn linker_run_emits_non_empty_executable_from_real_object() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("main.o");
    let out = scratch("a.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov x0, #0
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let mut text_size = 0u64;
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            for section in seg.sections {
                if section.sectname_str() == "__text" {
                    text_size = section.size;
                }
            }
        }
    }
    assert!(text_size > 0, "expected non-empty __text output");

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_emits_minimal_dylib_from_real_object() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("lib.o");
    let out = scratch("libtiny.dylib");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _exported
        _exported:
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Dylib,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    assert_eq!(header.filetype, afs_ld::macho::constants::MH_DYLIB);
    assert!(
        commands
            .iter()
            .any(|cmd| matches!(cmd, LoadCommand::Dylib(d) if d.cmd == afs_ld::macho::constants::LC_ID_DYLIB))
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_reports_unresolved_symbol() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

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

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(scratch("missing.out")),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    let err = Linker::run(&opts).unwrap_err();
    match err {
        LinkError::UndefinedSymbols(msg) => {
            assert!(msg.contains("undefined symbol: _missing"), "{msg}");
        }
        other => panic!("expected UndefinedSymbols, got {other:?}"),
    }

    let _ = fs::remove_file(obj);
}

#[test]
fn linker_run_reports_duplicate_from_fetched_archive_member() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let main_obj = scratch("dup-main.o");
    let dup_obj = scratch("dup-member.o");
    let archive = scratch("dup.a");

    let main_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        .globl _dup
        _main:
            bl _archive_sym
            ret
        _dup:
            ret
        .subsections_via_symbols
    "#;
    let dup_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _archive_sym
        .globl _dup
        _archive_sym:
            ret
        _dup:
            ret
        .subsections_via_symbols
    "#;

    for (src, out) in [(&main_src, &main_obj), (&dup_src, &dup_obj)] {
        if let Err(e) = assemble(src, out) {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    }

    let ar = Command::new("ar")
        .arg("rcs")
        .arg(&archive)
        .arg(&dup_obj)
        .output()
        .unwrap();
    if !ar.status.success() {
        eprintln!("skipping: ar failed: {}", String::from_utf8_lossy(&ar.stderr));
        return;
    }

    let opts = LinkOptions {
        inputs: vec![main_obj.clone(), archive.clone()],
        output: Some(scratch("dup.out")),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    let err = Linker::run(&opts).unwrap_err();
    match err {
        LinkError::DuplicateSymbols(msg) => {
            assert!(msg.contains("duplicate symbol _dup"), "{msg}");
        }
        other => panic!("expected DuplicateSymbols, got {other:?}"),
    }

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(dup_obj);
    let _ = fs::remove_file(archive);
}

#[test]
fn fetched_archive_member_undefined_reports_member_referrer() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let main_obj = scratch("member-main.o");
    let member_obj = scratch("member-undef.o");
    let archive = scratch("member.a");

    let main_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _archive_sym
            ret
        .subsections_via_symbols
    "#;
    let member_src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _archive_sym
        _archive_sym:
            bl _missing_from_member
            ret
        .subsections_via_symbols
    "#;

    for (src, out) in [(&main_src, &main_obj), (&member_src, &member_obj)] {
        if let Err(e) = assemble(src, out) {
            eprintln!("skipping: assemble failed: {e}");
            return;
        }
    }

    let ar = Command::new("ar")
        .arg("rcs")
        .arg(&archive)
        .arg(&member_obj)
        .output()
        .unwrap();
    if !ar.status.success() {
        eprintln!("skipping: ar failed: {}", String::from_utf8_lossy(&ar.stderr));
        return;
    }

    let opts = LinkOptions {
        inputs: vec![main_obj.clone(), archive.clone()],
        output: Some(scratch("member.out")),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    let err = Linker::run(&opts).unwrap_err();
    match err {
        LinkError::UndefinedSymbols(msg) => {
            assert!(msg.contains("undefined symbol: _missing_from_member"), "{msg}");
            assert!(
                msg.contains(&format!("referenced by {}(", archive.display())),
                "expected archive-member referrer in:\n{msg}"
            );
        }
        other => panic!("expected UndefinedSymbols, got {other:?}"),
    }

    let _ = fs::remove_file(main_obj);
    let _ = fs::remove_file(member_obj);
    let _ = fs::remove_file(archive);
}

#[test]
fn linker_run_carries_tbd_inputs_into_load_commands() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let tbd = PathBuf::from(format!("{sdk}/usr/lib/libSystem.tbd"));
    if !tbd.exists() {
        eprintln!("skipping: no libSystem.tbd at {}", tbd.display());
        return;
    }

    let obj = scratch("tbd-main.o");
    let out = scratch("tbd-a.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            mov x0, #0
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone(), tbd.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    assert!(
        commands.iter().any(|cmd| matches!(
            cmd,
            LoadCommand::Dylib(d) if d.cmd == afs_ld::macho::constants::LC_LOAD_DYLIB
        )),
        "expected at least one LC_LOAD_DYLIB in output"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_handles_non_standard_segment_without_panicking() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("custom-segment.o");
    let out = scratch("custom-segment.out");
    let src = r#"
        .section __FOO,__bar
        .globl _custom
        _custom:
            .quad 1
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    assert!(commands.iter().any(|cmd| match cmd {
        LoadCommand::Segment64(seg) => seg.segname_str() == "__FOO",
        _ => false,
    }));

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_uses_requested_entry_symbol() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("entry.o");
    let out = scratch("entry.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            ret
        .globl _alt
        _alt:
            mov x0, #1
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        entry: Some("_alt".into()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let header = parse_header(&bytes).unwrap();
    let commands = parse_commands(&header, &bytes).unwrap();
    let mut text_offset = None;
    let mut main_entryoff = None;
    for cmd in commands {
        match cmd {
            LoadCommand::Segment64(seg) => {
                for section in seg.sections {
                    if section.sectname_str() == "__text" {
                        text_offset = Some(section.offset as u64);
                    }
                }
            }
            LoadCommand::Raw { cmd, data, .. } if cmd == afs_ld::macho::constants::LC_MAIN => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[0..8]);
                main_entryoff = Some(u64::from_le_bytes(buf));
            }
            _ => {}
        }
    }

    let text_offset = text_offset.expect("text section offset");
    let main_entryoff = main_entryoff.expect("LC_MAIN entryoff");
    assert!(
        main_entryoff > text_offset,
        "expected custom entry to land after start of __text: text={text_offset}, entry={main_entryoff}"
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn linker_run_applies_core_arm64_relocations() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("relocs.o");
    let out = scratch("relocs.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        .globl _helper
        _main:
            adrp x0, _target@PAGE
            add x0, x0, _target@PAGEOFF
            bl _helper
            ret
        _helper:
            ret

        .section __DATA,__data
        .p2align 3
        _target:
            .quad _helper

        .section __TEXT,__const
        .p2align 3
        _delta:
            .quad _helper - _main
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").expect("text section");
    let (data_addr, data) = output_section(&bytes, "__DATA", "__data").expect("data section");
    let (_, cdata) = output_section(&bytes, "__TEXT", "__const").expect("const section");

    let adrp = u32::from_le_bytes(text[0..4].try_into().unwrap());
    let add = u32::from_le_bytes(text[4..8].try_into().unwrap());
    let branch = u32::from_le_bytes(text[8..12].try_into().unwrap());
    let data_ptr = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let delta = u64::from_le_bytes(cdata[0..8].try_into().unwrap());

    let adrp_immlo = ((adrp >> 29) & 0x3) as i64;
    let adrp_immhi = ((adrp >> 5) & 0x7ffff) as i64;
    let adrp_pages = sign_extend_21((adrp_immhi << 2) | adrp_immlo);
    let adrp_base = ((text_addr as i64) & !0xfff) + (adrp_pages << 12);
    let add_imm = ((add >> 10) & 0xfff) as u64;
    let reconstructed_target = (adrp_base as u64) + add_imm;

    assert_eq!(reconstructed_target, data_addr, "ADRP+ADD should resolve _target");
    assert_eq!(branch & 0x03ff_ffff, 0x2, "BL should branch forward 8 bytes");
    assert_eq!(data_ptr, text_addr + 16, ".quad _helper should point at helper");
    assert_eq!(delta, 16, "_helper - _main should fold through SUBTRACTOR");

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

fn sign_extend_21(value: i64) -> i64 {
    if value & (1 << 20) != 0 {
        value | !0x1f_ffff
    } else {
        value
    }
}

#[test]
fn linker_run_applies_scaled_pageoff12_for_ldr_x() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("scaled-ldr.o");
    let out = scratch("scaled-ldr.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _target@PAGE
            ldr x1, [x0, _target@PAGEOFF]
            ret

        .section __DATA,__data
        .space 0x3f8
        .p2align 3
        .globl _target
        _target:
            .quad 0x1122334455667788
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out.clone()),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    Linker::run(&opts).unwrap();

    let bytes = fs::read(&out).unwrap();
    let (text_addr, text) = output_section(&bytes, "__TEXT", "__text").expect("text section");
    let (data_addr, data) = output_section(&bytes, "__DATA", "__data").expect("data section");

    let adrp = u32::from_le_bytes(text[0..4].try_into().unwrap());
    let ldr = u32::from_le_bytes(text[4..8].try_into().unwrap());
    let adrp_immlo = ((adrp >> 29) & 0x3) as i64;
    let adrp_immhi = ((adrp >> 5) & 0x7ffff) as i64;
    let adrp_pages = sign_extend_21((adrp_immhi << 2) | adrp_immlo);
    let adrp_base = ((text_addr as i64) & !0xfff) + (adrp_pages << 12);
    let ldr_shift = ((ldr >> 30) & 0b11) as u64;
    let ldr_imm = ((ldr >> 10) & 0xfff) as u64;
    let reconstructed_target = (adrp_base as u64) + (ldr_imm << ldr_shift);

    assert_eq!(ldr_shift, 3, "expected 64-bit LDR scale");
    assert_eq!(ldr_imm, 0x7f, "scaled imm12 should store 0x3f8 >> 3");
    assert_eq!(reconstructed_target, data_addr + 0x3f8);
    assert_eq!(
        u64::from_le_bytes(data[0x3f8..0x400].try_into().unwrap()),
        0x1122334455667788
    );

    let _ = fs::remove_file(obj);
    let _ = fs::remove_file(out);
}

#[test]
fn relocated_sections_match_apple_ld_across_fixture_matrix() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: xcrun --show-sdk-path unavailable");
        return;
    };
    let Some(sdk_ver) = sdk_version() else {
        eprintln!("skipping: xcrun --show-sdk-version unavailable");
        return;
    };
    const TEXT: SectionCase = SectionCase {
        segname: "__TEXT",
        sectname: "__text",
    };
    const CONST: SectionCase = SectionCase {
        segname: "__TEXT",
        sectname: "__const",
    };

    let cases = [
        ParityCase {
            name: "branch-forward",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    bl _helper
                    ret
                _helper:
                    ret
                .subsections_via_symbols
            "#,
            check: ParityCheck::ExactSections(&[TEXT]),
        },
        ParityCase {
            name: "branch-backward",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _helper
                _helper:
                    ret
                .globl _main
                _main:
                    bl _helper
                    ret
                .subsections_via_symbols
            "#,
            check: ParityCheck::ExactSections(&[TEXT]),
        },
        ParityCase {
            name: "adrp-add-intra-text-forward",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _target@PAGE
                    add x0, x0, _target@PAGEOFF
                    ret
                .space 0x4ff4
                _target:
                    .quad 0
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0,
                target_offset: 0x5000,
                kind: PageRefKind::Add,
            },
        },
        ParityCase {
            name: "adrp-add-intra-text-backward",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                _target:
                    .quad 0x55
                .space 0x4ff8
                .globl _main
                _main:
                    adrp x0, _target@PAGE
                    add x0, x0, _target@PAGEOFF
                    ret
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0x5000,
                target_offset: 0,
                kind: PageRefKind::Add,
            },
        },
        ParityCase {
            name: "adrp-ldr-x-intra-text",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _target@PAGE
                    ldr x1, [x0, _target@PAGEOFF]
                    ret
                .space 0x3f4
                _target:
                    .quad 0x1122334455667788
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0,
                target_offset: 0x400,
                kind: PageRefKind::Load,
            },
        },
        ParityCase {
            name: "adrp-ldr-w-intra-text",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _target@PAGE
                    ldr w1, [x0, _target@PAGEOFF]
                    ret
                .space 0x2f4
                _target:
                    .long 0x11223344
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0,
                target_offset: 0x300,
                kind: PageRefKind::Load,
            },
        },
        ParityCase {
            name: "adrp-ldrh-intra-text",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _target@PAGE
                    ldrh w1, [x0, _target@PAGEOFF]
                    ret
                .space 0x1f4
                _target:
                    .hword 0x3344
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0,
                target_offset: 0x200,
                kind: PageRefKind::Load,
            },
        },
        ParityCase {
            name: "adrp-ldrb-intra-text",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                _main:
                    adrp x0, _target@PAGE
                    ldrb w1, [x0, _target@PAGEOFF]
                    ret
                .space 0xf4
                _target:
                    .byte 0x44
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0,
                target_offset: 0x100,
                kind: PageRefKind::Load,
            },
        },
        ParityCase {
            name: "mixed-branch-adrp-text",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _main
                .globl _helper
                _main:
                    adrp x0, _target@PAGE
                    add x0, x0, _target@PAGEOFF
                    bl _helper
                    ret
                _helper:
                    ret
                .space 0xff0
                _target:
                    .quad 0x99
                .subsections_via_symbols
            "#,
            check: ParityCheck::PageRef {
                section: TEXT,
                site_offset: 0,
                target_offset: 0x1004,
                kind: PageRefKind::Add,
            },
        },
        ParityCase {
            name: "subtractor-positive",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _helper
                _helper:
                    ret
                .globl _main
                _main:
                    bl _helper
                    ret
                .section __TEXT,__const
                .p2align 3
                _delta:
                    .quad _helper - _main
                .subsections_via_symbols
            "#,
            check: ParityCheck::ExactSections(&[CONST]),
        },
        ParityCase {
            name: "subtractor-negative",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _helper
                _helper:
                    ret
                .globl _main
                _main:
                    ret
                .section __TEXT,__const
                .p2align 3
                _delta:
                    .quad _main - _helper
                .subsections_via_symbols
            "#,
            check: ParityCheck::ExactSections(&[CONST]),
        },
        ParityCase {
            name: "branch-and-subtractor",
            src: r#"
                .section __TEXT,__text,regular,pure_instructions
                .globl _helper
                _helper:
                    ret
                .globl _main
                _main:
                    bl _helper
                    ret
                .section __TEXT,__const
                .p2align 3
                _delta:
                    .quad _main - _helper
                .subsections_via_symbols
            "#,
            check: ParityCheck::ExactSections(&[TEXT, CONST]),
        },
    ];

    let mut failures = Vec::new();
    for case in &cases {
        if let Err(err) = assert_case_matches_apple_ld(case, &sdk, &sdk_ver) {
            failures.push(err);
        }
    }

    assert!(
        failures.is_empty(),
        "Apple ld parity failures ({} cases):\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn linker_run_rejects_out_of_range_branch26() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun as unavailable");
        return;
    }

    let obj = scratch("branch26-range.o");
    let out = scratch("branch26-range.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            bl _helper
            ret

        .zerofill __DATA,__bss,_gap,0x9000000,0

        .section __FAR,__text,regular,pure_instructions
        .globl _helper
        _helper:
            ret
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    let err = Linker::run(&opts).unwrap_err();
    match err {
        LinkError::Reloc(err) => {
            let msg = err.to_string();
            assert!(msg.contains("Branch26"), "{msg}");
            assert!(msg.contains("out of BRANCH26 range"), "{msg}");
            assert!(msg.contains("_helper"), "{msg}");
        }
        other => panic!("expected Reloc error, got {other:?}"),
    }

    let _ = fs::remove_file(obj);
}

#[test]
fn linker_run_rejects_got_relocations_until_sprint_12() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }

    let obj = scratch("got-reloc.o");
    let out = scratch("got-reloc.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _target@GOTPAGE
            ldr x0, [x0, _target@GOTPAGEOFF]
            ret

        .section __DATA,__data
        .globl _target
        .p2align 3
        _target:
            .quad 0
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    let err = Linker::run(&opts).unwrap_err();
    match err {
        LinkError::Reloc(err) => {
            let msg = err.to_string();
            assert!(msg.contains("GotLoadPage21") || msg.contains("GotLoadPageOff12"), "{msg}");
            assert!(msg.contains("not yet implemented"), "{msg}");
            assert!(msg.contains("Sprint 12/13"), "{msg}");
            assert!(msg.contains("_target"), "{msg}");
        }
        other => panic!("expected Reloc error, got {other:?}"),
    }

    let _ = fs::remove_file(obj);
}

#[test]
fn linker_run_rejects_tlvp_relocations_until_sprint_13() {
    if !have_xcrun() {
        eprintln!("skipping: xcrun unavailable");
        return;
    }

    let obj = scratch("tlvp-reloc.o");
    let out = scratch("tlvp-reloc.out");
    let src = r#"
        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _tlsvar@TLVPPAGE
            ldr x0, [x0, _tlsvar@TLVPPAGEOFF]
            ret

        .section __DATA,__thread_data,thread_local_regular
        .globl _tlsvar
        .p2align 3
        _tlsvar:
            .quad 0
        .subsections_via_symbols
    "#;
    if let Err(e) = assemble(src, &obj) {
        eprintln!("skipping: assemble failed: {e}");
        return;
    }

    let opts = LinkOptions {
        inputs: vec![obj.clone()],
        output: Some(out),
        kind: OutputKind::Executable,
        ..LinkOptions::default()
    };
    let err = Linker::run(&opts).unwrap_err();
    match err {
        LinkError::Reloc(err) => {
            let msg = err.to_string();
            assert!(msg.contains("TlvpLoadPage21") || msg.contains("TlvpLoadPageOff12"), "{msg}");
            assert!(msg.contains("not yet implemented"), "{msg}");
            assert!(msg.contains("Sprint 12/13"), "{msg}");
            assert!(msg.contains("_tlsvar"), "{msg}");
        }
        other => panic!("expected Reloc error, got {other:?}"),
    }

    let _ = fs::remove_file(obj);
}
