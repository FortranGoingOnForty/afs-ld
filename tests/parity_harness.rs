//! Focused tests for Sprint 27 harness glue.

mod common;

use afs_ld::macho::constants::{
    CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE,
    EXPORT_SYMBOL_FLAGS_KIND_REGULAR, EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL, LC_FUNCTION_STARTS,
    MH_EXECUTE, MH_MAGIC_64, N_ABS, N_EXT, N_SECT, S_REGULAR, S_THREAD_LOCAL_VARIABLES,
};
use afs_ld::macho::exports::{ExportEntry, ExportKind};
use afs_ld::macho::reader::{
    write_commands, write_header, DyldInfoCmd, DysymtabCmd, LinkEditDataCmd, LoadCommand,
    MachHeader64, Section64Header, Segment64, SymtabCmd, HEADER_SIZE,
};
use afs_ld::symbol::RawNlist;
use afs_ld::synth::dyld_info::build_export_trie;
#[cfg(unix)]
use common::harness::run_program_with_timeout;
use common::harness::{
    apply_section_tolerances, compare_command_details, diff_macho, macho_exports,
    parse_case_tolerances, string_table_within_five_percent, CommandCheck,
};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::time::Duration;

const SINGLE_EXPORT_TRIE: &[u8] = &[0, 1, b'_', b'x', 0, 6, 2, 0, 7, 0];

fn executable_with_commands(commands: &[LoadCommand], payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_EXECUTE,
            ncmds: commands.len() as u32,
            sizeofcmds: commands.iter().map(LoadCommand::cmdsize).sum(),
            flags: 0,
            reserved: 0,
        },
        &mut bytes,
    );
    write_commands(commands, &mut bytes);
    bytes.extend_from_slice(payload);
    bytes
}

fn executable_with_function_starts(payload: &[u8]) -> Vec<u8> {
    let dataoff = HEADER_SIZE as u32 + LinkEditDataCmd::WIRE_SIZE;
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&dataoff.to_le_bytes());
    data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    executable_with_commands(
        &[LoadCommand::Raw {
            cmd: LC_FUNCTION_STARTS,
            cmdsize: LinkEditDataCmd::WIRE_SIZE,
            data,
        }],
        payload,
    )
}

fn executable_with_export(
    trie: &[u8],
    segments: Vec<Segment64>,
    symbol: RawNlist,
    symbol_name: &str,
) -> Vec<u8> {
    let command_size = segments.iter().map(Segment64::wire_size).sum::<u32>()
        + LinkEditDataCmd::WIRE_SIZE
        + SymtabCmd::WIRE_SIZE
        + DysymtabCmd::WIRE_SIZE;
    let trie_offset = HEADER_SIZE as u32 + command_size;
    let symbol_offset = trie_offset + trie.len() as u32;
    let string_offset = symbol_offset + 16;
    let string_size = symbol_name.len() as u32 + 2;
    let mut commands = segments
        .into_iter()
        .map(LoadCommand::Segment64)
        .collect::<Vec<_>>();
    commands.extend([
        LoadCommand::DyldExportsTrie(LinkEditDataCmd {
            dataoff: trie_offset,
            datasize: trie.len() as u32,
        }),
        LoadCommand::Symtab(SymtabCmd {
            symoff: symbol_offset,
            nsyms: 1,
            stroff: string_offset,
            strsize: string_size,
        }),
        LoadCommand::Dysymtab(DysymtabCmd {
            iextdefsym: 0,
            nextdefsym: 1,
            ..DysymtabCmd::default()
        }),
    ]);
    let mut bytes = executable_with_commands(&commands, trie);
    symbol.write(&mut bytes);
    bytes.push(0);
    bytes.extend_from_slice(symbol_name.as_bytes());
    bytes.push(0);
    bytes
}

fn executable_with_absolute_export(trie_address: u64, symbol_value: u64) -> Vec<u8> {
    let trie = build_export_trie(&[ExportEntry {
        name: "_x".to_string(),
        flags: EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE,
        kind: ExportKind::Absolute {
            address: trie_address,
        },
    }]);
    executable_with_export(
        &trie,
        Vec::new(),
        RawNlist {
            strx: 1,
            n_type: N_ABS | N_EXT,
            n_sect: 0,
            n_desc: 0,
            n_value: symbol_value,
        },
        "_x",
    )
}

#[derive(Clone, Copy)]
enum SyntheticSectionExportKind {
    Regular,
    ThreadLocal,
}

fn name16(name: &str) -> [u8; 16] {
    let mut out = [0; 16];
    out[..name.len()].copy_from_slice(name.as_bytes());
    out
}

fn executable_with_section_export(
    kind: SyntheticSectionExportKind,
    section_image_offset: u64,
    trie_section_offset: u64,
    symbol_section_offset: u64,
) -> Vec<u8> {
    const IMAGE_BASE: u64 = 0x1000;

    let (segment_name, section_name, section_flags, export_flags, export_kind) = match kind {
        SyntheticSectionExportKind::Regular => (
            "__TEXT",
            "__text",
            S_REGULAR,
            EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
            ExportKind::Regular {
                address: section_image_offset + trie_section_offset,
            },
        ),
        SyntheticSectionExportKind::ThreadLocal => (
            "__DATA",
            "__thread_vars",
            S_THREAD_LOCAL_VARIABLES,
            EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL,
            ExportKind::ThreadLocal {
                address: section_image_offset + trie_section_offset,
            },
        ),
    };
    let trie = build_export_trie(&[ExportEntry {
        name: "_x".to_string(),
        flags: export_flags,
        kind: export_kind,
    }]);
    let section = Section64Header {
        sectname: name16(section_name),
        segname: name16(segment_name),
        addr: IMAGE_BASE + section_image_offset,
        size: 0x100,
        offset: 0,
        align: 0,
        reloff: 0,
        nreloc: 0,
        flags: section_flags,
        reserved1: 0,
        reserved2: 0,
        reserved3: 0,
    };
    let text = Segment64 {
        segname: name16("__TEXT"),
        vmaddr: IMAGE_BASE,
        vmsize: 0x1000,
        fileoff: 0,
        filesize: 0,
        maxprot: 0,
        initprot: 0,
        flags: 0,
        sections: if matches!(kind, SyntheticSectionExportKind::Regular) {
            vec![section.clone()]
        } else {
            Vec::new()
        },
    };
    let mut segments = vec![text];
    if matches!(kind, SyntheticSectionExportKind::ThreadLocal) {
        segments.push(Segment64 {
            segname: name16("__DATA"),
            vmaddr: IMAGE_BASE + 0x1000,
            vmsize: 0x1000,
            fileoff: 0,
            filesize: 0,
            maxprot: 0,
            initprot: 0,
            flags: 0,
            sections: vec![section],
        });
    }
    executable_with_export(
        &trie,
        segments,
        RawNlist {
            strx: 1,
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: IMAGE_BASE + section_image_offset + symbol_section_offset,
        },
        "_x",
    )
}

fn executable_with_header_export(trie_address: u64, symbol_value: u64) -> Vec<u8> {
    const IMAGE_BASE: u64 = 0x1000;

    let trie = build_export_trie(&[ExportEntry {
        name: "__mh_execute_header".to_string(),
        flags: EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
        kind: ExportKind::Regular {
            address: trie_address,
        },
    }]);
    let text = Segment64 {
        segname: name16("__TEXT"),
        vmaddr: IMAGE_BASE,
        vmsize: 0x1000,
        fileoff: 0,
        filesize: 0,
        maxprot: 0,
        initprot: 0,
        flags: 0,
        sections: vec![Section64Header {
            sectname: name16("__text"),
            segname: name16("__TEXT"),
            addr: IMAGE_BASE + 0x20,
            size: 0x100,
            offset: 0,
            align: 0,
            reloff: 0,
            nreloc: 0,
            flags: S_REGULAR,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        }],
    };
    executable_with_export(
        &trie,
        vec![text],
        RawNlist {
            strx: 1,
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: symbol_value,
        },
        "__mh_execute_header",
    )
}

fn assert_single_regular_export(bytes: &[u8]) {
    let entries = macho_exports(bytes)
        .expect("read executable export trie")
        .entries()
        .expect("decode export trie");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "_x");
    assert!(matches!(
        entries[0].kind,
        ExportKind::Regular { address: 7 }
    ));
}

#[test]
fn export_trie_reader_accepts_executable_exports_command() {
    let command = LoadCommand::DyldExportsTrie(LinkEditDataCmd {
        dataoff: HEADER_SIZE as u32 + LinkEditDataCmd::WIRE_SIZE,
        datasize: SINGLE_EXPORT_TRIE.len() as u32,
    });
    let bytes = executable_with_commands(&[command], SINGLE_EXPORT_TRIE);

    assert_single_regular_export(&bytes);
}

#[test]
fn export_trie_reader_accepts_executable_dyld_info_command() {
    let command = LoadCommand::DyldInfoOnly(DyldInfoCmd {
        export_off: HEADER_SIZE as u32 + DyldInfoCmd::WIRE_SIZE,
        export_size: SINGLE_EXPORT_TRIE.len() as u32,
        ..DyldInfoCmd::default()
    });
    let bytes = executable_with_commands(&[command], SINGLE_EXPORT_TRIE);

    assert_single_regular_export(&bytes);
}

#[test]
fn export_trie_reader_accepts_executable_without_export_metadata() {
    let bytes = executable_with_commands(&[], &[]);

    let exports = macho_exports(&bytes).expect("read executable export trie");
    assert!(exports.entries().expect("decode export trie").is_empty());
}

#[test]
fn export_trie_reader_rejects_out_of_bounds_ranges() {
    let commands = [
        LoadCommand::DyldExportsTrie(LinkEditDataCmd {
            dataoff: 4096,
            datasize: 16,
        }),
        LoadCommand::DyldInfoOnly(DyldInfoCmd {
            export_off: 4096,
            export_size: 16,
            ..DyldInfoCmd::default()
        }),
    ];

    for command in commands {
        let bytes = executable_with_commands(&[command], &[]);
        let error = macho_exports(&bytes).expect_err("reject out-of-bounds export trie");
        assert!(
            error.contains("exceeds file size"),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn export_record_parity_compares_decoded_absolute_addresses() {
    let matching = executable_with_absolute_export(7, 7);
    let divergent = executable_with_absolute_export(99, 7);

    let error = compare_command_details(&matching, &divergent, &[CommandCheck::ExportRecords])
        .expect_err("different export-trie addresses must fail parity");
    assert!(
        error.contains("export"),
        "unexpected parity diagnostic: {error}"
    );
}

#[test]
fn export_record_parity_rejects_trie_and_symbol_address_disagreement() {
    let inconsistent = executable_with_absolute_export(99, 7);

    let error =
        compare_command_details(&inconsistent, &inconsistent, &[CommandCheck::ExportRecords])
            .expect_err("an export trie must agree with its symbol-table record");
    assert!(
        error.contains("export"),
        "unexpected consistency diagnostic: {error}"
    );
}

#[test]
fn export_record_parity_validates_mach_header_export_location() {
    const IMAGE_BASE: u64 = 0x1000;

    let matching = executable_with_header_export(0, IMAGE_BASE);
    compare_command_details(&matching, &matching, &[CommandCheck::ExportRecords])
        .expect("the executable header export should map to image offset zero");

    for invalid in [
        executable_with_header_export(0x20, IMAGE_BASE),
        executable_with_header_export(0, IMAGE_BASE + 8),
    ] {
        let error = compare_command_details(&invalid, &invalid, &[CommandCheck::ExportRecords])
            .expect_err("the header trie and LC_SYMTAB records must identify the Mach-O header");
        assert!(
            error.contains("__mh_execute_header"),
            "unexpected consistency diagnostic: {error}"
        );
    }
}

#[test]
fn export_record_parity_compares_decoded_section_addresses() {
    for (kind, section_image_offset) in [
        (SyntheticSectionExportKind::Regular, 0x20),
        (SyntheticSectionExportKind::ThreadLocal, 0x1020),
    ] {
        let matching = executable_with_section_export(kind, section_image_offset, 7, 7);
        let divergent = executable_with_section_export(kind, section_image_offset, 9, 7);

        compare_command_details(&matching, &divergent, &[CommandCheck::ExportRecords])
            .expect_err("different section-relative trie addresses must fail parity");
    }
}

#[test]
fn export_record_parity_normalizes_section_layout_drift() {
    for (kind, first_section_offset, second_section_offset) in [
        (SyntheticSectionExportKind::Regular, 0x20, 0x40),
        (SyntheticSectionExportKind::ThreadLocal, 0x1020, 0x1040),
    ] {
        let first = executable_with_section_export(kind, first_section_offset, 7, 7);
        let second = executable_with_section_export(kind, second_section_offset, 7, 7);

        compare_command_details(&first, &second, &[CommandCheck::ExportRecords])
            .expect("matching section-relative export locations should compare equal");
    }
}

#[test]
fn notes_tolerance_block_parses_section_range() {
    let notes = r#"
tolerated:
  - region: __TEXT,__text bytes 0x1-0x3 reason: "known padding drift"
"#;
    let tolerances = parse_case_tolerances(Some(notes)).expect("parse case tolerances");
    assert_eq!(tolerances.len(), 1);
    assert_eq!(tolerances[0].reason, "known padding drift");
}

#[test]
fn notes_tolerance_can_hide_section_byte_diff() {
    let notes = r#"
tolerated:
  - region: __TEXT,__text bytes 0x1-0x1 reason: "known one-byte drift"
"#;
    let tolerances = parse_case_tolerances(Some(notes)).expect("parse case tolerances");
    let diff = diff_macho(b"abc", b"adc");
    let filtered = apply_section_tolerances(diff, "__TEXT", "__text", &tolerances);
    assert!(
        filtered.is_clean(),
        "expected tolerance to absorb diff: {filtered:#?}"
    );
    assert_eq!(filtered.tolerated.len(), 1);
}

#[test]
fn notes_tolerance_does_not_hide_other_sections() {
    let notes = r#"
tolerated:
  - region: __TEXT,__text bytes 0x1-0x1 reason: "known one-byte drift"
"#;
    let tolerances = parse_case_tolerances(Some(notes)).expect("parse case tolerances");
    let diff = diff_macho(b"abc", b"adc");
    let filtered = apply_section_tolerances(diff, "__DATA", "__data", &tolerances);
    assert!(
        !filtered.is_clean(),
        "unexpectedly tolerated unrelated diff: {filtered:#?}"
    );
    assert_eq!(filtered.critical.len(), 1);
}

#[test]
fn string_table_near_parity_accepts_small_suffix_dedup_drift() {
    assert!(
        string_table_within_five_percent(101, 100),
        "1% string-table drift should stay within the Sprint 27 allowance"
    );
}

#[test]
fn string_table_near_parity_rejects_large_suffix_dedup_drift() {
    assert!(
        !string_table_within_five_percent(120, 100),
        "20% string-table drift should fail the Sprint 27 allowance"
    );
}

#[test]
fn function_starts_parity_rejects_missing_terminator() {
    let unterminated = executable_with_function_starts(&[0x04, 0x08]);
    let terminated = executable_with_function_starts(&[0x04, 0x08, 0x00]);

    for check in [
        CommandCheck::FunctionStarts,
        CommandCheck::NormalizedFunctionStarts,
    ] {
        let error = compare_command_details(&unterminated, &terminated, &[check])
            .expect_err("reject unterminated function-start metadata");
        assert!(error.contains("terminator"), "unexpected error: {error}");
    }
}

#[test]
fn function_starts_parity_rejects_records_after_terminator() {
    let trailing_record =
        executable_with_function_starts(&[0x04, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
    let padded = executable_with_function_starts(&[0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    for check in [
        CommandCheck::FunctionStarts,
        CommandCheck::NormalizedFunctionStarts,
    ] {
        let error = compare_command_details(&trailing_record, &padded, &[check])
            .expect_err("reject records after the function-start terminator");
        assert!(error.contains("padding"), "unexpected error: {error}");
    }
}

#[test]
fn function_starts_parity_accepts_zero_padding_after_terminator() {
    let compact = executable_with_function_starts(&[0x04, 0x08, 0x00]);
    let padded = executable_with_function_starts(&[0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    compare_command_details(
        &compact,
        &padded,
        &[
            CommandCheck::FunctionStarts,
            CommandCheck::NormalizedFunctionStarts,
        ],
    )
    .expect("zero alignment padding is valid function-start metadata");
}

#[test]
fn function_starts_parity_accepts_empty_metadata() {
    let empty = executable_with_function_starts(&[]);

    compare_command_details(
        &empty,
        &empty,
        &[
            CommandCheck::FunctionStarts,
            CommandCheck::NormalizedFunctionStarts,
        ],
    )
    .expect("an empty function-start payload represents no functions");
}

#[cfg(unix)]
#[test]
fn runtime_capture_drains_stdout_and_stderr_while_child_runs() {
    const CHUNK_LEN: usize = 1024;
    const ITERATIONS: usize = 2048;

    let stdout_chunk = "o".repeat(CHUNK_LEN);
    let stderr_chunk = "e".repeat(CHUNK_LEN);
    let script = format!(
        "i=0; while [ \"$i\" -lt {ITERATIONS} ]; do printf '%s' '{stdout_chunk}'; printf '%s' '{stderr_chunk}' >&2; i=$((i + 1)); done"
    );
    let output = run_program_with_timeout(
        Path::new("/bin/sh"),
        &["-c".to_string(), script],
        Duration::from_secs(5),
    )
    .expect("capture finite output larger than both child pipes");

    assert_eq!(output.exit_code, Some(0));
    assert_eq!(output.stdout.len(), CHUNK_LEN * ITERATIONS);
    assert_eq!(output.stderr.len(), CHUNK_LEN * ITERATIONS);
    assert!(output.stdout.iter().all(|byte| *byte == b'o'));
    assert!(output.stderr.iter().all(|byte| *byte == b'e'));
}
