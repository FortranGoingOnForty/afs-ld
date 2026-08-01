//! Focused tests for Sprint 27 harness glue.

mod common;

use afs_ld::macho::constants::{
    CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, LC_FUNCTION_STARTS, MH_EXECUTE, MH_MAGIC_64,
};
use afs_ld::macho::exports::ExportKind;
use afs_ld::macho::reader::{
    write_commands, write_header, DyldInfoCmd, LinkEditDataCmd, LoadCommand, MachHeader64,
    HEADER_SIZE,
};
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
