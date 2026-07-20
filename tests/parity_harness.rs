//! Focused tests for Sprint 27 harness glue.

mod common;

use afs_ld::macho::constants::{CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, MH_EXECUTE, MH_MAGIC_64};
use afs_ld::macho::reader::{
    write_commands, write_header, LinkEditDataCmd, LoadCommand, MachHeader64,
};
use common::harness::{
    apply_section_tolerances, diff_macho, macho_exports, parse_case_tolerances,
    string_table_within_five_percent,
};

#[test]
fn export_trie_reader_accepts_executable_images() {
    let command = LoadCommand::DyldExportsTrie(LinkEditDataCmd {
        dataoff: 48,
        datasize: 2,
    });
    let mut bytes = Vec::new();
    write_header(
        &MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_EXECUTE,
            ncmds: 1,
            sizeofcmds: command.cmdsize(),
            flags: 0,
            reserved: 0,
        },
        &mut bytes,
    );
    write_commands(&[command], &mut bytes);
    bytes.extend_from_slice(&[0, 0]);

    let exports = macho_exports(&bytes).expect("read executable export trie");
    assert!(exports.entries().expect("decode export trie").is_empty());
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
