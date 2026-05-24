use afs_ld::layout::Layout;
use afs_ld::macho::constants::*;
use afs_ld::macho::exports::{ExportEntry, ExportKind, Exports};
use afs_ld::macho::reader::{parse_commands, parse_header, LoadCommand, HEADER_SIZE};
use afs_ld::macho::writer;
use afs_ld::reloc::{parse_relocs, RawRelocation, Referent, RelocKind, RelocLength};
use afs_ld::resolve::SymbolId;
use afs_ld::symbol::{InputSymbol, RawNlist, SymKind};
use afs_ld::synth::chained_fixups::{
    self, ChainedFixupKind, ChainedFixupSite, ChainedImport, ChainedPointerKind, ChainedSegment,
    DYLD_CHAINED_IMPORT_ADDEND, DYLD_CHAINED_PTR_64_OFFSET,
};
use afs_ld::synth::code_sig::CodeSignaturePlan;
use afs_ld::synth::dyld_info::build_export_trie;
use afs_ld::{LinkOptions, OutputKind};

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn be32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn raw_reloc(r_type: u8, r_symbolnum: u32, r_extern: bool) -> RawRelocation {
    RawRelocation {
        r_address: 4,
        r_symbolnum,
        r_pcrel: false,
        r_length: RelocLength::Word.as_bits(),
        r_extern,
        r_type,
    }
}

fn nlist(n_type: u8, n_sect: u8, n_desc: u16, n_value: u64) -> InputSymbol {
    InputSymbol::from_raw(RawNlist {
        strx: 1,
        n_type,
        n_sect,
        n_desc,
        n_value,
    })
}

fn write_empty_output(kind: OutputKind, name: &str) -> Vec<u8> {
    let opts = LinkOptions {
        output: Some(name.into()),
        kind,
        ..LinkOptions::default()
    };
    let mut bytes = Vec::new();
    writer::write(&Layout::empty(kind, 0), kind, &opts, &mut bytes).expect("write Mach-O output");
    bytes
}

#[test]
fn public_macho_constants_match_supported_apple_wire_values() {
    assert_eq!(MH_MAGIC_64, 0xfeed_facf);
    assert_eq!(CPU_TYPE_ARM64, 0x0100_000c);
    assert_eq!(CPU_SUBTYPE_ARM64_ALL, 0);
    assert_eq!(MH_OBJECT, 1);
    assert_eq!(MH_EXECUTE, 2);
    assert_eq!(MH_DYLIB, 6);

    assert_eq!(LC_SEGMENT_64, 0x19);
    assert_eq!(LC_SYMTAB, 0x02);
    assert_eq!(LC_DYSYMTAB, 0x0b);
    assert_eq!(LC_ID_DYLIB, 0x0d);
    assert_eq!(LC_LOAD_DYLINKER, 0x0e);
    assert_eq!(LC_RPATH, 0x1c | LC_REQ_DYLD);
    assert_eq!(LC_CODE_SIGNATURE, 0x1d);
    assert_eq!(LC_DYLD_INFO_ONLY, 0x22 | LC_REQ_DYLD);
    assert_eq!(LC_MAIN, 0x28 | LC_REQ_DYLD);
    assert_eq!(LC_DYLD_EXPORTS_TRIE, 0x33 | LC_REQ_DYLD);
    assert_eq!(LC_DYLD_CHAINED_FIXUPS, 0x34 | LC_REQ_DYLD);

    assert_eq!(N_STAB, 0xe0);
    assert_eq!(N_PEXT, 0x10);
    assert_eq!(N_TYPE, 0x0e);
    assert_eq!(N_EXT, 0x01);
    assert_eq!(N_UNDF, 0x00);
    assert_eq!(N_ABS, 0x02);
    assert_eq!(N_INDR, 0x0a);
    assert_eq!(N_SECT, 0x0e);

    assert_eq!(ARM64_RELOC_UNSIGNED, 0);
    assert_eq!(ARM64_RELOC_SUBTRACTOR, 1);
    assert_eq!(ARM64_RELOC_BRANCH26, 2);
    assert_eq!(ARM64_RELOC_PAGE21, 3);
    assert_eq!(ARM64_RELOC_PAGEOFF12, 4);
    assert_eq!(ARM64_RELOC_GOT_LOAD_PAGE21, 5);
    assert_eq!(ARM64_RELOC_GOT_LOAD_PAGEOFF12, 6);
    assert_eq!(ARM64_RELOC_POINTER_TO_GOT, 7);
    assert_eq!(ARM64_RELOC_TLVP_LOAD_PAGE21, 8);
    assert_eq!(ARM64_RELOC_TLVP_LOAD_PAGEOFF12, 9);
    assert_eq!(ARM64_RELOC_ADDEND, 10);

    assert_eq!(SECTION_TYPE_MASK, 0x0000_00ff);
    assert_eq!(S_REGULAR, 0x00);
    assert_eq!(S_ZEROFILL, 0x01);
    assert_eq!(S_CSTRING_LITERALS, 0x02);
    assert_eq!(S_NON_LAZY_SYMBOL_POINTERS, 0x06);
    assert_eq!(S_LAZY_SYMBOL_POINTERS, 0x07);
    assert_eq!(S_SYMBOL_STUBS, 0x08);
    assert_eq!(S_THREAD_LOCAL_VARIABLES, 0x13);
    assert_eq!(S_THREAD_LOCAL_VARIABLE_POINTERS, 0x14);
    assert_eq!(S_ATTR_PURE_INSTRUCTIONS, 0x8000_0000);
    assert_eq!(S_ATTR_DEBUG, 0x0200_0000);
    assert_eq!(S_ATTR_SOME_INSTRUCTIONS, 0x0000_0400);

    assert_eq!(EXPORT_SYMBOL_FLAGS_KIND_MASK, 0x03);
    assert_eq!(EXPORT_SYMBOL_FLAGS_KIND_REGULAR, 0x00);
    assert_eq!(EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL, 0x01);
    assert_eq!(EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE, 0x02);
    assert_eq!(EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION, 0x04);
    assert_eq!(EXPORT_SYMBOL_FLAGS_REEXPORT, 0x08);
    assert_eq!(EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, 0x10);

    assert_eq!(REBASE_TYPE_POINTER, 1);
    assert_eq!(REBASE_OPCODE_MASK, 0xf0);
    assert_eq!(REBASE_IMMEDIATE_MASK, 0x0f);
    assert_eq!(REBASE_OPCODE_DONE, 0x00);
    assert_eq!(REBASE_OPCODE_SET_TYPE_IMM, 0x10);
    assert_eq!(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, 0x20);
    assert_eq!(REBASE_OPCODE_ADD_ADDR_ULEB, 0x30);
    assert_eq!(REBASE_OPCODE_ADD_ADDR_IMM_SCALED, 0x40);
    assert_eq!(REBASE_OPCODE_DO_REBASE_IMM_TIMES, 0x50);
    assert_eq!(REBASE_OPCODE_DO_REBASE_ULEB_TIMES, 0x60);
    assert_eq!(REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB, 0x70);
    assert_eq!(REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB, 0x80);

    assert_eq!(BIND_TYPE_POINTER, 1);
    assert_eq!(BIND_SYMBOL_FLAGS_WEAK_IMPORT, 0x01);
    assert_eq!(BIND_OPCODE_MASK, 0xf0);
    assert_eq!(BIND_IMMEDIATE_MASK, 0x0f);
    assert_eq!(BIND_OPCODE_DONE, 0x00);
    assert_eq!(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM, 0x10);
    assert_eq!(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB, 0x20);
    assert_eq!(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM, 0x30);
    assert_eq!(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, 0x40);
    assert_eq!(BIND_OPCODE_SET_TYPE_IMM, 0x50);
    assert_eq!(BIND_OPCODE_SET_ADDEND_SLEB, 0x60);
    assert_eq!(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, 0x70);
    assert_eq!(BIND_OPCODE_ADD_ADDR_ULEB, 0x80);
    assert_eq!(BIND_OPCODE_DO_BIND, 0x90);
    assert_eq!(BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB, 0xa0);
    assert_eq!(BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED, 0xb0);
    assert_eq!(BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, 0xc0);
}

#[test]
fn writer_outputs_have_spec_shaped_headers_load_commands_and_code_signature() {
    for (kind, filetype, output, has_main, has_id_dylib) in [
        (OutputKind::Executable, MH_EXECUTE, "spec-exec", true, false),
        (OutputKind::Dylib, MH_DYLIB, "libspec.dylib", false, true),
    ] {
        let bytes = write_empty_output(kind, output);
        let header = parse_header(&bytes).expect("parse Mach-O header");
        assert_eq!(header.magic, MH_MAGIC_64);
        assert_eq!(header.cputype, CPU_TYPE_ARM64);
        assert_eq!(header.cpusubtype, CPU_SUBTYPE_ARM64_ALL);
        assert_eq!(header.filetype, filetype);
        assert_eq!(header.reserved, 0);
        assert!(bytes.len() >= HEADER_SIZE + header.sizeofcmds as usize);

        let commands = parse_commands(&header, &bytes).expect("parse load commands");
        assert_eq!(header.ncmds as usize, commands.len());
        assert_eq!(
            header.sizeofcmds,
            commands.iter().map(LoadCommand::cmdsize).sum::<u32>()
        );
        assert!(commands.iter().any(|cmd| {
            matches!(cmd, LoadCommand::Segment64(segment) if segment.segname_str() == "__TEXT")
        }));
        assert_eq!(
            commands.iter().any(|cmd| cmd.cmd() == LC_MAIN),
            has_main,
            "LC_MAIN presence should match output kind"
        );
        assert_eq!(
            commands
                .iter()
                .any(|cmd| matches!(cmd, LoadCommand::Dylib(dylib) if dylib.cmd == LC_ID_DYLIB)),
            has_id_dylib,
            "LC_ID_DYLIB presence should match output kind"
        );

        let code_signature = commands
            .iter()
            .find_map(|cmd| match cmd {
                LoadCommand::Raw {
                    cmd: LC_CODE_SIGNATURE,
                    data,
                    ..
                } => Some((le32(data, 0) as usize, le32(data, 4) as usize)),
                _ => None,
            })
            .expect("LC_CODE_SIGNATURE");
        let (dataoff, datasize) = code_signature;
        assert!(dataoff + datasize <= bytes.len());
        assert_eq!(be32(&bytes[dataoff..dataoff + datasize], 0), 0xfade_0cc0);
    }
}

#[test]
fn every_arm64_relocation_wire_type_is_parsed_or_fused_intentionally() {
    for (r_type, expected_kind) in [
        (ARM64_RELOC_UNSIGNED, RelocKind::Unsigned),
        (ARM64_RELOC_BRANCH26, RelocKind::Branch26),
        (ARM64_RELOC_PAGE21, RelocKind::Page21),
        (ARM64_RELOC_PAGEOFF12, RelocKind::PageOff12),
        (ARM64_RELOC_GOT_LOAD_PAGE21, RelocKind::GotLoadPage21),
        (ARM64_RELOC_GOT_LOAD_PAGEOFF12, RelocKind::GotLoadPageOff12),
        (ARM64_RELOC_POINTER_TO_GOT, RelocKind::PointerToGot),
        (ARM64_RELOC_TLVP_LOAD_PAGE21, RelocKind::TlvpLoadPage21),
        (
            ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
            RelocKind::TlvpLoadPageOff12,
        ),
    ] {
        let relocs = parse_relocs(&[raw_reloc(r_type, 1, true)]).expect("parse primary reloc");
        assert_eq!(relocs.len(), 1);
        assert_eq!(relocs[0].kind, expected_kind);
        assert_eq!(relocs[0].referent, Referent::Symbol(1));
    }

    let addend_prefixed = parse_relocs(&[
        RawRelocation {
            r_type: ARM64_RELOC_ADDEND,
            r_symbolnum: 0x00ff_fffc,
            r_extern: false,
            ..raw_reloc(ARM64_RELOC_ADDEND, 0, false)
        },
        raw_reloc(ARM64_RELOC_UNSIGNED, 1, true),
    ])
    .expect("parse addend-prefixed reloc");
    assert_eq!(addend_prefixed[0].kind, RelocKind::Unsigned);
    assert_eq!(addend_prefixed[0].addend, -4);

    let subtractor = parse_relocs(&[
        raw_reloc(ARM64_RELOC_SUBTRACTOR, 2, true),
        raw_reloc(ARM64_RELOC_UNSIGNED, 1, true),
    ])
    .expect("parse subtractor pair");
    assert_eq!(subtractor[0].kind, RelocKind::Subtractor);
    assert_eq!(subtractor[0].referent, Referent::Symbol(1));
    assert_eq!(subtractor[0].subtrahend, Some(Referent::Symbol(2)));

    assert!(parse_relocs(&[raw_reloc(11, 1, true)]).is_err());
}

#[test]
fn nlist_symbol_types_decode_supported_spec_variants() {
    let undef = nlist(N_UNDF | N_EXT, NO_SECT, 3 << 8, 0);
    assert_eq!(undef.kind(), SymKind::Undef);
    assert_eq!(undef.library_ordinal(), Some(3));

    let abs = nlist(N_ABS | N_EXT, NO_SECT, 0, 0x1234);
    assert_eq!(abs.kind(), SymKind::Abs);
    assert!(abs.is_ext());

    let sect = nlist(N_SECT | N_EXT | N_PEXT, 2, N_WEAK_DEF, 0x1000);
    assert_eq!(sect.kind(), SymKind::Sect);
    assert!(sect.is_private_ext());
    assert!(sect.weak_def());

    let indirect = nlist(N_INDR | N_EXT, NO_SECT, 0, 77);
    assert_eq!(indirect.kind(), SymKind::Indirect);
    assert_eq!(indirect.indirect_target_strx(), Some(77));

    let stab_type = 0x24;
    let stab = nlist(stab_type, 1, 0, 0x2000);
    assert_eq!(stab.stab_kind(), Some(stab_type));
}

#[test]
fn export_trie_round_trips_all_terminal_payload_forms() {
    let mut entries = vec![
        ExportEntry {
            name: "_regular".into(),
            flags: EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
            kind: ExportKind::Regular { address: 0x10 },
        },
        ExportEntry {
            name: "_tlv".into(),
            flags: EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL | EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION,
            kind: ExportKind::ThreadLocal { address: 0x20 },
        },
        ExportEntry {
            name: "_absolute".into(),
            flags: EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE,
            kind: ExportKind::Absolute { address: 0x30 },
        },
        ExportEntry {
            name: "_reexported".into(),
            flags: EXPORT_SYMBOL_FLAGS_REEXPORT,
            kind: ExportKind::Reexport {
                ordinal: 2,
                imported_name: "_renamed".into(),
            },
        },
        ExportEntry {
            name: "_resolver".into(),
            flags: EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER,
            kind: ExportKind::StubAndResolver {
                stub: 0x40,
                resolver: 0x50,
            },
        },
    ];
    entries.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));

    let trie = build_export_trie(&entries);
    let mut decoded = Exports::from_trie_bytes(&trie)
        .entries()
        .expect("decode export trie");
    decoded.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
    assert_eq!(decoded, entries);
}

#[test]
fn chained_fixups_blob_uses_supported_header_starts_imports_and_pointer_formats() {
    let imports = [ChainedImport {
        symbol: SymbolId(0),
        dylib_ordinal: 1,
        weak_import: true,
        name: "_puts".into(),
        addend: 4,
    }];
    let fixups = chained_fixups::build(
        &[ChainedSegment {
            vm_offset: 0x1000,
            vm_size: 0x8000,
        }],
        &imports,
        &[
            ChainedFixupSite {
                segment_index: 0,
                segment_offset: 0,
                kind: ChainedFixupKind::Rebase,
            },
            ChainedFixupSite {
                segment_index: 0,
                segment_offset: 8,
                kind: ChainedFixupKind::Bind { import_ordinal: 0 },
            },
        ],
    )
    .expect("build chained fixups");

    assert_eq!(le32(&fixups.bytes, 0), 0);
    let starts_offset = le32(&fixups.bytes, 4) as usize;
    let imports_offset = le32(&fixups.bytes, 8) as usize;
    let symbols_offset = le32(&fixups.bytes, 12) as usize;
    assert_eq!(starts_offset % 8, 0);
    assert!(starts_offset < imports_offset);
    assert!(imports_offset < symbols_offset);
    assert_eq!(le32(&fixups.bytes, 16), 1);
    assert_eq!(le32(&fixups.bytes, 20), DYLD_CHAINED_IMPORT_ADDEND);
    assert_eq!(le32(&fixups.bytes, 24), 0);
    assert!(fixups
        .bytes
        .windows(b"_puts\0".len())
        .any(|window| window == b"_puts\0"));

    let segment_info_offset = le32(&fixups.bytes, starts_offset + 4) as usize;
    let segment_info = starts_offset + segment_info_offset;
    assert_eq!(
        u16::from_le_bytes(
            fixups.bytes[segment_info + 4..segment_info + 6]
                .try_into()
                .unwrap()
        ),
        0x4000
    );
    assert_eq!(
        u16::from_le_bytes(
            fixups.bytes[segment_info + 6..segment_info + 8]
                .try_into()
                .unwrap()
        ),
        DYLD_CHAINED_PTR_64_OFFSET
    );

    assert_eq!(fixups.pointer_writes.len(), 2);
    assert_eq!(
        fixups.pointer_writes[0].kind,
        ChainedPointerKind::Rebase { next: 2 }
    );
    assert_eq!(
        fixups.pointer_writes[1].kind,
        ChainedPointerKind::Bind {
            import_ordinal: 0,
            next: 0
        }
    );
}

#[test]
fn code_signature_superblob_has_ad_hoc_codedirectory_shape() {
    let opts = LinkOptions {
        output: Some("spec-bin".into()),
        ..LinkOptions::default()
    };
    let code_limit = 4097usize;
    let plan = CodeSignaturePlan::new(
        &Layout::empty(OutputKind::Executable, 0),
        &opts,
        code_limit as u64,
        true,
    )
    .expect("build code signature plan");
    let blob = plan.build(&vec![0; code_limit]);

    let superblob_len = be32(&blob, 4) as usize;
    let cd_offset = be32(&blob, 16) as usize;
    assert_eq!(be32(&blob, 0), 0xfade_0cc0);
    assert_eq!(be32(&blob, 8), 1);
    assert_eq!(be32(&blob, 12), 0);
    assert_eq!(cd_offset, 20);
    assert!(superblob_len <= blob.len());
    assert!(blob[superblob_len..].iter().all(|byte| *byte == 0));

    assert_eq!(be32(&blob, cd_offset), 0xfade_0c02);
    assert_eq!(be32(&blob, cd_offset + 8), 0x0002_0400);
    assert_eq!(be32(&blob, cd_offset + 12), 0x0002_0002);
    assert_eq!(be32(&blob, cd_offset + 20), 88);
    assert_eq!(be32(&blob, cd_offset + 24), 0);
    assert_eq!(be32(&blob, cd_offset + 28), 2);
    assert_eq!(be32(&blob, cd_offset + 32), code_limit as u32);
    assert_eq!(blob[cd_offset + 36], 32);
    assert_eq!(blob[cd_offset + 37], 2);
    assert_eq!(blob[cd_offset + 39], 12);
}
