//! Binary Mach-O dynamic library reader (`MH_DYLIB`).
//!
//! Sprint 5 lifts the dylib's self-identification (`LC_ID_DYLIB`), its
//! dependency chain (`LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` /
//! `LC_REEXPORT_DYLIB` / `LC_LOAD_UPWARD_DYLIB`), its runtime search paths
//! (`LC_RPATH`), and the export trie. Sprint 6 layers TBD text stubs onto
//! this same `DylibFile` surface so callers don't care whether a dylib came
//! from a real `.dylib` or a `.tbd` fixture.

use std::path::PathBuf;

use super::constants::*;
use super::exports::{ExportEntry, ExportKind, Exports};
use super::reader::{
    parse_commands, parse_header, DysymtabCmd, LoadCommand, MachHeader64, ReadError, SymtabCmd,
};
use super::tbd::{SymbolLists, Target, Tbd};
use crate::string_table::StringTable;
use crate::symbol::parse_nlist_table;

const DEFAULT_TBD_VERSION: u32 = 1 << 16;

/// How a consumer loaded this dylib. The filetype of the dylib itself is
/// always `MH_DYLIB`; this kind captures the *relationship*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DylibLoadKind {
    Normal,
    Weak,
    Reexport,
    Upward,
}

impl DylibLoadKind {
    pub fn from_cmd(cmd: u32) -> Option<Self> {
        match cmd {
            LC_LOAD_DYLIB => Some(DylibLoadKind::Normal),
            LC_LOAD_WEAK_DYLIB => Some(DylibLoadKind::Weak),
            LC_REEXPORT_DYLIB => Some(DylibLoadKind::Reexport),
            LC_LOAD_UPWARD_DYLIB => Some(DylibLoadKind::Upward),
            _ => None,
        }
    }

    pub fn load_cmd(self) -> u32 {
        match self {
            DylibLoadKind::Normal => LC_LOAD_DYLIB,
            DylibLoadKind::Weak => LC_LOAD_WEAK_DYLIB,
            DylibLoadKind::Reexport => LC_REEXPORT_DYLIB,
            DylibLoadKind::Upward => LC_LOAD_UPWARD_DYLIB,
        }
    }
}

/// One dylib this file depends on. Ordinals match the two-level namespace
/// convention: they're 1-based positions in command-line / load-command
/// order, encoded into undefined symbols' `n_desc` high byte so dyld knows
/// which dylib to bind from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DylibDependency {
    pub kind: DylibLoadKind,
    pub install_name: String,
    pub current_version: u32,
    pub compatibility_version: u32,
    /// 1-based ordinal into the dependency list.
    pub ordinal: u16,
}

#[derive(Debug)]
pub struct DylibFile {
    pub path: PathBuf,
    pub header: MachHeader64,
    pub commands: Vec<LoadCommand>,
    pub install_name: String,
    pub current_version: u32,
    pub compatibility_version: u32,
    pub dependencies: Vec<DylibDependency>,
    pub rpaths: Vec<String>,
    pub symtab: Option<SymtabCmd>,
    pub exports: Exports,
}

impl DylibFile {
    /// Parse an MH_DYLIB from its raw bytes.
    pub fn parse(path: impl Into<PathBuf>, file_bytes: &[u8]) -> Result<Self, ReadError> {
        let path = path.into();
        let header = parse_header(file_bytes)?;
        if header.filetype != MH_DYLIB {
            return Err(ReadError::UnexpectedFiletype {
                got: header.filetype,
                expected: MH_DYLIB,
            });
        }
        let commands = parse_commands(&header, file_bytes)?;

        let mut identity = None;
        let mut dependencies: Vec<DylibDependency> = Vec::new();
        let mut rpaths: Vec<String> = Vec::new();
        let mut symtab: Option<SymtabCmd> = None;

        for cmd in &commands {
            match cmd {
                LoadCommand::Dylib(d) if d.cmd == LC_ID_DYLIB => {
                    if identity.is_some() {
                        return Err(ReadError::BadDylibIdentity {
                            reason: "multiple LC_ID_DYLIB load commands",
                        });
                    }
                    if d.name.is_empty() {
                        return Err(ReadError::BadDylibIdentity {
                            reason: "LC_ID_DYLIB install name is empty",
                        });
                    }
                    identity = Some(d);
                }
                LoadCommand::Dylib(d) => {
                    if let Some(kind) = DylibLoadKind::from_cmd(d.cmd) {
                        let ordinal = (dependencies.len() + 1) as u16;
                        dependencies.push(DylibDependency {
                            kind,
                            install_name: d.name.clone(),
                            current_version: d.current_version,
                            compatibility_version: d.compatibility_version,
                            ordinal,
                        });
                    }
                }
                LoadCommand::Rpath(r) => rpaths.push(r.path.clone()),
                LoadCommand::Symtab(s) => symtab = Some(*s),
                _ => {}
            }
        }

        let identity = identity.ok_or(ReadError::BadDylibIdentity {
            reason: "missing LC_ID_DYLIB load command",
        })?;
        let install_name = identity.name.clone();
        let current_version = identity.current_version;
        let compatibility_version = identity.compatibility_version;
        let exports = locate_exports(&commands, file_bytes)?;

        Ok(DylibFile {
            path,
            header,
            commands,
            install_name,
            current_version,
            compatibility_version,
            dependencies,
            rpaths,
            symtab,
            exports,
        })
    }
}

/// Locate exports from an explicit export-trie command, or from the external
/// definitions partition of the legacy symbol table when no trie command is
/// present. An explicit zero-sized trie locator is authoritative: it describes
/// an empty export set and must not be replaced with legacy symbol-table data.
fn locate_exports(commands: &[LoadCommand], file_bytes: &[u8]) -> Result<Exports, ReadError> {
    let mut saw_export_locator = false;
    for cmd in commands {
        match cmd {
            LoadCommand::DyldInfoOnly(d) => {
                saw_export_locator = true;
                if d.export_size != 0 {
                    return trie_slice(file_bytes, d.export_off, d.export_size);
                }
            }
            LoadCommand::DyldExportsTrie(l) => {
                saw_export_locator = true;
                if l.datasize != 0 {
                    return trie_slice(file_bytes, l.dataoff, l.datasize);
                }
            }
            _ => {}
        }
    }
    if saw_export_locator {
        return Ok(Exports::empty());
    }

    locate_legacy_exports(commands, file_bytes)
}

fn locate_legacy_exports(
    commands: &[LoadCommand],
    file_bytes: &[u8],
) -> Result<Exports, ReadError> {
    let symtab = commands.iter().rev().find_map(|command| match command {
        LoadCommand::Symtab(symtab) => Some(*symtab),
        _ => None,
    });
    let dysymtab = commands.iter().rev().find_map(|command| match command {
        LoadCommand::Dysymtab(dysymtab) => Some(*dysymtab),
        _ => None,
    });
    let (Some(symtab), Some(dysymtab)) = (symtab, dysymtab) else {
        return Ok(Exports::empty());
    };

    let extdef_end =
        dysymtab
            .iextdefsym
            .checked_add(dysymtab.nextdefsym)
            .ok_or(ReadError::BadCmdsize {
                cmd: LC_DYSYMTAB,
                cmdsize: DysymtabCmd::WIRE_SIZE,
                at_offset: dysymtab.iextdefsym as usize,
                reason: "LC_DYSYMTAB external-definition range overflows",
            })?;
    if extdef_end > symtab.nsyms {
        return Err(ReadError::BadCmdsize {
            cmd: LC_DYSYMTAB,
            cmdsize: DysymtabCmd::WIRE_SIZE,
            at_offset: dysymtab.iextdefsym as usize,
            reason: "LC_DYSYMTAB external-definition range exceeds LC_SYMTAB nsyms",
        });
    }

    let symbols = parse_nlist_table(file_bytes, symtab.symoff, symtab.nsyms)?;
    let strings = StringTable::from_file(file_bytes, symtab.stroff, symtab.strsize)?;
    let entries = symbols[dysymtab.iextdefsym as usize..extdef_end as usize]
        .iter()
        .map(|symbol| {
            Ok(ExportEntry {
                name: strings.get(symbol.strx())?.to_owned(),
                flags: if symbol.weak_def() {
                    EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION
                } else {
                    0
                },
                kind: ExportKind::Regular {
                    address: symbol.value(),
                },
            })
        })
        .collect::<Result<Vec<_>, ReadError>>()?;
    Ok(Exports::from_entries(entries))
}

fn trie_slice(file_bytes: &[u8], off: u32, size: u32) -> Result<Exports, ReadError> {
    let start = off as usize;
    let end = start
        .checked_add(size as usize)
        .ok_or(ReadError::Truncated {
            need: usize::MAX,
            have: file_bytes.len(),
            context: "export trie (offset + size overflows)",
        })?;
    if end > file_bytes.len() {
        return Err(ReadError::Truncated {
            need: end,
            have: file_bytes.len(),
            context: "export trie",
        });
    }
    Ok(Exports::from_trie_bytes(&file_bytes[start..end]))
}

impl DylibFile {
    /// Materialize a TBD document as a `DylibFile` specialized for a single
    /// target. Scoped lists (`exports`, `reexported-libraries`, `rpaths`
    /// via parent-umbrella) narrow to entries whose target set includes
    /// `target`. Symbol kinds map to ObjC-class / ObjC-eh-type / ObjC-ivar /
    /// thread-local / weak / regular in `ExportKind::Regular` form —
    /// addresses are zero because TBD stubs don't commit to them.
    pub fn from_tbd(path: impl Into<PathBuf>, tbd: &Tbd, target: &Target) -> Self {
        let mut entries: Vec<ExportEntry> = Vec::new();
        for scoped in &tbd.exports {
            if !scope_matches(&scoped.targets, target) {
                continue;
            }
            append_entries(&scoped.value, &mut entries);
        }
        // re-exported symbols from peer dylibs surface the same way —
        // dyld treats them as part of this dylib's export surface.
        for scoped in &tbd.reexports {
            if !scope_matches(&scoped.targets, target) {
                continue;
            }
            append_entries(&scoped.value, &mut entries);
        }

        let mut dependencies = Vec::new();
        let mut ordinal: u16 = 1;
        for scoped in &tbd.reexported_libraries {
            if !scope_matches(&scoped.targets, target) {
                continue;
            }
            for install_name in &scoped.value {
                dependencies.push(DylibDependency {
                    kind: DylibLoadKind::Reexport,
                    install_name: install_name.clone(),
                    current_version: 0,
                    compatibility_version: 0,
                    ordinal,
                });
                ordinal += 1;
            }
        }

        DylibFile {
            path: path.into(),
            // TBDs have no binary header; synth a minimal one so downstream
            // consumers that only read `install_name` / versions don't care
            // whether they got a binary or a stub.
            header: synthetic_header(),
            commands: Vec::new(),
            install_name: tbd.install_name.clone(),
            current_version: tbd.current_version.unwrap_or(DEFAULT_TBD_VERSION),
            compatibility_version: tbd.compatibility_version.unwrap_or(DEFAULT_TBD_VERSION),
            dependencies,
            rpaths: Vec::new(),
            symtab: None,
            exports: Exports::from_entries(entries),
        }
    }
}

fn scope_matches(targets: &[Target], wanted: &Target) -> bool {
    targets.iter().any(|t| t.matches_requested(wanted))
}

fn append_entries(lists: &SymbolLists, out: &mut Vec<ExportEntry>) {
    for n in &lists.symbols {
        out.push(regular_entry(n, 0));
    }
    for n in &lists.weak_symbols {
        out.push(weak_entry(n));
    }
    for n in &lists.thread_local_symbols {
        out.push(tls_entry(n));
    }
    // ObjC classes ship as `_OBJC_CLASS_$_<name>` externs in a real dylib.
    for n in &lists.objc_classes {
        let full = format!("_OBJC_CLASS_$_{n}");
        out.push(regular_entry(&full, 0));
    }
    for n in &lists.objc_eh_types {
        let full = format!("_OBJC_EHTYPE_$_{n}");
        out.push(regular_entry(&full, 0));
    }
    for n in &lists.objc_ivars {
        let full = format!("_OBJC_IVAR_$_{n}");
        out.push(regular_entry(&full, 0));
    }
}

fn regular_entry(name: &str, flags: u64) -> ExportEntry {
    ExportEntry {
        name: name.to_string(),
        flags,
        kind: ExportKind::Regular { address: 0 },
    }
}

fn weak_entry(name: &str) -> ExportEntry {
    ExportEntry {
        name: name.to_string(),
        flags: EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION,
        kind: ExportKind::Regular { address: 0 },
    }
}

fn tls_entry(name: &str) -> ExportEntry {
    ExportEntry {
        name: name.to_string(),
        flags: EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL,
        kind: ExportKind::ThreadLocal { address: 0 },
    }
}

fn synthetic_header() -> MachHeader64 {
    MachHeader64 {
        magic: MH_MAGIC_64,
        cputype: CPU_TYPE_ARM64,
        cpusubtype: 0,
        filetype: MH_DYLIB,
        ncmds: 0,
        sizeofcmds: 0,
        flags: MH_DYLDLINK | MH_TWOLEVEL,
        reserved: 0,
    }
}

/// Look up the 1-based ordinal of a dependency by its install name. Used by
/// Sprint 14's symbol-table writer when encoding each undefined symbol's
/// two-level-namespace library ordinal into its `n_desc` high byte.
pub fn dependency_ordinal(deps: &[DylibDependency], install_name: &str) -> Option<u16> {
    deps.iter()
        .find(|d| d.install_name == install_name)
        .map(|d| d.ordinal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::reader::{
        write_commands, write_header, DyldInfoCmd, DylibCmd, DysymtabCmd, RpathCmd, SymtabCmd,
        HEADER_SIZE,
    };
    use crate::symbol::{RawNlist, NLIST_SIZE};

    fn make_dylib_image(commands: Vec<LoadCommand>) -> Vec<u8> {
        let sizeofcmds: u32 = commands.iter().map(|c| c.cmdsize()).sum();
        let ncmds = commands.len() as u32;
        let hdr = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 0,
            filetype: MH_DYLIB,
            ncmds,
            sizeofcmds,
            flags: MH_DYLDLINK | MH_TWOLEVEL,
            reserved: 0,
        };
        let mut image = Vec::new();
        write_header(&hdr, &mut image);
        write_commands(&commands, &mut image);
        image
    }

    fn dylib_cmd(kind: u32, name: &str) -> DylibCmd {
        DylibCmd {
            cmd: kind,
            name: name.into(),
            timestamp: 2,
            current_version: 1 << 16,
            compatibility_version: 1 << 16,
        }
    }

    fn make_legacy_dylib_image(
        symbols: &[(&str, u8, u16, u64)],
        dysymtab: DysymtabCmd,
        export_locator: Option<LoadCommand>,
    ) -> Vec<u8> {
        let mut strings = vec![0];
        let mut raw_symbols = Vec::with_capacity(symbols.len());
        for &(name, n_type, n_desc, n_value) in symbols {
            let strx = strings.len() as u32;
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            raw_symbols.push(RawNlist {
                strx,
                n_type,
                n_sect: u8::from(n_type & N_TYPE != N_UNDF),
                n_desc,
                n_value,
            });
        }

        let identity =
            LoadCommand::Dylib(dylib_cmd(LC_ID_DYLIB, "/usr/lib/liblegacy-exports.dylib"));
        let mut commands = vec![identity];
        commands.extend(export_locator);
        let sizeofcmds = commands.iter().map(LoadCommand::cmdsize).sum::<u32>()
            + SymtabCmd::WIRE_SIZE
            + DysymtabCmd::WIRE_SIZE;
        let symoff = HEADER_SIZE as u32 + sizeofcmds;
        let stroff = symoff + (raw_symbols.len() * NLIST_SIZE) as u32;
        commands.push(LoadCommand::Symtab(SymtabCmd {
            symoff,
            nsyms: raw_symbols.len() as u32,
            stroff,
            strsize: strings.len() as u32,
        }));
        commands.push(LoadCommand::Dysymtab(dysymtab));

        let mut image = make_dylib_image(commands);
        for symbol in raw_symbols {
            symbol.write(&mut image);
        }
        image.extend_from_slice(&strings);
        image
    }

    #[test]
    fn parse_dylib_extracts_install_name_and_versions() {
        let image = make_dylib_image(vec![LoadCommand::Dylib(DylibCmd {
            cmd: LC_ID_DYLIB,
            name: "@rpath/libfoo.dylib".into(),
            timestamp: 2,
            current_version: (1 << 16) | (2 << 8) | 3,
            compatibility_version: 1 << 16,
        })]);
        let dy = DylibFile::parse("/tmp/libfoo.dylib", &image).unwrap();
        assert_eq!(dy.install_name, "@rpath/libfoo.dylib");
        assert_eq!(dy.current_version, (1 << 16) | (2 << 8) | 3);
        assert_eq!(dy.compatibility_version, 1 << 16);
    }

    #[test]
    fn parse_dylib_requires_exactly_one_nonempty_identity() {
        let cases = [
            (
                Vec::new(),
                "malformed MH_DYLIB identity: missing LC_ID_DYLIB load command",
            ),
            (
                vec![LoadCommand::Dylib(dylib_cmd(LC_ID_DYLIB, ""))],
                "malformed MH_DYLIB identity: LC_ID_DYLIB install name is empty",
            ),
            (
                vec![
                    LoadCommand::Dylib(dylib_cmd(LC_ID_DYLIB, "@rpath/libfirst.dylib")),
                    LoadCommand::Dylib(dylib_cmd(LC_ID_DYLIB, "@rpath/libsecond.dylib")),
                ],
                "malformed MH_DYLIB identity: multiple LC_ID_DYLIB load commands",
            ),
        ];

        for (commands, expected) in cases {
            let image = make_dylib_image(commands);
            let error = DylibFile::parse("/tmp/invalid.dylib", &image)
                .expect_err("malformed dylib identity must be rejected");
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn parse_dylib_assigns_ordinals_to_dependencies_in_order() {
        let image = make_dylib_image(vec![
            LoadCommand::Dylib(dylib_cmd(LC_ID_DYLIB, "@rpath/libself.dylib")),
            LoadCommand::Dylib(dylib_cmd(LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib")),
            LoadCommand::Dylib(dylib_cmd(LC_LOAD_WEAK_DYLIB, "/usr/lib/libobjc.A.dylib")),
            LoadCommand::Dylib(dylib_cmd(LC_REEXPORT_DYLIB, "/usr/lib/libc++abi.dylib")),
        ]);
        let dy = DylibFile::parse("/tmp/x.dylib", &image).unwrap();
        assert_eq!(dy.install_name, "@rpath/libself.dylib");
        assert_eq!(dy.dependencies.len(), 3);
        assert_eq!(dy.dependencies[0].kind, DylibLoadKind::Normal);
        assert_eq!(dy.dependencies[0].ordinal, 1);
        assert_eq!(dy.dependencies[1].kind, DylibLoadKind::Weak);
        assert_eq!(dy.dependencies[1].ordinal, 2);
        assert_eq!(dy.dependencies[2].kind, DylibLoadKind::Reexport);
        assert_eq!(dy.dependencies[2].ordinal, 3);

        assert_eq!(
            dependency_ordinal(&dy.dependencies, "/usr/lib/libSystem.B.dylib"),
            Some(1)
        );
        assert_eq!(
            dependency_ordinal(&dy.dependencies, "/usr/lib/libc++abi.dylib"),
            Some(3)
        );
        assert_eq!(dependency_ordinal(&dy.dependencies, "missing"), None);
    }

    #[test]
    fn parse_dylib_collects_rpaths_in_source_order() {
        let image = make_dylib_image(vec![
            LoadCommand::Dylib(dylib_cmd(LC_ID_DYLIB, "@rpath/libself.dylib")),
            LoadCommand::Rpath(RpathCmd {
                path: "@executable_path/../lib".into(),
            }),
            LoadCommand::Rpath(RpathCmd {
                path: "/opt/local/lib".into(),
            }),
        ]);
        let dy = DylibFile::parse("/tmp/x.dylib", &image).unwrap();
        assert_eq!(dy.rpaths, vec!["@executable_path/../lib", "/opt/local/lib"]);
    }

    #[test]
    fn parse_dylib_falls_back_to_dysymtab_external_definitions() {
        let image = make_legacy_dylib_image(
            &[
                ("_local", N_SECT, 0, 0x1000),
                ("_legacy_export", N_SECT | N_EXT, 0, 0x1010),
                ("_legacy_weak", N_SECT | N_EXT, N_WEAK_DEF, 0x1020),
                ("_dependency", N_UNDF | N_EXT, 0, 0),
            ],
            DysymtabCmd {
                ilocalsym: 0,
                nlocalsym: 1,
                iextdefsym: 1,
                nextdefsym: 2,
                iundefsym: 3,
                nundefsym: 1,
                ..DysymtabCmd::default()
            },
            None,
        );

        let dylib = DylibFile::parse("/tmp/liblegacy-exports.dylib", &image).unwrap();
        assert_eq!(
            dylib.exports.entries().unwrap(),
            vec![
                ExportEntry {
                    name: "_legacy_export".into(),
                    flags: 0,
                    kind: ExportKind::Regular { address: 0x1010 },
                },
                ExportEntry {
                    name: "_legacy_weak".into(),
                    flags: EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION,
                    kind: ExportKind::Regular { address: 0x1020 },
                },
            ]
        );
    }

    #[test]
    fn parse_dylib_rejects_invalid_dysymtab_external_definition_ranges() {
        for (iextdefsym, nextdefsym, expected_reason) in
            [(u32::MAX, 1, "overflows"), (1, 1, "exceeds")]
        {
            let image = make_legacy_dylib_image(
                &[("_legacy_export", N_SECT | N_EXT, 0, 0x1010)],
                DysymtabCmd {
                    iextdefsym,
                    nextdefsym,
                    ..DysymtabCmd::default()
                },
                None,
            );

            let error = DylibFile::parse("/tmp/liblegacy-exports.dylib", &image).unwrap_err();
            assert!(matches!(
                error,
                ReadError::BadCmdsize {
                    cmd: LC_DYSYMTAB,
                    reason,
                    ..
                } if reason.contains(expected_reason)
            ));
        }
    }

    #[test]
    fn parse_dylib_does_not_override_an_explicit_empty_export_locator() {
        let image = make_legacy_dylib_image(
            &[("_legacy_export", N_SECT | N_EXT, 0, 0x1010)],
            DysymtabCmd {
                iextdefsym: 0,
                nextdefsym: 1,
                ..DysymtabCmd::default()
            },
            Some(LoadCommand::DyldInfoOnly(DyldInfoCmd::default())),
        );

        let dylib = DylibFile::parse("/tmp/liblegacy-exports.dylib", &image).unwrap();
        assert!(dylib.exports.entries().unwrap().is_empty());
    }

    // ----- DylibFile::from_tbd tests -----

    use crate::macho::tbd::{parse_tbd, Arch, Platform};

    fn arm64_macos() -> Target {
        Target {
            arch: Arch::Arm64,
            platform: Platform::MacOs,
        }
    }

    #[test]
    fn from_tbd_filters_exports_by_target() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets: [ arm64-macos, x86_64-macos ]\n\
                   install-name: '/usr/lib/libdemo.dylib'\n\
                   current-version: 1.2.3\n\
                   exports:\n\
                   \x20 - targets: [ arm64-macos ]\n\
                   \x20   symbols: [ _arm_only ]\n\
                   \x20 - targets: [ x86_64-macos ]\n\
                   \x20   symbols: [ _x86_only ]\n\
                   \x20 - targets: [ arm64-macos, x86_64-macos ]\n\
                   \x20   symbols: [ _shared_sym ]\n";
        let tbd = &parse_tbd(src).unwrap()[0];
        let dy = DylibFile::from_tbd("/stub/libdemo.tbd", tbd, &arm64_macos());
        let names: Vec<String> = dy
            .exports
            .entries()
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"_arm_only".to_string()));
        assert!(names.contains(&"_shared_sym".to_string()));
        assert!(!names.contains(&"_x86_only".to_string()));
    }

    #[test]
    fn from_tbd_arm64_uses_arm64e_scopes() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets: [ arm64e-macos ]\n\
                   install-name: '/usr/lib/libdemo.dylib'\n\
                   exports:\n\
                   \x20 - targets: [ arm64e-macos ]\n\
                   \x20   symbols: [ _umbrella_only ]\n";
        let tbd = &parse_tbd(src).unwrap()[0];
        let dy = DylibFile::from_tbd("/stub/libdemo.tbd", tbd, &arm64_macos());
        let names: Vec<String> = dy
            .exports
            .entries()
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["_umbrella_only".to_string()]);
    }

    #[test]
    fn from_tbd_includes_reexported_libraries_as_dependencies() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets: [ arm64-macos ]\n\
                   install-name: '/usr/lib/libSystem.B.dylib'\n\
                   reexported-libraries:\n\
                   \x20 - targets: [ arm64-macos ]\n\
                   \x20   libraries: [ '/usr/lib/system/libcache.dylib', '/usr/lib/system/libxpc.dylib' ]\n";
        let tbd = &parse_tbd(src).unwrap()[0];
        let dy = DylibFile::from_tbd("/stub/libSystem.tbd", tbd, &arm64_macos());
        assert_eq!(dy.dependencies.len(), 2);
        assert_eq!(dy.dependencies[0].kind, DylibLoadKind::Reexport);
        assert_eq!(dy.dependencies[0].ordinal, 1);
        assert_eq!(
            dy.dependencies[0].install_name,
            "/usr/lib/system/libcache.dylib"
        );
        assert_eq!(dy.dependencies[1].ordinal, 2);
    }

    #[test]
    fn from_tbd_decodes_objc_symbols_with_prefix() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets: [ arm64-macos ]\n\
                   install-name: '/usr/lib/libobjc.A.dylib'\n\
                   exports:\n\
                   \x20 - targets: [ arm64-macos ]\n\
                   \x20   objc-classes: [ NSObject, NSArray ]\n\
                   \x20   objc-eh-types: [ NSException ]\n";
        let tbd = &parse_tbd(src).unwrap()[0];
        let dy = DylibFile::from_tbd("/stub/libobjc.tbd", tbd, &arm64_macos());
        let names: Vec<String> = dy
            .exports
            .entries()
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"_OBJC_CLASS_$_NSObject".to_string()));
        assert!(names.contains(&"_OBJC_CLASS_$_NSArray".to_string()));
        assert!(names.contains(&"_OBJC_EHTYPE_$_NSException".to_string()));
    }

    #[test]
    fn from_tbd_parses_current_version_into_packed_u32() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets: [ arm64-macos ]\n\
                   install-name: '/usr/lib/libfoo.dylib'\n\
                   current-version: 14.2.3\n";
        let tbd = &parse_tbd(src).unwrap()[0];
        let dy = DylibFile::from_tbd("/stub", tbd, &arm64_macos());
        assert_eq!(dy.current_version, (14 << 16) | (2 << 8) | 3);
    }

    #[test]
    fn parse_dylib_rejects_non_dylib_filetype() {
        // MH_OBJECT image — should fail DylibFile::parse with a clear error.
        let hdr = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 0,
            filetype: MH_OBJECT,
            ncmds: 0,
            sizeofcmds: 0,
            flags: 0,
            reserved: 0,
        };
        let mut image = Vec::new();
        write_header(&hdr, &mut image);
        let err = DylibFile::parse("/tmp/obj.o", &image).unwrap_err();
        assert!(matches!(
            err,
            ReadError::UnexpectedFiletype {
                got: MH_OBJECT,
                expected: MH_DYLIB
            }
        ));
    }
}
