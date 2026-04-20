//! afs-ld — standalone ARM64 Mach-O linker.
//!
//! Sprint 0 scaffolding: public surface is declared but every link attempt
//! returns `LinkError::NotYetImplemented`. Subsequent sprints fill in the
//! reader, resolver, layout, reloc, synth, writer, and signing paths.

pub mod archive;
pub mod args;
pub mod atom;
pub mod diag;
pub mod dump;
pub mod input;
pub mod layout;
pub mod leb;
pub mod macho;
pub mod reloc;
pub mod resolve;
pub mod section;
pub mod string_table;
pub mod symbol;
pub mod synth;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::{fs, io};

use atom::{atomize_object, backpatch_symbol_atoms, AtomTable};
use layout::{Layout, LayoutInput};
use macho::dylib::{DylibDependency, DylibFile, DylibLoadKind};
use macho::reader::ReadError;
use macho::tbd::{parse_tbd, parse_version, Arch, Platform, Target};
use reloc::arm64::RelocError;
use resolve::{
    classify_unresolved, drain_fetches, find_archive_by_path, force_load_all, force_load_archive,
    format_duplicate_diagnostic, format_undefined_diagnostic, seed_all, DrainReport, DylibLoadMeta,
    InputAddError, Inputs, Symbol, SymbolTable, UndefinedTreatment,
};

const DEFAULT_TBD_VERSION: u32 = 1 << 16;

/// What kind of Mach-O file the linker is producing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    Executable,
    Dylib,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformVersion {
    pub minos: u32,
    pub sdk: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkSpec {
    pub name: String,
    pub weak: bool,
}

/// User-facing linker configuration, populated by the CLI parser.
#[derive(Debug, Clone)]
pub struct LinkOptions {
    pub inputs: Vec<PathBuf>,
    pub library_names: Vec<String>,
    pub frameworks: Vec<FrameworkSpec>,
    pub search_paths: Vec<PathBuf>,
    pub syslibroot: Option<PathBuf>,
    pub platform_version: Option<PlatformVersion>,
    pub undefined_treatment: UndefinedTreatment,
    pub rpaths: Vec<String>,
    pub install_name: Option<String>,
    pub current_version: Option<u32>,
    pub compatibility_version: Option<u32>,
    pub output: Option<PathBuf>,
    pub entry: Option<String>,
    pub arch: Option<String>,
    pub objc_force_load: bool,
    pub strip_locals: bool,
    pub all_load: bool,
    pub force_load_archives: Vec<PathBuf>,
    pub kind: OutputKind,
    /// When set, afs-ld operates in dump mode and prints the given file's
    /// header + load commands instead of linking.
    pub dump: Option<PathBuf>,
    /// When set, afs-ld dumps the named static archive's structure.
    pub dump_archive: Option<PathBuf>,
    /// When set, afs-ld dumps the named MH_DYLIB's load commands + exports.
    pub dump_dylib: Option<PathBuf>,
    /// When set, afs-ld dumps the named TAPI TBD stub (all documents).
    pub dump_tbd: Option<PathBuf>,
}

impl Default for LinkOptions {
    fn default() -> Self {
        Self {
            inputs: Vec::new(),
            library_names: Vec::new(),
            frameworks: Vec::new(),
            search_paths: Vec::new(),
            syslibroot: None,
            platform_version: None,
            undefined_treatment: UndefinedTreatment::Error,
            rpaths: Vec::new(),
            install_name: None,
            current_version: None,
            compatibility_version: None,
            output: None,
            entry: None,
            arch: None,
            objc_force_load: false,
            strip_locals: false,
            all_load: false,
            force_load_archives: Vec::new(),
            kind: OutputKind::Executable,
            dump: None,
            dump_archive: None,
            dump_dylib: None,
            dump_tbd: None,
        }
    }
}

#[derive(Debug)]
pub enum LinkError {
    /// No input files were provided on the command line.
    NoInputs,
    Io(io::Error),
    Input(InputAddError),
    Seed(resolve::SeedError),
    Fetch(resolve::FetchError),
    Write(macho::writer::WriteError),
    Tbd(macho::tbd::TbdError),
    Reloc(RelocError),
    Synth(synth::SynthError),
    Unwind(synth::unwind::UnwindError),
    DuplicateSymbols(String),
    UndefinedSymbols(String),
    UnsupportedArch(String),
    NoTbdDocument(PathBuf),
    EntrySymbolNotFound(String),
    ForceLoadNotArchive(PathBuf),
    LibraryNotFound(String),
    FrameworkNotFound(String),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::NoInputs => write!(f, "no input files"),
            LinkError::Io(e) => write!(f, "{e}"),
            LinkError::Input(e) => write!(f, "{e}"),
            LinkError::Seed(e) => write!(f, "{e}"),
            LinkError::Fetch(e) => write!(f, "{e}"),
            LinkError::Write(e) => write!(f, "{e}"),
            LinkError::Tbd(e) => write!(f, "{e}"),
            LinkError::Reloc(e) => write!(f, "{e}"),
            LinkError::Synth(e) => write!(f, "{e}"),
            LinkError::Unwind(e) => write!(f, "{e}"),
            LinkError::DuplicateSymbols(msg) | LinkError::UndefinedSymbols(msg) => {
                write!(f, "{msg}")
            }
            LinkError::UnsupportedArch(arch) => {
                write!(f, "unsupported arch `{arch}` (afs-ld requires arm64)")
            }
            LinkError::NoTbdDocument(path) => {
                write!(f, "{}: no arm64-macos TBD document found", path.display())
            }
            LinkError::EntrySymbolNotFound(name) => {
                write!(f, "entry symbol `{name}` was not found in linked objects")
            }
            LinkError::ForceLoadNotArchive(path) => {
                write!(
                    f,
                    "{}: -force_load requires a path that is also present as an archive input",
                    path.display()
                )
            }
            LinkError::LibraryNotFound(name) => {
                write!(f, "unable to find library `{name}`")
            }
            LinkError::FrameworkNotFound(name) => {
                write!(f, "unable to find framework `{name}`")
            }
        }
    }
}

impl std::error::Error for LinkError {}

impl From<io::Error> for LinkError {
    fn from(value: io::Error) -> Self {
        LinkError::Io(value)
    }
}

impl From<InputAddError> for LinkError {
    fn from(value: InputAddError) -> Self {
        LinkError::Input(value)
    }
}

impl From<ReadError> for LinkError {
    fn from(value: ReadError) -> Self {
        LinkError::Input(InputAddError::from(value))
    }
}

impl From<resolve::SeedError> for LinkError {
    fn from(value: resolve::SeedError) -> Self {
        LinkError::Seed(value)
    }
}

impl From<resolve::FetchError> for LinkError {
    fn from(value: resolve::FetchError) -> Self {
        LinkError::Fetch(value)
    }
}

impl From<macho::writer::WriteError> for LinkError {
    fn from(value: macho::writer::WriteError) -> Self {
        LinkError::Write(value)
    }
}

impl From<macho::tbd::TbdError> for LinkError {
    fn from(value: macho::tbd::TbdError) -> Self {
        LinkError::Tbd(value)
    }
}

impl From<RelocError> for LinkError {
    fn from(value: RelocError) -> Self {
        LinkError::Reloc(value)
    }
}

impl From<synth::SynthError> for LinkError {
    fn from(value: synth::SynthError) -> Self {
        LinkError::Synth(value)
    }
}

impl From<synth::unwind::UnwindError> for LinkError {
    fn from(value: synth::unwind::UnwindError) -> Self {
        LinkError::Unwind(value)
    }
}

/// The linker itself. Sprint 0 only validates that inputs exist; later sprints
/// grow this into the full pipeline described in `.docs/overview.md`.
pub struct Linker;

impl Linker {
    pub fn run(opts: &LinkOptions) -> Result<(), LinkError> {
        if opts.inputs.is_empty() && opts.library_names.is_empty() && opts.frameworks.is_empty() {
            return Err(LinkError::NoInputs);
        }

        if let Some(arch) = &opts.arch {
            if arch != "arm64" {
                return Err(LinkError::UnsupportedArch(arch.clone()));
            }
        }

        let mut load_paths = opts.inputs.clone();
        let mut dylib_load_kinds = std::collections::HashMap::new();
        for name in &opts.library_names {
            let path = resolve_library_input(opts, name)?;
            dylib_load_kinds.insert(path.clone(), DylibLoadKind::Normal);
            load_paths.push(path);
        }
        for framework in &opts.frameworks {
            let path = resolve_framework_input(opts, &framework.name)?;
            dylib_load_kinds.insert(
                path.clone(),
                if framework.weak {
                    DylibLoadKind::Weak
                } else {
                    DylibLoadKind::Normal
                },
            );
            load_paths.push(path);
        }

        let mut inputs = Inputs::new();
        for (load_order, path) in load_paths.iter().enumerate() {
            register_input(&mut inputs, path, load_order)?;
        }

        let mut sym_table = SymbolTable::new();
        let seed_report = seed_all(&inputs, &mut sym_table)?;
        if seed_report.has_errors() {
            let mut msg = String::new();
            for err in &seed_report.duplicates {
                msg.push_str(&format_duplicate_diagnostic(&sym_table, &inputs, err));
            }
            return Err(LinkError::DuplicateSymbols(msg));
        }

        let mut force_report = DrainReport::default();
        if opts.all_load {
            force_load_all(&mut inputs, &mut sym_table, &mut force_report)?;
        }
        for archive_path in &opts.force_load_archives {
            let Some(archive_id) = find_archive_by_path(&inputs, archive_path) else {
                return Err(LinkError::ForceLoadNotArchive(archive_path.clone()));
            };
            force_load_archive(&mut inputs, &mut sym_table, archive_id, &mut force_report)?;
        }
        if !force_report.duplicates.is_empty() {
            let mut msg = String::new();
            for err in &force_report.duplicates {
                msg.push_str(&format_duplicate_diagnostic(&sym_table, &inputs, err));
            }
            return Err(LinkError::DuplicateSymbols(msg));
        }

        let drain_report = drain_fetches(&mut inputs, &mut sym_table, seed_report.pending_fetches)?;
        if !drain_report.duplicates.is_empty() {
            let mut msg = String::new();
            for err in &drain_report.duplicates {
                msg.push_str(&format_duplicate_diagnostic(&sym_table, &inputs, err));
            }
            return Err(LinkError::DuplicateSymbols(msg));
        }
        let mut referrers = seed_report.referrers.clone();
        referrers.extend_from(&force_report.referrers);
        referrers.extend_from(&drain_report.referrers);
        let unresolved = classify_unresolved(&mut sym_table, opts.undefined_treatment);
        if !unresolved.errors.is_empty() {
            return Err(LinkError::UndefinedSymbols(format_undefined_diagnostic(
                &sym_table,
                &inputs,
                &referrers,
                &unresolved.errors,
            )));
        }

        let mut atom_table = AtomTable::new();
        let mut objects = Vec::new();
        for idx in 0..inputs.objects.len() {
            let input_id = resolve::InputId(idx as u32);
            let obj = inputs.object_file(input_id)?;
            let atomization = atomize_object(input_id, &obj, &mut atom_table);
            backpatch_symbol_atoms(
                &atomization,
                input_id,
                &obj,
                &mut sym_table,
                &mut atom_table,
            );
            objects.push((input_id, obj));
        }

        let layout_inputs: Vec<LayoutInput<'_>> = objects
            .iter()
            .map(|(id, object)| {
                let input = inputs.object(*id);
                LayoutInput {
                    id: *id,
                    object,
                    load_order: input.load_order,
                    archive_member_offset: input.archive_member_offset,
                }
            })
            .collect();
        let mut dylib_loads = Vec::new();
        let mut seen_ordinals = std::collections::BTreeSet::new();
        for dylib in &inputs.dylibs {
            if !seen_ordinals.insert(dylib.ordinal) {
                continue;
            }
            dylib_loads.push(DylibDependency {
                kind: dylib_load_kinds
                    .get(&dylib.path)
                    .copied()
                    .unwrap_or(DylibLoadKind::Normal),
                install_name: dylib.load_install_name.clone(),
                current_version: dylib.load_current_version,
                compatibility_version: dylib.load_compatibility_version,
                ordinal: dylib.ordinal,
            });
        }
        let synthetic_plan = synth::SyntheticPlan::build(
            &layout_inputs,
            &atom_table,
            &mut sym_table,
            &inputs.dylibs,
        )?;
        let mut layout = Layout::build_with_synthetics(
            opts.kind,
            &layout_inputs,
            &atom_table,
            0,
            Some(&synthetic_plan),
        );
        let linkedit_context = macho::writer::LinkEditContext {
            layout_inputs: &layout_inputs,
            atom_table: &atom_table,
            sym_table: &sym_table,
            synthetic_plan: &synthetic_plan,
        };
        let mut linkedit = None;
        for _ in 0..4 {
            let (next_layout, next_linkedit) = macho::writer::finalize_layout_with_linkedit(
                &layout,
                opts.kind,
                opts,
                &dylib_loads,
                linkedit_context,
            )?;
            layout = next_layout;
            linkedit = Some(next_linkedit);
            let changed = synth::unwind::synthesize(
                &mut layout,
                &layout_inputs,
                &atom_table,
                &sym_table,
                &synthetic_plan,
            )?;
            if !changed {
                break;
            }
        }
        let linkedit = linkedit.expect("finalize loop always runs at least once");
        reloc::arm64::apply_layout(
            &mut layout,
            &layout_inputs,
            &atom_table,
            &sym_table,
            Some(&synthetic_plan),
            &linkedit,
        )?;

        let mut image = Vec::new();
        let entry_point = resolve_entry_point(opts, &sym_table)?;
        macho::writer::write_finalized_with_linkedit(
            &layout,
            opts.kind,
            opts,
            entry_point,
            &dylib_loads,
            &linkedit,
            &mut image,
        )?;
        let output = default_output_path(opts);
        fs::write(&output, image)?;
        if opts.kind == OutputKind::Executable {
            let mut perms = fs::metadata(&output)?.permissions();
            let mode = perms.mode();
            perms.set_mode(mode | ((mode & 0o444) >> 2));
            fs::set_permissions(&output, perms)?;
        }
        Ok(())
    }
}

fn resolve_library_input(opts: &LinkOptions, name: &str) -> Result<PathBuf, LinkError> {
    let mut search_dirs = Vec::new();
    for dir in &opts.search_paths {
        search_dirs.push(dir.clone());
        if let Some(root) = &opts.syslibroot {
            if let Ok(stripped) = dir.strip_prefix("/") {
                search_dirs.push(root.join(stripped));
            }
        }
    }
    if let Some(root) = &opts.syslibroot {
        search_dirs.push(root.join("usr/lib"));
    } else {
        search_dirs.push(PathBuf::from("/usr/lib"));
    }

    let candidates = [
        format!("lib{name}.tbd"),
        format!("lib{name}.dylib"),
        format!("lib{name}.a"),
    ];
    for dir in search_dirs {
        for candidate in &candidates {
            let path = dir.join(candidate);
            if path.is_file() {
                return Ok(path);
            }
        }
    }
    Err(LinkError::LibraryNotFound(name.to_string()))
}

fn resolve_framework_input(opts: &LinkOptions, name: &str) -> Result<PathBuf, LinkError> {
    let mut roots = Vec::new();
    if let Some(root) = &opts.syslibroot {
        roots.push(root.join("System/Library/Frameworks"));
        roots.push(root.join("Library/Frameworks"));
    } else {
        roots.push(PathBuf::from("/System/Library/Frameworks"));
        roots.push(PathBuf::from("/Library/Frameworks"));
    }

    for root in roots {
        let framework_dir = root.join(format!("{name}.framework"));
        for candidate in [
            framework_dir.join(format!("{name}.tbd")),
            framework_dir.join(name),
        ] {
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(LinkError::FrameworkNotFound(name.to_string()))
}

fn default_output_path(opts: &LinkOptions) -> PathBuf {
    opts.output
        .clone()
        .unwrap_or_else(|| PathBuf::from("a.out"))
}

fn register_input(
    inputs: &mut Inputs,
    path: &std::path::Path,
    load_order: usize,
) -> Result<(), LinkError> {
    let bytes = fs::read(path)?;
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("a") => {
            let _ = inputs.add_archive(path.to_path_buf(), bytes, load_order)?;
        }
        Some("dylib") => {
            let _ = inputs.add_dylib(path.to_path_buf(), bytes)?;
        }
        Some("tbd") => {
            let text = std::str::from_utf8(&bytes).map_err(|e| {
                LinkError::Tbd(macho::tbd::TbdError::Schema {
                    msg: format!("TBD input is not UTF-8: {e}"),
                })
            })?;
            let docs = parse_tbd(text)?;
            let target = Target {
                arch: Arch::Arm64,
                platform: Platform::MacOs,
            };
            let canonical = docs
                .iter()
                .find(|doc| doc.parent_umbrella.is_empty())
                .unwrap_or_else(|| &docs[0]);
            let load = DylibLoadMeta {
                install_name: canonical.install_name.clone(),
                current_version: canonical
                    .current_version
                    .as_deref()
                    .map(parse_version)
                    .unwrap_or(DEFAULT_TBD_VERSION),
                compatibility_version: canonical
                    .compatibility_version
                    .as_deref()
                    .map(parse_version)
                    .unwrap_or(DEFAULT_TBD_VERSION),
                ordinal: inputs.next_dylib_ordinal(),
            };
            let mut loaded = false;
            for doc in docs
                .iter()
                .filter(|doc| doc.targets.iter().any(|t| t.matches_requested(&target)))
            {
                let file = DylibFile::from_tbd(path, doc, &target);
                let _ =
                    inputs.add_dylib_from_file_with_meta(path.to_path_buf(), file, load.clone());
                loaded = true;
            }
            if !loaded {
                return Err(LinkError::NoTbdDocument(path.to_path_buf()));
            }
        }
        _ => {
            let _ = inputs.add_object(path.to_path_buf(), bytes, load_order)?;
        }
    }
    Ok(())
}

fn resolve_entry_point(
    opts: &LinkOptions,
    sym_table: &SymbolTable,
) -> Result<Option<macho::writer::EntryPoint>, LinkError> {
    let name = if let Some(name) = &opts.entry {
        name.as_str()
    } else if opts.kind == OutputKind::Executable {
        if symbol_defined(sym_table, "_main") {
            "_main"
        } else if symbol_defined(sym_table, "_start") {
            "_start"
        } else {
            return Ok(None);
        }
    } else {
        return Ok(None);
    };
    let Some((symbol_id, _)) = sym_table
        .iter()
        .find(|(_, symbol)| sym_table.interner.resolve(symbol.name()) == name)
    else {
        return Err(LinkError::EntrySymbolNotFound(name.to_string()));
    };
    let Symbol::Defined { atom, value, .. } = sym_table.get(symbol_id) else {
        return Err(LinkError::EntrySymbolNotFound(name.to_string()));
    };
    Ok(Some(macho::writer::EntryPoint {
        atom: *atom,
        atom_value: *value,
    }))
}

fn symbol_defined(sym_table: &SymbolTable, name: &str) -> bool {
    sym_table.iter().any(|(_, symbol)| {
        sym_table.interner.resolve(symbol.name()) == name
            && matches!(symbol, Symbol::Defined { .. })
    })
}
