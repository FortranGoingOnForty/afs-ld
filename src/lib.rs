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
pub mod icf;
pub mod input;
pub mod layout;
pub mod leb;
pub mod link_map;
pub mod loh;
pub mod macho;
pub mod reloc;
pub mod resolve;
pub mod section;
pub mod string_table;
pub mod symbol;
pub mod synth;
pub mod why_live;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::{
    collections::{HashSet, VecDeque},
    fs, io,
};

use archive::Archive;
use atom::{atomize_object, backpatch_symbol_atoms, AtomTable};
use icf::IcfError;
use input::ObjectFile;
use layout::{ExtraLayoutSections, Layout, LayoutInput};
use macho::dylib::{DylibDependency, DylibFile, DylibLoadKind};
use macho::reader::ReadError;
use macho::tbd::{
    parse_tbd_for_target_matching, parse_tbd_metadata_for_target, parse_version, Arch, Platform,
    Target,
};
use reloc::arm64::RelocError;
use resolve::{
    classify_unresolved, drain_fetches, find_archive_by_path, force_load_all, force_load_archive,
    format_duplicate_diagnostic, format_undefined_diagnostic, format_undefined_warning_diagnostic,
    levenshtein, seed_all, seed_dylib, DrainReport, DylibLoadMeta, InputAddError, InputId, Inputs,
    SeedReport, Symbol, SymbolTable, UndefinedTreatment,
};
use symbol::SymKind;

const DEFAULT_TBD_VERSION: u32 = 1 << 16;
const THUNK_PLAN_MAX_ITERATIONS: usize = 16;

/// What kind of Mach-O file the linker is producing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    Executable,
    Dylib,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcfMode {
    None,
    Safe,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThunkMode {
    None,
    Safe,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformVersion {
    pub minos: u32,
    pub sdk: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixupChainsMode {
    Auto,
    Classic,
    Chained,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
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
    pub exported_symbols_lists: Vec<PathBuf>,
    pub unexported_symbols_lists: Vec<PathBuf>,
    pub exported_symbols: Vec<String>,
    pub unexported_symbols: Vec<String>,
    pub map: Option<PathBuf>,
    pub why_live: Vec<String>,
    pub trace_inputs: bool,
    pub verbose: bool,
    pub show_version: bool,
    pub show_help: bool,
    pub output: Option<PathBuf>,
    pub entry: Option<String>,
    pub arch: Option<String>,
    pub relocatable: bool,
    pub bundle: bool,
    pub objc_force_load: bool,
    pub strip_locals: bool,
    pub strip_debug: bool,
    pub emit_uuid: bool,
    pub dead_strip: bool,
    pub no_loh: bool,
    pub icf_mode: IcfMode,
    pub thunks: ThunkMode,
    pub fixup_chains: FixupChainsMode,
    pub color: ColorMode,
    pub all_load: bool,
    pub force_load_archives: Vec<PathBuf>,
    pub jobs: Option<usize>,
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
            exported_symbols_lists: Vec::new(),
            unexported_symbols_lists: Vec::new(),
            exported_symbols: Vec::new(),
            unexported_symbols: Vec::new(),
            map: None,
            why_live: Vec::new(),
            trace_inputs: false,
            verbose: false,
            show_version: false,
            show_help: false,
            output: None,
            entry: None,
            arch: None,
            relocatable: false,
            bundle: false,
            objc_force_load: false,
            strip_locals: false,
            strip_debug: false,
            emit_uuid: true,
            dead_strip: false,
            no_loh: false,
            icf_mode: IcfMode::None,
            thunks: ThunkMode::Safe,
            fixup_chains: FixupChainsMode::Auto,
            color: ColorMode::Auto,
            all_load: false,
            force_load_archives: Vec::new(),
            jobs: None,
            kind: OutputKind::Executable,
            dump: None,
            dump_archive: None,
            dump_dylib: None,
            dump_tbd: None,
        }
    }
}

impl LinkOptions {
    pub fn parallel_jobs(&self) -> usize {
        self.jobs
            .unwrap_or_else(|| {
                thread::available_parallelism()
                    .map(usize::from)
                    .unwrap_or(1)
            })
            .max(1)
    }

    pub fn uses_chained_fixups(&self) -> bool {
        match self.fixup_chains {
            FixupChainsMode::Chained => true,
            FixupChainsMode::Classic => false,
            FixupChainsMode::Auto => self
                .platform_version
                .is_some_and(|version| version.minos >= (12 << 16)),
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
    Icf(IcfError),
    Loh(loh::LohError),
    MalformedInput {
        path: PathBuf,
        bytes: Vec<u8>,
        error: ReadError,
    },
    DuplicateSymbols(String),
    UndefinedSymbols(String),
    UnsupportedArch(String),
    NoTbdDocument(PathBuf),
    EntrySymbolNotFound(String),
    ForceLoadNotArchive(PathBuf),
    LibraryNotFound {
        name: String,
        suggestion: Option<String>,
    },
    FrameworkNotFound {
        name: String,
        suggestion: Option<String>,
    },
    ThunkPlanningDidNotConverge,
    WhyLive(String),
    UnsupportedOption(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkPhaseTimings {
    pub input_parsing: Duration,
    pub input_read: Duration,
    pub input_object_parse: Duration,
    pub input_archive_parse: Duration,
    pub input_dylib_parse: Duration,
    pub input_tbd_decode: Duration,
    pub input_tbd_materialize: Duration,
    pub input_reloc_parse: Duration,
    pub symbol_resolution: Duration,
    pub atomization: Duration,
    pub layout: Duration,
    pub layout_entry_lookup: Duration,
    pub layout_dead_strip: Duration,
    pub layout_icf: Duration,
    pub layout_synthetic_plan: Duration,
    pub layout_build: Duration,
    pub layout_thunk_plan: Duration,
    pub synth_sections: Duration,
    pub synth_linkedit_finalize: Duration,
    pub synth_linkedit_symbol_plan: Duration,
    pub synth_linkedit_symbol_plan_locals: Duration,
    pub synth_linkedit_symbol_plan_globals: Duration,
    pub synth_linkedit_symbol_plan_strtab: Duration,
    pub synth_linkedit_dyld_info: Duration,
    pub synth_linkedit_dyld_bind: Duration,
    pub synth_linkedit_dyld_rebase: Duration,
    pub synth_linkedit_dyld_export: Duration,
    pub synth_linkedit_metadata_tables: Duration,
    pub synth_linkedit_code_signature: Duration,
    pub synth_unwind: Duration,
    pub reloc_apply: Duration,
    pub write_output: Duration,
    pub write_image_build: Duration,
    pub write_file: Duration,
    pub write_link_map: Duration,
    pub write_permissions: Duration,
}

impl LinkPhaseTimings {
    pub fn accounted_total(&self) -> Duration {
        self.input_parsing
            + self.symbol_resolution
            + self.atomization
            + self.layout
            + self.synth_sections
            + self.reloc_apply
            + self.write_output
    }

    fn add_input_load(&mut self, timings: InputLoadTimings) {
        self.input_read += timings.read;
        self.input_object_parse += timings.object_parse;
        self.input_archive_parse += timings.archive_parse;
        self.input_dylib_parse += timings.dylib_parse;
        self.input_tbd_decode += timings.tbd_decode;
        self.input_tbd_materialize += timings.tbd_materialize;
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct InputLoadTimings {
    read: Duration,
    object_parse: Duration,
    archive_parse: Duration,
    dylib_parse: Duration,
    tbd_decode: Duration,
    tbd_materialize: Duration,
}

impl std::ops::AddAssign for InputLoadTimings {
    fn add_assign(&mut self, rhs: Self) {
        self.read += rhs.read;
        self.object_parse += rhs.object_parse;
        self.archive_parse += rhs.archive_parse;
        self.dylib_parse += rhs.dylib_parse;
        self.tbd_decode += rhs.tbd_decode;
        self.tbd_materialize += rhs.tbd_materialize;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkProfile {
    pub output: PathBuf,
    pub phases: LinkPhaseTimings,
    pub total_wall: Duration,
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
            LinkError::Icf(e) => write!(f, "{e}"),
            LinkError::Loh(e) => write!(f, "{e}"),
            LinkError::MalformedInput { path, error, .. } => {
                write!(f, "{}: {error}", path.display())
            }
            LinkError::DuplicateSymbols(msg) | LinkError::UndefinedSymbols(msg) => {
                write!(f, "{msg}")
            }
            LinkError::UnsupportedArch(arch) => {
                write!(f, "unsupported arch `{arch}` (afs-ld requires arm64)")?;
                if let Some(suggestion) = arch_suggestion(arch) {
                    write!(f, " (did you mean `{suggestion}`?)")?;
                }
                Ok(())
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
            LinkError::LibraryNotFound { name, suggestion } => {
                write!(f, "unable to find library `{name}`")?;
                if let Some(suggestion) = suggestion {
                    write!(f, " (did you mean `-l{suggestion}`?)")?;
                }
                Ok(())
            }
            LinkError::FrameworkNotFound { name, suggestion } => {
                write!(f, "unable to find framework `{name}`")?;
                if let Some(suggestion) = suggestion {
                    write!(f, " (did you mean `-framework {suggestion}`?)")?;
                }
                Ok(())
            }
            LinkError::ThunkPlanningDidNotConverge => {
                write!(f, "thunk planning did not converge")
            }
            LinkError::WhyLive(msg) => write!(f, "{msg}"),
            LinkError::UnsupportedOption(msg) => write!(f, "{msg}"),
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

impl From<IcfError> for LinkError {
    fn from(value: IcfError) -> Self {
        LinkError::Icf(value)
    }
}

impl From<loh::LohError> for LinkError {
    fn from(value: loh::LohError) -> Self {
        LinkError::Loh(value)
    }
}

/// The linker itself. Sprint 0 only validates that inputs exist; later sprints
/// grow this into the full pipeline described in `.docs/overview.md`.
pub struct Linker;

impl Linker {
    pub fn run(opts: &LinkOptions) -> Result<(), LinkError> {
        Self::run_profiled(opts).map(|_| ())
    }

    pub fn run_profiled(opts: &LinkOptions) -> Result<LinkProfile, LinkError> {
        let overall_started = Instant::now();
        let mut phases = LinkPhaseTimings::default();
        if opts.relocatable {
            return Err(LinkError::UnsupportedOption(
                "`-r` relocatable output is not yet supported".into(),
            ));
        }
        if opts.bundle {
            return Err(LinkError::UnsupportedOption(
                "`-bundle` output is not yet supported".into(),
            ));
        }
        if opts.icf_mode == IcfMode::All {
            return Err(LinkError::UnsupportedOption(
                "`-icf=all` is not yet supported; use `-icf=safe` or `-icf=none`".into(),
            ));
        }
        if opts.inputs.is_empty() && opts.library_names.is_empty() && opts.frameworks.is_empty() {
            return Err(LinkError::NoInputs);
        }
        let parallel_jobs = opts.parallel_jobs();

        if let Some(arch) = &opts.arch {
            if arch != "arm64" {
                return Err(LinkError::UnsupportedArch(arch.clone()));
            }
        }

        if opts.strip_debug {
            crate::diag::warning(
                "`-S` requested, but afs-ld does not currently emit debug symbols",
            );
        }
        if opts.objc_force_load {
            crate::diag::warning(
                "`-ObjC` requested, but afs-ld does not yet scan Objective-C archive metadata; the flag currently has no effect",
            );
        }
        if opts.no_loh {
            crate::diag::warning(
                "`-no_loh` requested, but afs-ld currently matches Apple ld by omitting final-output LOH; the flag has no effect",
            );
        }

        let mut load_paths = Vec::new();
        let mut positional_dylibs = Vec::new();
        for path in &opts.inputs {
            match path.extension().and_then(|ext| ext.to_str()) {
                Some("dylib" | "tbd") => positional_dylibs.push(path.clone()),
                _ => load_paths.push(path.clone()),
            }
        }
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
        load_paths.extend(positional_dylibs);

        let mut inputs = Inputs::new();
        let mut deferred_dylibs = Vec::new();
        let mut initial_loads = Vec::new();
        let phase_started = Instant::now();
        for (load_order, path) in load_paths.iter().enumerate() {
            if matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("dylib" | "tbd")
            ) {
                deferred_dylibs.push((load_order, path.clone()));
                continue;
            }
            if opts.trace_inputs {
                eprintln!("afs-ld: loading {}", path.display());
            }
            initial_loads.push((load_order, path.clone()));
        }
        for loaded in load_initial_inputs(initial_loads, parallel_jobs)? {
            let timings = register_loaded_initial_input(&mut inputs, loaded);
            phases.add_input_load(timings);
        }
        let tbd_export_names = if inputs_may_need_dylib_exports(&inputs)? {
            Some(collect_initial_tbd_export_names(&inputs)?)
        } else {
            None
        };
        let tbd_export_selection = tbd_export_names.as_ref().map_or(
            TbdExportSelection::MetadataOnly,
            TbdExportSelection::Matching,
        );
        for (load_order, path) in &deferred_dylibs {
            if opts.trace_inputs {
                eprintln!("afs-ld: loading {}", path.display());
            }
            let timings = register_input(&mut inputs, path, *load_order, tbd_export_selection)?;
            phases.add_input_load(timings);
        }
        phases.input_parsing = phase_started.elapsed();

        let mut sym_table = SymbolTable::new();
        let phase_started = Instant::now();
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
            force_load_all(
                &mut inputs,
                &mut sym_table,
                &mut force_report,
                parallel_jobs,
            )?;
        }
        for archive_path in &opts.force_load_archives {
            let Some(archive_id) = find_archive_by_path(&inputs, archive_path) else {
                return Err(LinkError::ForceLoadNotArchive(archive_path.clone()));
            };
            force_load_archive(
                &mut inputs,
                &mut sym_table,
                archive_id,
                &mut force_report,
                parallel_jobs,
            )?;
        }
        if opts.trace_inputs {
            for path in &force_report.loaded_paths {
                eprintln!("afs-ld: loading {}", path.display());
            }
        }
        if !force_report.duplicates.is_empty() {
            let mut msg = String::new();
            for err in &force_report.duplicates {
                msg.push_str(&format_duplicate_diagnostic(&sym_table, &inputs, err));
            }
            return Err(LinkError::DuplicateSymbols(msg));
        }

        let drain_report = drain_fetches(
            &mut inputs,
            &mut sym_table,
            seed_report.pending_fetches,
            parallel_jobs,
        )?;
        if opts.trace_inputs {
            for path in &drain_report.loaded_paths {
                eprintln!("afs-ld: loading {}", path.display());
            }
        }
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
        let tbd_report = load_tbd_exports_for_unresolved(
            &mut inputs,
            &deferred_dylibs,
            &mut sym_table,
            tbd_export_names.as_ref(),
        )?;
        phases.add_input_load(tbd_report.timings);
        if tbd_report.seed_report.has_errors() {
            let mut msg = String::new();
            for err in &tbd_report.seed_report.duplicates {
                msg.push_str(&format_duplicate_diagnostic(&sym_table, &inputs, err));
            }
            return Err(LinkError::DuplicateSymbols(msg));
        }
        let unresolved = classify_unresolved(&mut sym_table, opts.undefined_treatment);
        if !unresolved.errors.is_empty() {
            return Err(LinkError::UndefinedSymbols(format_undefined_diagnostic(
                &sym_table,
                &inputs,
                &referrers,
                &unresolved.errors,
            )));
        }
        if !unresolved.warnings.is_empty() {
            crate::diag::warning_verbatim(&format_undefined_warning_diagnostic(
                &sym_table,
                &inputs,
                &referrers,
                &unresolved.warnings,
            ));
        }
        phases.symbol_resolution = phase_started.elapsed();

        let mut atom_table = AtomTable::new();
        let mut objects = Vec::new();
        let phase_started = Instant::now();
        for idx in 0..inputs.objects.len() {
            let input_id = resolve::InputId(idx as u32);
            let obj = inputs.object_file(input_id)?;
            let atomization = atomize_object(input_id, obj, &mut atom_table);
            backpatch_symbol_atoms(&atomization, input_id, obj, &mut sym_table, &mut atom_table);
            objects.push((input_id, obj));
        }
        phases.atomization = phase_started.elapsed();

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
        let phase_started = Instant::now();
        let parsed_relocs = macho::writer::build_parsed_reloc_cache(&layout_inputs)?;
        let elapsed = phase_started.elapsed();
        phases.input_reloc_parse += elapsed;
        phases.input_parsing += elapsed;
        let layout_started = Instant::now();
        let phase_started = Instant::now();
        let entry_symbol = find_entry_symbol_id(opts, &sym_table)?;
        phases.layout_entry_lookup = phase_started.elapsed();
        let phase_started = Instant::now();
        let dead_strip = opts.dead_strip.then(|| {
            why_live::DeadStripAnalysis::build(
                opts,
                &layout_inputs,
                &atom_table,
                &sym_table,
                entry_symbol,
            )
        });
        phases.layout_dead_strip = phase_started.elapsed();
        let phase_started = Instant::now();
        let icf = (opts.icf_mode == IcfMode::Safe)
            .then(|| {
                icf::fold_safe(
                    &layout_inputs,
                    &mut atom_table,
                    &mut sym_table,
                    dead_strip.as_ref().map(|analysis| analysis.live_atoms()),
                )
            })
            .transpose()?;
        phases.layout_icf = phase_started.elapsed();
        let kept_atoms = if let Some(icf) = &icf {
            Some(icf.kept_atoms())
        } else {
            dead_strip.as_ref().map(|analysis| analysis.live_atoms())
        };
        let phase_started = Instant::now();
        let synthetic_plan = synth::SyntheticPlan::build_filtered_with_relocs_and_options(
            &layout_inputs,
            &atom_table,
            &mut sym_table,
            &inputs.dylibs,
            kept_atoms,
            &parsed_relocs,
            synth::SyntheticPlanOptions {
                chained_fixups: opts.uses_chained_fixups(),
            },
        )?;
        phases.layout_synthetic_plan = phase_started.elapsed();
        let icf_redirects = icf.as_ref().map(|plan| plan.redirects());
        let phase_started = Instant::now();
        let mut layout = Layout::build_with_synthetics_filtered(
            opts.kind,
            &layout_inputs,
            &atom_table,
            0,
            Some(&synthetic_plan),
            kept_atoms,
        );
        phases.layout_build += phase_started.elapsed();
        let mut thunk_plan = None;
        let mut thunk_converged = false;
        for _ in 0..THUNK_PLAN_MAX_ITERATIONS {
            let phase_started = Instant::now();
            let next_plan = reloc::arm64::plan_thunks(
                opts,
                reloc::arm64::ThunkPlanningContext {
                    layout: &layout,
                    inputs: &layout_inputs,
                    atoms: &atom_table,
                    sym_table: &sym_table,
                    synthetic_plan: Some(&synthetic_plan),
                    icf_redirects,
                    parsed_relocs: &parsed_relocs,
                },
            )?;
            phases.layout_thunk_plan += phase_started.elapsed();
            if next_plan == thunk_plan {
                thunk_converged = true;
                break;
            }
            let extra_sections = next_plan
                .as_ref()
                .map_or_else(Vec::new, |plan| plan.output_sections());
            let split_after_atoms = next_plan
                .as_ref()
                .map_or_else(Vec::new, |plan| plan.split_after_atoms());
            let phase_started = Instant::now();
            layout = Layout::build_with_synthetics_and_extra_filtered(
                opts.kind,
                &layout_inputs,
                &atom_table,
                0,
                Some(&synthetic_plan),
                kept_atoms,
                ExtraLayoutSections {
                    extra_sections: &extra_sections,
                    split_after_atoms: &split_after_atoms,
                },
            );
            phases.layout_build += phase_started.elapsed();
            thunk_plan = next_plan;
        }
        if !thunk_converged {
            return Err(LinkError::ThunkPlanningDidNotConverge);
        }
        phases.layout = layout_started.elapsed();
        let linkedit_context = macho::writer::LinkEditContext {
            layout_inputs: &layout_inputs,
            atom_table: &atom_table,
            sym_table: &sym_table,
            synthetic_plan: &synthetic_plan,
            icf_redirects,
            parsed_relocs: &parsed_relocs,
        };
        let phase_started = Instant::now();
        let mut linkedit = None;
        let mut synth_linkedit_finalize = Duration::ZERO;
        let mut synth_linkedit_symbol_plan = Duration::ZERO;
        let mut synth_linkedit_symbol_plan_locals = Duration::ZERO;
        let mut synth_linkedit_symbol_plan_globals = Duration::ZERO;
        let mut synth_linkedit_symbol_plan_strtab = Duration::ZERO;
        let mut synth_linkedit_dyld_info = Duration::ZERO;
        let mut synth_linkedit_dyld_bind = Duration::ZERO;
        let mut synth_linkedit_dyld_rebase = Duration::ZERO;
        let mut synth_linkedit_dyld_export = Duration::ZERO;
        let mut synth_linkedit_metadata_tables = Duration::ZERO;
        let mut synth_linkedit_code_signature = Duration::ZERO;
        let mut synth_unwind = Duration::ZERO;
        let mut linkedit_cache = macho::writer::LinkEditBuildCache::default();
        for _ in 0..4 {
            let phase_started = Instant::now();
            let (next_layout, next_linkedit, linkedit_timings) =
                macho::writer::finalize_layout_with_linkedit_cached(
                    &layout,
                    opts.kind,
                    opts,
                    &dylib_loads,
                    linkedit_context,
                    &mut linkedit_cache,
                )?;
            synth_linkedit_finalize += phase_started.elapsed();
            synth_linkedit_symbol_plan += linkedit_timings.symbol_plan;
            synth_linkedit_symbol_plan_locals += linkedit_timings.symbol_plan_locals;
            synth_linkedit_symbol_plan_globals += linkedit_timings.symbol_plan_globals;
            synth_linkedit_symbol_plan_strtab += linkedit_timings.symbol_plan_strtab;
            synth_linkedit_dyld_info += linkedit_timings.dyld_info;
            synth_linkedit_dyld_bind += linkedit_timings.dyld_bind;
            synth_linkedit_dyld_rebase += linkedit_timings.dyld_rebase;
            synth_linkedit_dyld_export += linkedit_timings.dyld_export;
            synth_linkedit_metadata_tables += linkedit_timings.metadata_tables;
            synth_linkedit_code_signature += linkedit_timings.code_signature;
            layout = next_layout;
            linkedit = Some(next_linkedit);
            let phase_started = Instant::now();
            let changed = synth::unwind::synthesize(
                &mut layout,
                &layout_inputs,
                &atom_table,
                &sym_table,
                &synthetic_plan,
                &parsed_relocs,
            )?;
            synth_unwind += phase_started.elapsed();
            if !changed {
                break;
            }
        }
        let linkedit = linkedit.expect("finalize loop always runs at least once");
        phases.synth_linkedit_finalize = synth_linkedit_finalize;
        phases.synth_linkedit_symbol_plan = synth_linkedit_symbol_plan;
        phases.synth_linkedit_symbol_plan_locals = synth_linkedit_symbol_plan_locals;
        phases.synth_linkedit_symbol_plan_globals = synth_linkedit_symbol_plan_globals;
        phases.synth_linkedit_symbol_plan_strtab = synth_linkedit_symbol_plan_strtab;
        phases.synth_linkedit_dyld_info = synth_linkedit_dyld_info;
        phases.synth_linkedit_dyld_bind = synth_linkedit_dyld_bind;
        phases.synth_linkedit_dyld_rebase = synth_linkedit_dyld_rebase;
        phases.synth_linkedit_dyld_export = synth_linkedit_dyld_export;
        phases.synth_linkedit_metadata_tables = synth_linkedit_metadata_tables;
        phases.synth_linkedit_code_signature = synth_linkedit_code_signature;
        phases.synth_unwind = synth_unwind;
        phases.synth_sections = phase_started.elapsed();
        let phase_started = Instant::now();
        reloc::arm64::apply_layout(
            &mut layout,
            &layout_inputs,
            &atom_table,
            &sym_table,
            reloc::arm64::ApplyLayoutPlan {
                synthetic_plan: Some(&synthetic_plan),
                thunk_plan: thunk_plan.as_ref(),
                linkedit: &linkedit,
                icf_redirects,
                parsed_relocs: &parsed_relocs,
                parallel_jobs,
            },
        )?;
        macho::writer::apply_chained_fixups(&mut layout, &linkedit)?;
        phases.reloc_apply = phase_started.elapsed();
        let folded_symbols = icf
            .as_ref()
            .map(|plan| plan.folded_symbols(&atom_table, &sym_table, &layout_inputs))
            .unwrap_or_default();

        if let Some(report) = why_live::format_explanations(
            opts,
            &layout_inputs,
            &atom_table,
            &sym_table,
            entry_symbol,
            dead_strip.as_ref(),
            &folded_symbols,
        )
        .map_err(LinkError::WhyLive)?
        {
            print!("{report}");
        }

        let write_started = Instant::now();
        let phase_started = Instant::now();
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
        phases.write_image_build = phase_started.elapsed();
        let output = default_output_path(opts);
        let phase_started = Instant::now();
        fs::write(&output, image)?;
        phases.write_file = phase_started.elapsed();
        if let Some(map_path) = &opts.map {
            let phase_started = Instant::now();
            let dead_stripped = dead_strip
                .as_ref()
                .map(|analysis| {
                    analysis.dead_stripped_symbols(&atom_table, &sym_table, &layout_inputs)
                })
                .unwrap_or_default();
            link_map::write_link_map(
                map_path,
                opts,
                &layout,
                &layout_inputs,
                &linkedit,
                &folded_symbols,
                &dead_stripped,
            )?;
            phases.write_link_map = phase_started.elapsed();
        }
        if opts.kind == OutputKind::Executable {
            let phase_started = Instant::now();
            let mut perms = fs::metadata(&output)?.permissions();
            let mode = perms.mode();
            perms.set_mode(mode | ((mode & 0o444) >> 2));
            fs::set_permissions(&output, perms)?;
            phases.write_permissions = phase_started.elapsed();
        }
        phases.write_output = write_started.elapsed();
        Ok(LinkProfile {
            output,
            phases,
            total_wall: overall_started.elapsed(),
        })
    }
}

fn resolve_library_input(opts: &LinkOptions, name: &str) -> Result<PathBuf, LinkError> {
    let search_dirs = library_search_dirs(opts);
    let candidates = [
        format!("lib{name}.tbd"),
        format!("lib{name}.dylib"),
        format!("lib{name}.a"),
    ];
    for dir in &search_dirs {
        for candidate in &candidates {
            let path = dir.join(candidate);
            if path.is_file() {
                return Ok(path);
            }
        }
    }
    Err(LinkError::LibraryNotFound {
        name: name.to_string(),
        suggestion: library_suggestion(&search_dirs, name),
    })
}

fn library_search_dirs(opts: &LinkOptions) -> Vec<PathBuf> {
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
    search_dirs
}

fn library_suggestion(search_dirs: &[PathBuf], requested: &str) -> Option<String> {
    let mut available = Vec::new();
    for dir in search_dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Some(filename) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                continue;
            };
            if let Some(name) = parse_library_filename(&filename) {
                available.push(name);
            }
        }
    }
    best_suggestion(requested, available.into_iter())
}

fn parse_library_filename(filename: &str) -> Option<String> {
    let stem = filename.strip_prefix("lib")?;
    for suffix in [".tbd", ".dylib", ".a"] {
        if let Some(name) = stem.strip_suffix(suffix) {
            return (!name.is_empty()).then(|| name.to_string());
        }
    }
    None
}

fn resolve_framework_input(opts: &LinkOptions, name: &str) -> Result<PathBuf, LinkError> {
    let roots = framework_search_roots(opts);
    for root in &roots {
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

    Err(LinkError::FrameworkNotFound {
        name: name.to_string(),
        suggestion: framework_suggestion(&roots, name),
    })
}

fn framework_search_roots(opts: &LinkOptions) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(root) = &opts.syslibroot {
        roots.push(root.join("System/Library/Frameworks"));
        roots.push(root.join("Library/Frameworks"));
    } else {
        roots.push(PathBuf::from("/System/Library/Frameworks"));
        roots.push(PathBuf::from("/Library/Frameworks"));
    }
    roots
}

fn framework_suggestion(roots: &[PathBuf], requested: &str) -> Option<String> {
    let mut available = Vec::new();
    for root in roots {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let Some(filename) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                continue;
            };
            if let Some(name) = filename.strip_suffix(".framework") {
                available.push(name.to_string());
            }
        }
    }
    best_suggestion(requested, available.into_iter())
}

fn best_suggestion(requested: &str, candidates: impl Iterator<Item = String>) -> Option<String> {
    let requested_lower = requested.to_ascii_lowercase();
    candidates
        .filter(|candidate| candidate != requested)
        .map(|candidate| {
            let distance = levenshtein(&requested_lower, &candidate.to_ascii_lowercase());
            (distance, candidate)
        })
        .filter(|(distance, _)| *distance <= 3)
        .min_by(|(lhs_distance, lhs), (rhs_distance, rhs)| {
            lhs_distance
                .cmp(rhs_distance)
                .then_with(|| lhs.len().cmp(&rhs.len()))
                .then_with(|| lhs.cmp(rhs))
        })
        .map(|(_, candidate)| candidate)
}

fn arch_suggestion(value: &str) -> Option<String> {
    (levenshtein(value, "arm64") <= 3).then(|| "arm64".to_string())
}

fn default_output_path(opts: &LinkOptions) -> PathBuf {
    opts.output
        .clone()
        .unwrap_or_else(|| PathBuf::from("a.out"))
}

struct LoadedObjectInput {
    path: PathBuf,
    load_order: usize,
    bytes: Vec<u8>,
    parsed: ObjectFile,
    timings: InputLoadTimings,
}

struct LoadedArchiveInput {
    path: PathBuf,
    load_order: usize,
    bytes: Vec<u8>,
    timings: InputLoadTimings,
}

enum LoadedInitialInput {
    Object(Box<LoadedObjectInput>),
    Archive(LoadedArchiveInput),
}

impl LoadedInitialInput {
    fn load_order(&self) -> usize {
        match self {
            LoadedInitialInput::Object(input) => input.load_order,
            LoadedInitialInput::Archive(input) => input.load_order,
        }
    }
}

struct InitialLoadError {
    load_order: usize,
    error: LinkError,
}

fn load_initial_inputs(
    loads: Vec<(usize, PathBuf)>,
    parallel_jobs: usize,
) -> Result<Vec<LoadedInitialInput>, LinkError> {
    let mut results = Vec::new();
    let mut object_jobs = Vec::new();
    for (load_order, path) in loads {
        if matches!(path.extension().and_then(|ext| ext.to_str()), Some("a")) {
            results.push(load_archive_input(path, load_order));
        } else {
            object_jobs.push((load_order, path));
        }
    }
    results.extend(load_objects_parallel(object_jobs, parallel_jobs));
    results.sort_by_key(|result| match result {
        Ok(input) => input.load_order(),
        Err(error) => error.load_order,
    });

    let mut loaded = Vec::with_capacity(results.len());
    for result in results {
        match result {
            Ok(input) => loaded.push(input),
            Err(error) => return Err(error.error),
        }
    }
    Ok(loaded)
}

fn load_objects_parallel(
    jobs: Vec<(usize, PathBuf)>,
    parallel_jobs: usize,
) -> Vec<Result<LoadedInitialInput, InitialLoadError>> {
    if jobs.is_empty() {
        return Vec::new();
    }
    let job_count = parallel_jobs.max(1).min(jobs.len()).max(1);
    if job_count == 1 {
        return jobs
            .into_iter()
            .map(|(load_order, path)| load_object_input(path, load_order))
            .collect();
    }

    let queue = Arc::new(Mutex::new(VecDeque::from(jobs)));
    let (tx, rx) = mpsc::channel();
    thread::scope(|scope| {
        for _ in 0..job_count {
            let queue = Arc::clone(&queue);
            let tx = tx.clone();
            scope.spawn(move || loop {
                let Some((load_order, path)) = queue
                    .lock()
                    .expect("input load queue mutex poisoned")
                    .pop_front()
                else {
                    break;
                };
                tx.send(load_object_input(path, load_order))
                    .expect("input load receiver should stay live");
            });
        }
        drop(tx);
        rx.into_iter().collect()
    })
}

fn load_object_input(
    path: PathBuf,
    load_order: usize,
) -> Result<LoadedInitialInput, InitialLoadError> {
    let mut timings = InputLoadTimings::default();
    let phase_started = Instant::now();
    let bytes = fs::read(&path).map_err(|error| InitialLoadError {
        load_order,
        error: LinkError::Io(error),
    })?;
    timings.read = phase_started.elapsed();

    let phase_started = Instant::now();
    let parsed = match ObjectFile::parse(&path, &bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Err(InitialLoadError {
                load_order,
                error: LinkError::MalformedInput { path, bytes, error },
            });
        }
    };
    timings.object_parse = phase_started.elapsed();

    Ok(LoadedInitialInput::Object(Box::new(LoadedObjectInput {
        path,
        load_order,
        bytes,
        parsed,
        timings,
    })))
}

fn load_archive_input(
    path: PathBuf,
    load_order: usize,
) -> Result<LoadedInitialInput, InitialLoadError> {
    let mut timings = InputLoadTimings::default();
    let phase_started = Instant::now();
    let bytes = fs::read(&path).map_err(|error| InitialLoadError {
        load_order,
        error: LinkError::Io(error),
    })?;
    timings.read = phase_started.elapsed();

    let phase_started = Instant::now();
    Archive::open(&path, &bytes).map_err(|error| InitialLoadError {
        load_order,
        error: LinkError::from(InputAddError::from(error)),
    })?;
    timings.archive_parse = phase_started.elapsed();

    Ok(LoadedInitialInput::Archive(LoadedArchiveInput {
        path,
        load_order,
        bytes,
        timings,
    }))
}

fn register_loaded_initial_input(
    inputs: &mut Inputs,
    loaded: LoadedInitialInput,
) -> InputLoadTimings {
    match loaded {
        LoadedInitialInput::Object(input) => {
            inputs.add_parsed_object(input.path, input.bytes, input.parsed, input.load_order);
            input.timings
        }
        LoadedInitialInput::Archive(input) => {
            inputs.add_validated_archive(input.path, input.bytes, input.load_order);
            input.timings
        }
    }
}

fn register_input(
    inputs: &mut Inputs,
    path: &std::path::Path,
    load_order: usize,
    tbd_exports: TbdExportSelection<'_>,
) -> Result<InputLoadTimings, LinkError> {
    let mut timings = InputLoadTimings::default();
    let phase_started = Instant::now();
    let bytes = fs::read(path)?;
    timings.read = phase_started.elapsed();
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("a") => {
            let phase_started = Instant::now();
            let _ = inputs.add_archive(path.to_path_buf(), bytes, load_order)?;
            timings.archive_parse = phase_started.elapsed();
        }
        Some("dylib") => {
            let phase_started = Instant::now();
            let _ = inputs.add_dylib(path.to_path_buf(), bytes)?;
            timings.dylib_parse = phase_started.elapsed();
        }
        Some("tbd") => {
            let phase_started = Instant::now();
            let text = std::str::from_utf8(&bytes).map_err(|e| {
                LinkError::Tbd(macho::tbd::TbdError::Schema {
                    msg: format!("TBD input is not UTF-8: {e}"),
                })
            })?;
            let target = Target {
                arch: Arch::Arm64,
                platform: Platform::MacOs,
            };
            let docs = match tbd_exports {
                TbdExportSelection::MetadataOnly => parse_tbd_metadata_for_target(text, &target)?,
                TbdExportSelection::Matching(names) => {
                    parse_tbd_for_target_matching(text, &target, names)?
                }
            };
            timings.tbd_decode = phase_started.elapsed();

            let phase_started = Instant::now();
            if docs.is_empty() {
                return Err(LinkError::NoTbdDocument(path.to_path_buf()));
            }
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
            for doc in &docs {
                let file = DylibFile::from_tbd(path, doc, &target);
                let _ =
                    inputs.add_dylib_from_file_with_meta(path.to_path_buf(), file, load.clone());
            }
            timings.tbd_materialize = phase_started.elapsed();
        }
        _ => {
            let phase_started = Instant::now();
            let _ = inputs.add_object(path.to_path_buf(), bytes, load_order)?;
            timings.object_parse = phase_started.elapsed();
        }
    }
    Ok(timings)
}

#[derive(Clone, Copy)]
enum TbdExportSelection<'a> {
    MetadataOnly,
    Matching(&'a HashSet<String>),
}

struct TbdResolutionReport {
    timings: InputLoadTimings,
    seed_report: SeedReport,
}

fn inputs_may_need_dylib_exports(inputs: &Inputs) -> Result<bool, LinkError> {
    if !inputs.archives.is_empty() {
        return Ok(true);
    }
    for i in 0..inputs.objects.len() {
        let input_id = InputId(i as u32);
        let object = inputs.object_file(input_id)?;
        if object.symbols.iter().any(|sym| {
            sym.stab_kind().is_none()
                && (sym.is_ext() || sym.is_private_ext())
                && sym.kind() == SymKind::Undef
                && !sym.is_common()
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn collect_initial_tbd_export_names(inputs: &Inputs) -> Result<HashSet<String>, LinkError> {
    let mut names = HashSet::new();
    for object in &inputs.objects {
        collect_object_undefined_names(&object.parsed, &mut names);
    }
    for archive_input in &inputs.archives {
        let archive = Archive::open(&archive_input.path, &archive_input.bytes)
            .map_err(|error| LinkError::from(InputAddError::from(error)))?;
        if let Some(index) = archive.symbol_index() {
            for entry in &index.entries {
                names.insert(entry.name.clone());
            }
        }
    }
    Ok(names)
}

fn collect_object_undefined_names(object: &ObjectFile, names: &mut HashSet<String>) {
    for symbol in &object.symbols {
        if symbol.stab_kind().is_some()
            || (!symbol.is_ext() && !symbol.is_private_ext())
            || symbol.kind() != SymKind::Undef
            || symbol.is_common()
        {
            continue;
        }
        if let Ok(name) = object.symbol_name(symbol) {
            names.insert(name.to_string());
        }
    }
}

fn collect_unresolved_symbol_names(sym_table: &SymbolTable) -> HashSet<String> {
    sym_table
        .iter()
        .filter_map(|(_, symbol)| match symbol {
            Symbol::Undefined { name, .. } => Some(sym_table.interner.resolve(*name).to_string()),
            _ => None,
        })
        .collect()
}

fn load_tbd_exports_for_unresolved(
    inputs: &mut Inputs,
    deferred_dylibs: &[(usize, PathBuf)],
    sym_table: &mut SymbolTable,
    already_requested: Option<&HashSet<String>>,
) -> Result<TbdResolutionReport, LinkError> {
    let mut names = collect_unresolved_symbol_names(sym_table);
    if let Some(already_requested) = already_requested {
        names.retain(|name| !already_requested.contains(name));
    }
    if names.is_empty() {
        return Ok(TbdResolutionReport {
            timings: InputLoadTimings::default(),
            seed_report: SeedReport::default(),
        });
    }

    let first_new_dylib = inputs.dylibs.len();
    let mut timings = InputLoadTimings::default();
    for (_, path) in deferred_dylibs {
        if path.extension().and_then(|ext| ext.to_str()) != Some("tbd") {
            continue;
        }
        let Some(load) = dylib_load_meta_for_path(inputs, path) else {
            continue;
        };
        timings += register_tbd_matching_exports(inputs, path, &names, load)?;
    }

    let mut seed_report = SeedReport::default();
    for idx in first_new_dylib..inputs.dylibs.len() {
        seed_dylib(
            inputs,
            resolve::DylibId(idx as u32),
            sym_table,
            &mut seed_report,
        )?;
    }
    Ok(TbdResolutionReport {
        timings,
        seed_report,
    })
}

fn dylib_load_meta_for_path(inputs: &Inputs, path: &std::path::Path) -> Option<DylibLoadMeta> {
    inputs
        .dylibs
        .iter()
        .find(|dylib| dylib.path == path)
        .map(|dylib| DylibLoadMeta {
            install_name: dylib.load_install_name.clone(),
            current_version: dylib.load_current_version,
            compatibility_version: dylib.load_compatibility_version,
            ordinal: dylib.ordinal,
        })
}

fn register_tbd_matching_exports(
    inputs: &mut Inputs,
    path: &std::path::Path,
    names: &HashSet<String>,
    load: DylibLoadMeta,
) -> Result<InputLoadTimings, LinkError> {
    let mut timings = InputLoadTimings::default();
    let phase_started = Instant::now();
    let bytes = fs::read(path)?;
    timings.read = phase_started.elapsed();

    let phase_started = Instant::now();
    let text = std::str::from_utf8(&bytes).map_err(|e| {
        LinkError::Tbd(macho::tbd::TbdError::Schema {
            msg: format!("TBD input is not UTF-8: {e}"),
        })
    })?;
    let target = Target {
        arch: Arch::Arm64,
        platform: Platform::MacOs,
    };
    let docs = parse_tbd_for_target_matching(text, &target, names)?;
    timings.tbd_decode = phase_started.elapsed();

    let phase_started = Instant::now();
    for doc in &docs {
        if doc
            .exports
            .iter()
            .chain(doc.reexports.iter())
            .all(|scoped| scoped.value.is_empty())
        {
            continue;
        }
        let file = DylibFile::from_tbd(path, doc, &target);
        let _ = inputs.add_dylib_from_file_with_meta(path.to_path_buf(), file, load.clone());
    }
    timings.tbd_materialize = phase_started.elapsed();
    Ok(timings)
}

fn resolve_entry_point(
    opts: &LinkOptions,
    sym_table: &SymbolTable,
) -> Result<Option<macho::writer::EntryPoint>, LinkError> {
    let Some(symbol_id) = find_entry_symbol_id(opts, sym_table)? else {
        return Ok(None);
    };
    let Symbol::Defined { atom, value, .. } = sym_table.get(symbol_id) else {
        let name = sym_table.interner.resolve(sym_table.get(symbol_id).name());
        return Err(LinkError::EntrySymbolNotFound(name.to_string()));
    };
    Ok(Some(macho::writer::EntryPoint {
        atom: *atom,
        atom_value: *value,
    }))
}

fn find_entry_symbol_id(
    opts: &LinkOptions,
    sym_table: &SymbolTable,
) -> Result<Option<resolve::SymbolId>, LinkError> {
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
    Ok(Some(symbol_id))
}

fn symbol_defined(sym_table: &SymbolTable, name: &str) -> bool {
    sym_table.iter().any(|(_, symbol)| {
        sym_table.interner.resolve(symbol.name()) == name
            && matches!(symbol, Symbol::Defined { .. })
    })
}
