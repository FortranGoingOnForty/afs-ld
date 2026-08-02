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
pub mod elf;
pub mod icf;
pub mod input;
pub mod layout;
pub mod leb;
pub mod link_map;
pub mod loh;
pub mod macho;
pub mod output;
pub mod reloc;
pub mod resolve;
pub mod section;
pub mod string_table;
pub mod symbol;
pub mod synth;
pub mod why_live;

use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::{collections::VecDeque, fs, io};

use archive::ArchiveMetadata;
use atom::{
    atomize_object, backpatch_symbol_atoms, materialize_common_symbols, AtomTable,
    CommonMaterializationError,
};
use icf::IcfError;
use input::ObjectFile;
use layout::{ExtraLayoutSections, Layout, LayoutInput};
use macho::constants::{
    macho_filetype_name, CPU_SUBTYPE_ARM64_ALL, MH_DYLIB, MH_OBJECT, SECTION_TYPE_MASK, S_ZEROFILL,
};
use macho::dylib::{DylibDependency, DylibFile, DylibLoadKind};
use macho::reader::{parse_header, ReadError};
use macho::tbd::{
    parse_tbd_for_target, parse_tbd_metadata_for_target, parse_version, Arch, Platform, Target,
};
use reloc::arm64::RelocError;
use resolve::{
    classify_unresolved, find_archive_by_path, force_load_archive, format_duplicate_diagnostic,
    format_undefined_diagnostic, format_undefined_warning_diagnostic, resolve_inputs_in_order,
    DrainReport, DylibId, DylibLoadMeta, InputAddError, InputId, Inputs, OrderedInput,
    OrderedInputEntry, Symbol, SymbolTable, UndefinedTreatment,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkSpec {
    pub name: String,
    pub weak: bool,
}

/// One input request in command-line order. Library and framework requests
/// stay unresolved until all search-path options have been parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSpec {
    Path(PathBuf),
    Library(String),
    Framework(FrameworkSpec),
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
    pub fixup_chains: bool,
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
            fixup_chains: false,
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
}

#[derive(Debug)]
pub enum LinkError {
    /// No input files were provided on the command line.
    NoInputs,
    Io(io::Error),
    MachOParse {
        path: PathBuf,
        source: ReadError,
    },
    UnsupportedMachOInput {
        path: PathBuf,
        filetype: u32,
    },
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
    CommonMaterialization(CommonMaterializationError),
    IncompatibleCommonSection(PathBuf),
    DuplicateSymbols(String),
    UndefinedSymbols(String),
    UnsupportedArch(String),
    IncompatibleCpuSubtypes {
        reference_path: PathBuf,
        reference_subtype: u32,
        path: PathBuf,
        subtype: u32,
    },
    NoTbdDocument(PathBuf),
    MissingExecutableEntry,
    EntrySymbolNotFound(String),
    AbsoluteEntrySymbol(String),
    ForceLoadNotArchive(PathBuf),
    LibraryNotFound(String),
    FrameworkNotFound(String),
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

impl LinkError {
    fn macho_parse(path: &std::path::Path, source: ReadError) -> Self {
        Self::MachOParse {
            path: path.to_path_buf(),
            source,
        }
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
            LinkError::MachOParse { path, source } => {
                write!(f, "{}: {source}", path.display())
            }
            LinkError::UnsupportedMachOInput { path, filetype } => write!(
                f,
                "{}: unsupported Mach-O input filetype {} (0x{filetype:08x}); expected MH_OBJECT or MH_DYLIB",
                path.display(),
                macho_filetype_name(*filetype).unwrap_or("unknown")
            ),
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
            LinkError::CommonMaterialization(e) => write!(f, "{e}"),
            LinkError::IncompatibleCommonSection(path) => write!(
                f,
                "{}: __DATA,__common must be an S_ZEROFILL section",
                path.display()
            ),
            LinkError::DuplicateSymbols(msg) | LinkError::UndefinedSymbols(msg) => {
                write!(f, "{msg}")
            }
            LinkError::UnsupportedArch(arch) => {
                write!(f, "unsupported arch `{arch}` (afs-ld requires arm64)")
            }
            LinkError::IncompatibleCpuSubtypes {
                reference_path,
                reference_subtype,
                path,
                subtype,
            } => write!(
                f,
                "incompatible ARM64 CPU subtypes: {} uses 0x{reference_subtype:08x}, but {} uses 0x{subtype:08x}; all object inputs must use one exact subtype and capability set",
                reference_path.display(),
                path.display()
            ),
            LinkError::NoTbdDocument(path) => {
                write!(f, "{}: no arm64-macos TBD document found", path.display())
            }
            LinkError::MissingExecutableEntry => write!(
                f,
                "executable has no entry symbol; define `_main` or `_start`, or use `-e <symbol>`"
            ),
            LinkError::EntrySymbolNotFound(name) => {
                write!(f, "entry symbol `{name}` was not found in linked objects")
            }
            LinkError::AbsoluteEntrySymbol(name) => write!(
                f,
                "entry symbol `{name}` is absolute and cannot be used as an executable entry point"
            ),
            LinkError::ForceLoadNotArchive(path) => {
                write!(
                    f,
                    "{}: -force_load requires a static archive",
                    path.display()
                )
            }
            LinkError::LibraryNotFound(name) => {
                write!(f, "unable to find library `{name}`")
            }
            LinkError::FrameworkNotFound(name) => {
                write!(f, "unable to find framework `{name}`")
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

impl From<CommonMaterializationError> for LinkError {
    fn from(value: CommonMaterializationError) -> Self {
        LinkError::CommonMaterialization(value)
    }
}

fn validate_common_sections(
    symbols: &SymbolTable,
    objects: &[(InputId, &ObjectFile)],
) -> Result<(), LinkError> {
    if !symbols
        .iter()
        .any(|(_, symbol)| matches!(symbol, Symbol::Common { .. }))
    {
        return Ok(());
    }
    for (_, object) in objects {
        if object.sections.iter().any(|section| {
            section.segname == "__DATA"
                && section.sectname == "__common"
                && section.flags & SECTION_TYPE_MASK != S_ZEROFILL
        }) {
            return Err(LinkError::IncompatibleCommonSection(object.path.clone()));
        }
    }
    Ok(())
}

/// The linker itself. Sprint 0 only validates that inputs exist; later sprints
/// grow this into the full pipeline described in `.docs/overview.md`.
pub struct Linker;

impl Linker {
    /// Link a programmatically grouped configuration. This preserves the
    /// historical group order but cannot recover command-line interleaving;
    /// CLI-style callers should use [`Linker::run_ordered`].
    pub fn run(opts: &LinkOptions) -> Result<(), LinkError> {
        Self::run_profiled(opts).map(|_| ())
    }

    pub fn run_profiled(opts: &LinkOptions) -> Result<LinkProfile, LinkError> {
        let input_specs = legacy_input_specs(opts);
        Self::run_profiled_with_inputs(opts, &input_specs, &[], true)
    }

    pub fn run_ordered(opts: &LinkOptions, input_specs: &[InputSpec]) -> Result<(), LinkError> {
        Self::run_profiled_with_inputs(opts, input_specs, &[], true).map(|_| ())
    }

    pub fn run_profiled_ordered(
        opts: &LinkOptions,
        input_specs: &[InputSpec],
    ) -> Result<LinkProfile, LinkError> {
        Self::run_profiled_with_inputs(opts, input_specs, &[], true)
    }

    #[doc(hidden)]
    pub fn run_ordered_with_force_loads(
        opts: &LinkOptions,
        input_specs: &[InputSpec],
        force_load_positions: &[usize],
    ) -> Result<(), LinkError> {
        Self::run_profiled_with_inputs(opts, input_specs, force_load_positions, false).map(|_| ())
    }

    fn run_profiled_with_inputs(
        opts: &LinkOptions,
        input_specs: &[InputSpec],
        force_load_positions: &[usize],
        apply_legacy_force_loads: bool,
    ) -> Result<LinkProfile, LinkError> {
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
        if opts.fixup_chains {
            return Err(LinkError::UnsupportedOption(
                "`-fixup_chains` is not yet supported".into(),
            ));
        }
        if opts.icf_mode == IcfMode::All {
            return Err(LinkError::UnsupportedOption(
                "`-icf=all` is not yet supported; use `-icf=safe` or `-icf=none`".into(),
            ));
        }
        if input_specs.is_empty() {
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

        let (resolved_inputs, mut first_input_error) =
            resolve_input_specs(opts, input_specs, force_load_positions);
        let mut dylib_load_kinds: std::collections::HashMap<DylibId, DylibLoadKind> =
            std::collections::HashMap::new();
        let mut loaded_inputs = vec![false; resolved_inputs.len()];

        let mut inputs = Inputs::new();
        let mut input_order = Vec::new();
        let mut deferred_dylibs = Vec::new();
        let mut initial_loads = Vec::new();
        let phase_started = Instant::now();
        for (load_order, input) in resolved_inputs.iter().enumerate() {
            if !input.force_load
                && matches!(
                    input.path.extension().and_then(|ext| ext.to_str()),
                    Some("dylib" | "tbd")
                )
            {
                deferred_dylibs.push(DeferredDylibInput::Path {
                    load_order,
                    path: input.path.clone(),
                });
                continue;
            }
            initial_loads.push((load_order, input.path.clone(), input.force_load));
        }
        for result in load_initial_inputs(initial_loads, parallel_jobs) {
            match result {
                Ok(LoadedInitialInput::Dylib(input)) => {
                    deferred_dylibs.push(DeferredDylibInput::Loaded(input));
                }
                Ok(loaded) => {
                    let load_order = loaded.load_order();
                    let mut registered = register_loaded_initial_input(&mut inputs, loaded);
                    if resolved_inputs[load_order].force_load {
                        let OrderedInput::Archive(id) = registered.ordered[0].input else {
                            unreachable!("force-loaded input must be registered as an archive");
                        };
                        registered.ordered[0] =
                            OrderedInputEntry::force_load_archive(load_order, id);
                    }
                    phases.add_input_load(registered.timings);
                    input_order.extend(registered.ordered);
                    loaded_inputs[load_order] = true;
                }
                Err(error) => retain_earliest_input_error(&mut first_input_error, error),
            }
        }
        deferred_dylibs.sort_by_key(DeferredDylibInput::load_order);
        let include_tbd_exports = inputs_may_need_dylib_exports(&inputs)?;
        for deferred in deferred_dylibs {
            let load_order = deferred.load_order();
            let result = match deferred {
                DeferredDylibInput::Path { path, .. } => {
                    register_input(&mut inputs, &path, load_order, include_tbd_exports)
                }
                DeferredDylibInput::Loaded(input) => Ok(register_loaded_initial_input(
                    &mut inputs,
                    LoadedInitialInput::Dylib(input),
                )),
            };
            match result {
                Ok(registered) => {
                    for entry in &registered.ordered {
                        if let OrderedInput::Dylib(id) = entry.input {
                            dylib_load_kinds.insert(id, resolved_inputs[load_order].load_kind);
                        }
                    }
                    phases.add_input_load(registered.timings);
                    input_order.extend(registered.ordered);
                    loaded_inputs[load_order] = true;
                }
                Err(error) => retain_earliest_input_error(
                    &mut first_input_error,
                    InitialLoadError { load_order, error },
                ),
            }
        }
        if let Some(error) = first_input_error {
            if opts.trace_inputs {
                for (load_order, input) in resolved_inputs.iter().enumerate() {
                    if load_order >= error.load_order {
                        break;
                    }
                    if loaded_inputs[load_order] {
                        eprintln!("afs-ld: loading {}", input.path.display());
                    }
                }
            }
            return Err(error.error);
        }
        phases.input_parsing = phase_started.elapsed();

        let mut sym_table = SymbolTable::new();
        let phase_started = Instant::now();
        let resolution_report = match resolve_inputs_in_order(
            &mut inputs,
            &input_order,
            &mut sym_table,
            parallel_jobs,
            opts.all_load,
        ) {
            Ok(report) => report,
            Err(error) => {
                if opts.trace_inputs {
                    for path in &error.report.loaded_paths {
                        eprintln!("afs-ld: loading {}", path.display());
                    }
                }
                return Err(LinkError::Fetch(error.error));
            }
        };
        if opts.trace_inputs {
            for path in &resolution_report.loaded_paths {
                eprintln!("afs-ld: loading {}", path.display());
            }
        }
        if !resolution_report.duplicates.is_empty() {
            let mut msg = String::new();
            for err in &resolution_report.duplicates {
                msg.push_str(&format_duplicate_diagnostic(&sym_table, &inputs, err));
            }
            return Err(LinkError::DuplicateSymbols(msg));
        }

        let mut force_report = DrainReport::default();
        if apply_legacy_force_loads {
            for archive_path in &opts.force_load_archives {
                let Some(archive_id) = find_archive_by_path(&inputs, archive_path) else {
                    return Err(LinkError::ForceLoadNotArchive(archive_path.clone()));
                };
                if let Err(error) = force_load_archive(
                    &mut inputs,
                    &mut sym_table,
                    archive_id,
                    &mut force_report,
                    parallel_jobs,
                ) {
                    if opts.trace_inputs {
                        for path in &force_report.loaded_paths {
                            eprintln!("afs-ld: loading {}", path.display());
                        }
                    }
                    return Err(LinkError::Fetch(error));
                }
            }
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

        let output_cpu_subtype = resolve_output_cpu_subtype(&inputs)?;

        let mut referrers = resolution_report.referrers.clone();
        referrers.extend_from(&force_report.referrers);
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
        validate_common_sections(&sym_table, &objects)?;
        materialize_common_symbols(&mut atom_table, &mut sym_table)?;
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
        for (index, dylib) in inputs.dylibs.iter().enumerate() {
            if !seen_ordinals.insert(dylib.ordinal) {
                continue;
            }
            dylib_loads.push(DylibDependency {
                kind: dylib_load_kinds
                    .get(&DylibId(index as u32))
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
        let synthetic_plan = synth::SyntheticPlan::build_filtered_with_relocs(
            &layout_inputs,
            &atom_table,
            &mut sym_table,
            &inputs.dylibs,
            kept_atoms,
            &parsed_relocs,
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
        for _ in 0..4 {
            let phase_started = Instant::now();
            let (next_layout, next_linkedit, linkedit_timings) =
                macho::writer::finalize_layout_with_linkedit(
                    &layout,
                    opts.kind,
                    opts,
                    &dylib_loads,
                    linkedit_context,
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

        let phase_started = Instant::now();
        let mut image = Vec::new();
        let entry_point = resolve_entry_point(opts, &sym_table)?;
        macho::writer::write_finalized_with_linkedit_for_header(
            &layout,
            macho::writer::OutputHeaderSpec::new(opts.kind, output_cpu_subtype),
            opts,
            entry_point,
            &dylib_loads,
            &linkedit,
            &mut image,
        )?;
        let output = default_output_path(opts);
        let permission_mode = if opts.kind == OutputKind::Executable {
            output::PermissionMode::AddExecute
        } else {
            output::PermissionMode::Preserve
        };
        output::write_atomic(&output, &image, permission_mode).map_err(|error| {
            io::Error::new(error.kind(), format!("{}: {error}", output.display()))
        })?;
        if let Some(map_path) = &opts.map {
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
        }
        phases.write_output = phase_started.elapsed();
        Ok(LinkProfile {
            output,
            phases,
            total_wall: overall_started.elapsed(),
        })
    }
}

fn resolve_output_cpu_subtype(inputs: &Inputs) -> Result<u32, LinkError> {
    let mut objects: Vec<_> = inputs.objects.iter().collect();
    objects.sort_by(|left, right| {
        left.load_order
            .cmp(&right.load_order)
            .then_with(|| left.archive_member_offset.cmp(&right.archive_member_offset))
            .then_with(|| left.path.cmp(&right.path))
    });

    let Some(reference) = objects.first() else {
        return Ok(CPU_SUBTYPE_ARM64_ALL);
    };
    let reference_subtype = reference.parsed.header.cpusubtype;
    for object in objects.iter().skip(1) {
        let subtype = object.parsed.header.cpusubtype;
        if subtype != reference_subtype {
            return Err(LinkError::IncompatibleCpuSubtypes {
                reference_path: reference.path.clone(),
                reference_subtype,
                path: object.path.clone(),
                subtype,
            });
        }
    }
    Ok(reference_subtype)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedInput {
    path: PathBuf,
    load_kind: DylibLoadKind,
    force_load: bool,
}

fn legacy_input_specs(opts: &LinkOptions) -> Vec<InputSpec> {
    let mut input_specs =
        Vec::with_capacity(opts.inputs.len() + opts.library_names.len() + opts.frameworks.len());
    let mut positional_dylibs = Vec::new();
    for path in &opts.inputs {
        if matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("dylib" | "tbd")
        ) {
            positional_dylibs.push(path.clone());
        } else {
            input_specs.push(InputSpec::Path(path.clone()));
        }
    }
    input_specs.extend(opts.library_names.iter().cloned().map(InputSpec::Library));
    input_specs.extend(opts.frameworks.iter().cloned().map(InputSpec::Framework));
    input_specs.extend(positional_dylibs.into_iter().map(InputSpec::Path));
    input_specs
}

fn resolve_input_specs(
    opts: &LinkOptions,
    input_specs: &[InputSpec],
    force_load_positions: &[usize],
) -> (Vec<ResolvedInput>, Option<InitialLoadError>) {
    let mut resolved = Vec::with_capacity(input_specs.len());
    for (position, spec) in input_specs.iter().enumerate() {
        let result = match spec {
            InputSpec::Path(path) => Ok((path.clone(), DylibLoadKind::Normal)),
            InputSpec::Library(name) => {
                resolve_library_input(opts, name).map(|path| (path, DylibLoadKind::Normal))
            }
            InputSpec::Framework(framework) => {
                resolve_framework_input(opts, &framework.name).map(|path| {
                    (
                        path,
                        if framework.weak {
                            DylibLoadKind::Weak
                        } else {
                            DylibLoadKind::Normal
                        },
                    )
                })
            }
        };
        let (path, load_kind) = match result {
            Ok(resolved_input) => resolved_input,
            Err(error) => {
                let load_order = resolved.len();
                return (resolved, Some(InitialLoadError { load_order, error }));
            }
        };
        resolved.push(ResolvedInput {
            path,
            load_kind,
            force_load: force_load_positions.contains(&position),
        });
    }
    (resolved, None)
}

fn retain_earliest_input_error(
    current: &mut Option<InitialLoadError>,
    candidate: InitialLoadError,
) {
    if current
        .as_ref()
        .is_none_or(|error| candidate.load_order < error.load_order)
    {
        *current = Some(candidate);
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
    metadata: ArchiveMetadata,
    timings: InputLoadTimings,
}

struct LoadedDylibInput {
    path: PathBuf,
    load_order: usize,
    parsed: DylibFile,
    timings: InputLoadTimings,
}

enum LoadedInitialInput {
    Object(Box<LoadedObjectInput>),
    Archive(Box<LoadedArchiveInput>),
    Dylib(Box<LoadedDylibInput>),
}

impl LoadedInitialInput {
    fn load_order(&self) -> usize {
        match self {
            LoadedInitialInput::Object(input) => input.load_order,
            LoadedInitialInput::Archive(input) => input.load_order,
            LoadedInitialInput::Dylib(input) => input.load_order,
        }
    }
}

enum DeferredDylibInput {
    Path { load_order: usize, path: PathBuf },
    Loaded(Box<LoadedDylibInput>),
}

impl DeferredDylibInput {
    fn load_order(&self) -> usize {
        match self {
            DeferredDylibInput::Path { load_order, .. } => *load_order,
            DeferredDylibInput::Loaded(input) => input.load_order,
        }
    }
}

struct InitialLoadError {
    load_order: usize,
    error: LinkError,
}

struct RegisteredInput {
    timings: InputLoadTimings,
    ordered: Vec<OrderedInputEntry>,
}

impl RegisteredInput {
    fn one(timings: InputLoadTimings, ordered: OrderedInputEntry) -> Self {
        Self {
            timings,
            ordered: vec![ordered],
        }
    }
}

fn load_initial_inputs(
    loads: Vec<(usize, PathBuf, bool)>,
    parallel_jobs: usize,
) -> Vec<Result<LoadedInitialInput, InitialLoadError>> {
    let mut results = Vec::new();
    let mut macho_jobs = Vec::new();
    for (load_order, path, force_archive) in loads {
        if force_archive || matches!(path.extension().and_then(|ext| ext.to_str()), Some("a")) {
            results.push(load_archive_input(path, load_order, force_archive));
        } else {
            macho_jobs.push((load_order, path));
        }
    }
    results.extend(load_macho_inputs_parallel(macho_jobs, parallel_jobs));
    results.sort_by_key(|result| match result {
        Ok(input) => input.load_order(),
        Err(error) => error.load_order,
    });

    results
}

fn load_macho_inputs_parallel(
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
            .map(|(load_order, path)| load_macho_input(path, load_order))
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
                tx.send(load_macho_input(path, load_order))
                    .expect("input load receiver should stay live");
            });
        }
        drop(tx);
        rx.into_iter().collect()
    })
}

fn load_macho_input(
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
    let filetype = parse_header(&bytes).map_err(|error| InitialLoadError {
        load_order,
        error: LinkError::macho_parse(&path, error),
    })?;
    match filetype.filetype {
        MH_DYLIB => {
            let parsed = DylibFile::parse(&path, &bytes).map_err(|error| InitialLoadError {
                load_order,
                error: LinkError::macho_parse(&path, error),
            })?;
            timings.dylib_parse = phase_started.elapsed();
            Ok(LoadedInitialInput::Dylib(Box::new(LoadedDylibInput {
                path,
                load_order,
                parsed,
                timings,
            })))
        }
        MH_OBJECT => {
            let parsed = ObjectFile::parse(&path, &bytes).map_err(|error| InitialLoadError {
                load_order,
                error: LinkError::macho_parse(&path, error),
            })?;
            timings.object_parse = phase_started.elapsed();
            Ok(LoadedInitialInput::Object(Box::new(LoadedObjectInput {
                path,
                load_order,
                bytes,
                parsed,
                timings,
            })))
        }
        filetype => Err(InitialLoadError {
            load_order,
            error: LinkError::UnsupportedMachOInput { path, filetype },
        }),
    }
}

fn load_archive_input(
    path: PathBuf,
    load_order: usize,
    force_archive: bool,
) -> Result<LoadedInitialInput, InitialLoadError> {
    let mut timings = InputLoadTimings::default();
    let phase_started = Instant::now();
    let bytes = fs::read(&path).map_err(|error| InitialLoadError {
        load_order,
        error: LinkError::Io(error),
    })?;
    timings.read = phase_started.elapsed();

    let phase_started = Instant::now();
    let metadata = ArchiveMetadata::parse(&path, &bytes).map_err(|error| InitialLoadError {
        load_order,
        error: if force_archive {
            LinkError::ForceLoadNotArchive(path.clone())
        } else {
            LinkError::from(InputAddError::from(error))
        },
    })?;
    timings.archive_parse = phase_started.elapsed();

    Ok(LoadedInitialInput::Archive(Box::new(LoadedArchiveInput {
        path,
        load_order,
        bytes,
        metadata,
        timings,
    })))
}

fn register_loaded_initial_input(
    inputs: &mut Inputs,
    loaded: LoadedInitialInput,
) -> RegisteredInput {
    match loaded {
        LoadedInitialInput::Object(input) => {
            let id =
                inputs.add_parsed_object(input.path, input.bytes, input.parsed, input.load_order);
            RegisteredInput::one(
                input.timings,
                OrderedInputEntry::object(input.load_order, id),
            )
        }
        LoadedInitialInput::Archive(input) => {
            let id = inputs.add_parsed_archive(
                input.path,
                input.bytes,
                input.metadata,
                input.load_order,
            );
            RegisteredInput::one(
                input.timings,
                OrderedInputEntry::archive(input.load_order, id),
            )
        }
        LoadedInitialInput::Dylib(input) => {
            let id = inputs.add_dylib_from_file(input.path, input.parsed);
            RegisteredInput::one(
                input.timings,
                OrderedInputEntry::dylib(input.load_order, id),
            )
        }
    }
}

fn register_input(
    inputs: &mut Inputs,
    path: &std::path::Path,
    load_order: usize,
    include_tbd_exports: bool,
) -> Result<RegisteredInput, LinkError> {
    let mut timings = InputLoadTimings::default();
    let mut ordered = Vec::new();
    let phase_started = Instant::now();
    let bytes = fs::read(path)?;
    timings.read = phase_started.elapsed();
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("a") => {
            let phase_started = Instant::now();
            let id = inputs.add_archive(path.to_path_buf(), bytes, load_order)?;
            ordered.push(OrderedInputEntry::archive(load_order, id));
            timings.archive_parse = phase_started.elapsed();
        }
        Some("dylib") => {
            let phase_started = Instant::now();
            let id = inputs.add_dylib(path.to_path_buf(), bytes)?;
            ordered.push(OrderedInputEntry::dylib(load_order, id));
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
            let docs = if include_tbd_exports {
                parse_tbd_for_target(text, &target)?
            } else {
                parse_tbd_metadata_for_target(text, &target)?
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
                let id =
                    inputs.add_dylib_from_file_with_meta(path.to_path_buf(), file, load.clone());
                ordered.push(OrderedInputEntry::dylib(load_order, id));
            }
            timings.tbd_materialize = phase_started.elapsed();
        }
        _ => {
            let phase_started = Instant::now();
            let id = inputs.add_object(path.to_path_buf(), bytes, load_order)?;
            ordered.push(OrderedInputEntry::object(load_order, id));
            timings.object_parse = phase_started.elapsed();
        }
    }
    Ok(RegisteredInput { timings, ordered })
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

fn resolve_entry_point(
    opts: &LinkOptions,
    sym_table: &SymbolTable,
) -> Result<Option<macho::writer::EntryPoint>, LinkError> {
    let Some(symbol_id) = find_entry_symbol_id(opts, sym_table)? else {
        return Ok(None);
    };
    let symbol = sym_table.get(symbol_id);
    let Symbol::Defined { atom, value, .. } = symbol else {
        let name = opts
            .entry
            .as_deref()
            .unwrap_or_else(|| sym_table.interner.resolve(symbol.name()));
        return match symbol {
            Symbol::Absolute { .. } => Err(LinkError::AbsoluteEntrySymbol(name.to_string())),
            _ => Err(LinkError::EntrySymbolNotFound(name.to_string())),
        };
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
            return Err(LinkError::MissingExecutableEntry);
        }
    } else {
        return Ok(None);
    };
    let Some(symbol_id) = sym_table.lookup_resolved_str(name) else {
        return Err(LinkError::EntrySymbolNotFound(name.to_string()));
    };
    Ok(Some(symbol_id))
}

fn symbol_defined(sym_table: &SymbolTable, name: &str) -> bool {
    sym_table
        .lookup_resolved_str(name)
        .map(|symbol_id| {
            matches!(
                sym_table.get(symbol_id),
                Symbol::Defined { .. } | Symbol::Absolute { .. }
            )
        })
        .unwrap_or(false)
}
