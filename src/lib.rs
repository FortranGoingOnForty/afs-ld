//! afs-ld — standalone ARM64 Mach-O linker.
//!
//! Sprints 0-9 built the reader, archive loader, dylib/TBD readers,
//! symbol table, fixed-point resolution substrate, and atomization model.
//! Linking still stops before layout / relocation application / writing,
//! but the driver now executes real input loading and name resolution.

pub mod archive;
pub mod args;
pub mod atom;
pub mod diag;
pub mod dump;
pub mod input;
pub mod leb;
pub mod macho;
pub mod reloc;
pub mod resolve;
pub mod section;
pub mod string_table;
pub mod symbol;

use std::path::{Path, PathBuf};

use macho::dylib::DylibFile;
use macho::tbd::{parse_tbd, Arch, Platform, Target};
use resolve::{
    format_duplicate_diagnostic, format_undefined_diagnostic, InputId, Inputs, SymbolTable,
};

/// What kind of Mach-O file the linker is producing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    Executable,
    Dylib,
}

/// User-facing linker configuration, populated by the CLI parser.
#[derive(Debug, Clone)]
pub struct LinkOptions {
    pub inputs: Vec<PathBuf>,
    pub output: Option<PathBuf>,
    pub entry: Option<String>,
    pub arch: Option<String>,
    pub kind: OutputKind,
    pub all_load: bool,
    pub force_load: Vec<PathBuf>,
    pub undefined_treatment: resolve::UndefinedTreatment,
    pub syslibroots: Vec<PathBuf>,
    pub library_search_paths: Vec<PathBuf>,
    pub framework_search_paths: Vec<PathBuf>,
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
            output: None,
            entry: None,
            arch: None,
            kind: OutputKind::Executable,
            all_load: false,
            force_load: Vec::new(),
            undefined_treatment: resolve::UndefinedTreatment::Error,
            syslibroots: Vec::new(),
            library_search_paths: Vec::new(),
            framework_search_paths: Vec::new(),
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
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Input {
        path: PathBuf,
        reason: String,
    },
    Resolution(resolve::ResolutionError),
    Atomize(String),
    Write(macho::writer::WriteError),
    Diagnostics(String),
    /// Path to this sprint's incomplete functionality.
    NotYetImplemented(&'static str),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::NoInputs => write!(f, "no input files"),
            LinkError::Io { path, source } => write!(f, "{}: {}", path.display(), source),
            LinkError::Input { path, reason } => write!(f, "{}: {}", path.display(), reason),
            LinkError::Resolution(e) => write!(f, "{e}"),
            LinkError::Atomize(text) => write!(f, "{text}"),
            LinkError::Write(e) => write!(f, "{e}"),
            LinkError::Diagnostics(text) => write!(f, "{text}"),
            LinkError::NotYetImplemented(what) => write!(f, "not yet implemented: {what}"),
        }
    }
}

/// The linker itself. Sprint 0 only validates that inputs exist; later sprints
/// grow this into the full pipeline described in `.docs/overview.md`.
pub struct Linker;

impl Linker {
    pub fn run(opts: &LinkOptions) -> Result<(), LinkError> {
        if opts.inputs.is_empty() {
            return Err(LinkError::NoInputs);
        }

        let mut inputs = Inputs::new();
        for path in &opts.inputs {
            load_input(&mut inputs, path, opts)?;
        }

        let mut table = SymbolTable::new();
        let report =
            resolve::resolve(&mut inputs, &mut table, opts).map_err(LinkError::Resolution)?;

        if !report.duplicates.is_empty() {
            let mut text = String::new();
            for duplicate in &report.duplicates {
                text.push_str(&format_duplicate_diagnostic(&table, &inputs, duplicate));
            }
            return Err(LinkError::Diagnostics(text.trim_end().to_string()));
        }

        if !report.classification.errors.is_empty() {
            let text = format_undefined_diagnostic(
                &table,
                &inputs,
                &report.referrers,
                &report.classification.errors,
            );
            return Err(LinkError::Diagnostics(text.trim_end().to_string()));
        }

        let mut atoms = atom::AtomTable::new();
        for i in 0..inputs.objects.len() {
            let input_id = InputId(i as u32);
            let obj = inputs
                .object_file(input_id)
                .map_err(|e| LinkError::Input {
                    path: inputs.object(input_id).path.clone(),
                    reason: e.to_string(),
                })?;
            let atomization = atom::atomize_object(input_id, &obj, &mut atoms, &table)
                .map_err(|e| LinkError::Atomize(e.to_string()))?;
            atom::backpatch_symbol_atoms(&atomization, input_id, &obj, &mut table, &mut atoms);
        }

        let layout = section::build_layout(opts.kind, &atoms, &table);
        let mut bytes = Vec::new();
        macho::writer::write_with_atoms(&layout, &atoms, opts.kind, opts, &mut bytes)
            .map_err(LinkError::Write)?;

        let out_path = output_path(opts);
        std::fs::write(&out_path, &bytes).map_err(|source| LinkError::Io {
            path: out_path,
            source,
        })?;
        Ok(())
    }
}

fn output_path(opts: &LinkOptions) -> PathBuf {
    opts.output
        .clone()
        .unwrap_or_else(|| PathBuf::from("a.out"))
}

fn load_input(inputs: &mut Inputs, path: &PathBuf, opts: &LinkOptions) -> Result<(), LinkError> {
    let bytes = std::fs::read(path).map_err(|source| LinkError::Io {
        path: path.clone(),
        source,
    })?;

    match path.extension().and_then(|ext| ext.to_str()) {
        Some("a") => inputs
            .add_archive(path.clone(), bytes)
            .map(|_| ())
            .map_err(|e| LinkError::Input {
                path: path.clone(),
                reason: e.to_string(),
            }),
        Some("dylib") => inputs
            .add_dylib(path.clone(), bytes)
            .map(|_| ())
            .map_err(|e| LinkError::Input {
                path: path.clone(),
                reason: e.to_string(),
            }),
        Some("tbd") => load_tbd(inputs, path, &bytes, opts),
        _ => inputs
            .add_object(path.clone(), bytes)
            .map(|_| ())
            .map_err(|e| LinkError::Input {
                path: path.clone(),
                reason: e.to_string(),
            }),
    }
}

fn load_tbd(
    inputs: &mut Inputs,
    path: &Path,
    bytes: &[u8],
    opts: &LinkOptions,
) -> Result<(), LinkError> {
    let text = std::str::from_utf8(bytes).map_err(|e| LinkError::Input {
        path: path.to_path_buf(),
        reason: format!("TBD is not valid UTF-8: {e}"),
    })?;
    let docs = parse_tbd(text).map_err(|e| LinkError::Input {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    let target = tbd_target(opts);
    let doc = docs
        .iter()
        .find(|doc| doc.targets.iter().any(|candidate| candidate == &target))
        .or_else(|| docs.first())
        .ok_or_else(|| LinkError::Input {
            path: path.to_path_buf(),
            reason: "TBD contained no documents".into(),
        })?;
    let dylib =
        DylibFile::from_tbd(path.to_path_buf(), doc, &target).map_err(|e| LinkError::Input {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
    inputs.add_dylib_from_file(path.to_path_buf(), dylib);
    Ok(())
}

fn tbd_target(opts: &LinkOptions) -> Target {
    let arch = match opts.arch.as_deref() {
        Some("arm64e") => Arch::Arm64e,
        _ => Arch::Arm64,
    };
    Target {
        arch,
        platform: Platform::MacOs,
    }
}
