//! afs-ld — standalone ARM64 Mach-O linker.
//!
//! Sprint 0 scaffolding: public surface is declared but every link attempt
//! returns `LinkError::NotYetImplemented`. Subsequent sprints fill in the
//! reader, resolver, layout, reloc, synth, writer, and signing paths.

pub mod archive;
pub mod args;
pub mod diag;
pub mod dump;
pub mod input;
pub mod leb;
pub mod macho;
pub mod reloc;
pub mod section;
pub mod string_table;
pub mod symbol;

use std::path::PathBuf;

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
    /// When set, afs-ld operates in dump mode and prints the given file's
    /// header + load commands instead of linking.
    pub dump: Option<PathBuf>,
    /// When set, afs-ld dumps the named static archive's structure.
    pub dump_archive: Option<PathBuf>,
    /// When set, afs-ld dumps the named MH_DYLIB's load commands + exports.
    pub dump_dylib: Option<PathBuf>,
}

impl Default for LinkOptions {
    fn default() -> Self {
        Self {
            inputs: Vec::new(),
            output: None,
            entry: None,
            arch: None,
            kind: OutputKind::Executable,
            dump: None,
            dump_archive: None,
            dump_dylib: None,
        }
    }
}

#[derive(Debug)]
pub enum LinkError {
    /// No input files were provided on the command line.
    NoInputs,
    /// Path to this sprint's incomplete functionality.
    NotYetImplemented(&'static str),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::NoInputs => write!(f, "no input files"),
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
        Err(LinkError::NotYetImplemented(
            "input parsing (Sprint 1) lands next",
        ))
    }
}
