//! Hand-rolled CLI parser. No clap.
//!
//! Sprint 0 recognizes a minimal set (`-o`, `-e`, `-arch`, positional inputs)
//! and errors on anything else with a precise diagnostic. Sprint 19 grows this
//! into the full `ld`-compatible surface described in `.docs/sprints/sprint19.md`.

use std::path::PathBuf;

use crate::{LinkOptions, OutputKind};
use crate::resolve::levenshtein;

const KNOWN_FLAGS: &[&str] = &[
    "-o",
    "-e",
    "-arch",
    "-x",
    "-dylib",
    "-all_load",
    "-force_load",
    "--dump",
    "--dump-archive",
    "--dump-dylib",
    "--dump-tbd",
];

#[derive(Debug)]
pub enum ArgsError {
    /// A flag that takes an argument was supplied without one.
    MissingValue(String),
    /// A recognized flag got a value we do not accept.
    InvalidValue {
        flag: String,
        value: String,
        expected: String,
    },
    /// An unrecognized flag.
    UnknownFlag { flag: String, suggestion: Option<String> },
}

impl std::fmt::Display for ArgsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgsError::MissingValue(flag) => {
                write!(f, "flag `{flag}` requires a value")
            }
            ArgsError::InvalidValue {
                flag,
                value,
                expected,
            } => {
                write!(
                    f,
                    "flag `{flag}` got invalid value `{value}` (expected {expected})"
                )
            }
            ArgsError::UnknownFlag { flag, suggestion } => {
                write!(f, "unknown flag `{flag}`")?;
                if let Some(suggestion) = suggestion {
                    write!(f, " (did you mean `{suggestion}`?)")?;
                }
                write!(f, " (Sprint 19 adds the full `ld` surface)")
            }
        }
    }
}

fn unknown_flag(flag: &str) -> ArgsError {
    let suggestion = KNOWN_FLAGS
        .iter()
        .map(|candidate| (levenshtein(flag, candidate), *candidate))
        .filter(|(distance, _)| *distance <= 3)
        .min_by_key(|(distance, candidate)| (*distance, candidate.len()))
        .map(|(_, candidate)| candidate.to_string());
    ArgsError::UnknownFlag {
        flag: flag.to_string(),
        suggestion,
    }
}

pub fn parse(argv: &[String]) -> Result<LinkOptions, ArgsError> {
    let mut opts = LinkOptions::default();
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-o" => {
                opts.output = Some(PathBuf::from(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-o".into()))?,
                ));
            }
            "-e" => {
                opts.entry = Some(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-e".into()))?
                        .clone(),
                );
            }
            "-arch" => {
                opts.arch = Some(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-arch".into()))?
                        .clone(),
                );
            }
            "-x" => {
                opts.strip_locals = true;
            }
            "-dylib" => {
                opts.kind = OutputKind::Dylib;
            }
            "-all_load" => {
                opts.all_load = true;
            }
            "-force_load" => {
                opts.force_load_archives.push(PathBuf::from(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-force_load".into()))?,
                ));
            }
            "--dump" => {
                opts.dump = Some(PathBuf::from(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("--dump".into()))?,
                ));
            }
            "--dump-archive" => {
                opts.dump_archive =
                    Some(PathBuf::from(it.next().ok_or_else(|| {
                        ArgsError::MissingValue("--dump-archive".into())
                    })?));
            }
            "--dump-dylib" => {
                opts.dump_dylib =
                    Some(PathBuf::from(it.next().ok_or_else(|| {
                        ArgsError::MissingValue("--dump-dylib".into())
                    })?));
            }
            "--dump-tbd" => {
                opts.dump_tbd =
                    Some(PathBuf::from(it.next().ok_or_else(|| {
                        ArgsError::MissingValue("--dump-tbd".into())
                    })?));
            }
            s if s.starts_with('-') => {
                return Err(unknown_flag(s));
            }
            _ => {
                opts.inputs.push(PathBuf::from(arg));
            }
        }
    }
    Ok(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_output_and_entry() {
        let opts = parse(&argv(&["-o", "out", "-e", "_start", "a.o", "b.o"])).unwrap();
        assert_eq!(opts.output.as_deref(), Some(std::path::Path::new("out")));
        assert_eq!(opts.entry.as_deref(), Some("_start"));
        assert_eq!(opts.inputs.len(), 2);
    }

    #[test]
    fn dylib_flag_switches_output_kind() {
        let opts = parse(&argv(&["-dylib", "foo.o"])).unwrap();
        assert_eq!(opts.kind, OutputKind::Dylib);
    }

    #[test]
    fn strip_locals_flag_is_recorded() {
        let opts = parse(&argv(&["-x", "foo.o"])).unwrap();
        assert!(opts.strip_locals);
    }

    #[test]
    fn all_load_flag_is_recorded() {
        let opts = parse(&argv(&["-all_load", "libfoo.a"])).unwrap();
        assert!(opts.all_load);
        assert_eq!(opts.inputs, vec![PathBuf::from("libfoo.a")]);
    }

    #[test]
    fn force_load_flag_accumulates_archive_paths() {
        let opts = parse(&argv(&[
            "-force_load",
            "liba.a",
            "-force_load",
            "libb.a",
            "main.o",
        ]))
        .unwrap();
        assert_eq!(
            opts.force_load_archives,
            vec![PathBuf::from("liba.a"), PathBuf::from("libb.a")]
        );
        assert_eq!(opts.inputs, vec![PathBuf::from("main.o")]);
    }

    #[test]
    fn missing_force_load_value_errors() {
        let err = parse(&argv(&["-force_load"])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue(ref f) if f == "-force_load"));
    }

    #[test]
    fn missing_output_value_errors() {
        let err = parse(&argv(&["-o"])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue(ref f) if f == "-o"));
    }

    #[test]
    fn unknown_flag_errors() {
        let err = parse(&argv(&["-nonsense"])).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::UnknownFlag {
                ref flag,
                suggestion: None
            } if flag == "-nonsense"
        ));
    }

    #[test]
    fn unknown_flag_suggests_nearby_match() {
        let err = parse(&argv(&["-all_lod"])).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::UnknownFlag {
                ref flag,
                suggestion: Some(ref suggestion)
            } if flag == "-all_lod" && suggestion == "-all_load"
        ));
    }

    #[test]
    fn empty_argv_is_ok_with_no_inputs() {
        let opts = parse(&[]).unwrap();
        assert!(opts.inputs.is_empty());
    }

    #[test]
    fn dump_flag_captures_path() {
        let opts = parse(&argv(&["--dump", "some.o"])).unwrap();
        assert_eq!(opts.dump.as_deref(), Some(std::path::Path::new("some.o")));
    }

    #[test]
    fn dump_flag_without_value_errors() {
        let err = parse(&argv(&["--dump"])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue(ref f) if f == "--dump"));
    }

    #[test]
    fn dump_archive_flag_captures_path() {
        let opts = parse(&argv(&["--dump-archive", "libfoo.a"])).unwrap();
        assert_eq!(
            opts.dump_archive.as_deref(),
            Some(std::path::Path::new("libfoo.a"))
        );
    }
}
