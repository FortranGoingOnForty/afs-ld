//! Hand-rolled CLI parser. No clap.
//!
//! Sprint 0 recognizes a minimal set (`-o`, `-e`, `-arch`, positional inputs)
//! and errors on anything else with a precise diagnostic. Sprint 19 grows this
//! into the full `ld`-compatible surface described in `.docs/sprints/sprint19.md`.

use std::path::PathBuf;

use crate::{resolve::UndefinedTreatment, LinkOptions, OutputKind};

#[derive(Debug)]
pub enum ArgsError {
    /// A flag that takes an argument was supplied without one.
    MissingValue(String),
    /// A flag took a value outside the currently supported set.
    InvalidValue { flag: String, value: String },
    /// An unrecognized flag.
    UnknownFlag(String),
}

impl std::fmt::Display for ArgsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgsError::MissingValue(flag) => {
                write!(f, "flag `{flag}` requires a value")
            }
            ArgsError::InvalidValue { flag, value } => {
                write!(f, "flag `{flag}` does not accept value `{value}`")
            }
            ArgsError::UnknownFlag(flag) => {
                write!(
                    f,
                    "unknown flag `{flag}` (Sprint 19 adds the full `ld` surface)"
                )
            }
        }
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
            "-dylib" => {
                opts.kind = OutputKind::Dylib;
            }
            "-all_load" => {
                opts.all_load = true;
            }
            "-force_load" => {
                opts.force_load
                    .push(PathBuf::from(it.next().ok_or_else(|| {
                        ArgsError::MissingValue("-force_load".into())
                    })?));
            }
            "-undefined" => {
                let value = it
                    .next()
                    .ok_or_else(|| ArgsError::MissingValue("-undefined".into()))?;
                opts.undefined_treatment =
                    parse_undefined_treatment(value).ok_or_else(|| ArgsError::InvalidValue {
                        flag: "-undefined".into(),
                        value: value.clone(),
                    })?;
            }
            "-rpath" => {
                opts.rpaths.push(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-rpath".into()))?
                        .clone(),
                );
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
                return Err(ArgsError::UnknownFlag(s.to_string()));
            }
            _ => {
                opts.inputs.push(PathBuf::from(arg));
            }
        }
    }
    Ok(opts)
}

fn parse_undefined_treatment(value: &str) -> Option<UndefinedTreatment> {
    match value {
        "error" => Some(UndefinedTreatment::Error),
        "warning" => Some(UndefinedTreatment::Warning),
        "suppress" => Some(UndefinedTreatment::Suppress),
        "dynamic_lookup" => Some(UndefinedTreatment::DynamicLookup),
        _ => None,
    }
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
    fn missing_output_value_errors() {
        let err = parse(&argv(&["-o"])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue(ref f) if f == "-o"));
    }

    #[test]
    fn unknown_flag_errors() {
        let err = parse(&argv(&["-nonsense"])).unwrap_err();
        assert!(matches!(err, ArgsError::UnknownFlag(ref f) if f == "-nonsense"));
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

    #[test]
    fn all_load_and_force_load_parse() {
        let opts = parse(&argv(&["-all_load", "-force_load", "libfoo.a", "main.o"])).unwrap();
        assert!(opts.all_load);
        assert_eq!(opts.force_load, vec![PathBuf::from("libfoo.a")]);
        assert_eq!(opts.inputs, vec![PathBuf::from("main.o")]);
    }

    #[test]
    fn undefined_treatment_parses() {
        let opts = parse(&argv(&["-undefined", "dynamic_lookup", "main.o"])).unwrap();
        assert_eq!(opts.undefined_treatment, UndefinedTreatment::DynamicLookup);
    }

    #[test]
    fn undefined_treatment_rejects_unknown_value() {
        let err = parse(&argv(&["-undefined", "maybe"])).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::InvalidValue { ref flag, ref value }
                if flag == "-undefined" && value == "maybe"
        ));
    }

    #[test]
    fn rpath_parses() {
        let opts = parse(&argv(&["-rpath", "@executable_path/../lib", "main.o"])).unwrap();
        assert_eq!(opts.rpaths, vec!["@executable_path/../lib".to_string()]);
        assert_eq!(opts.inputs, vec![PathBuf::from("main.o")]);
    }
}
