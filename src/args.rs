//! Hand-rolled CLI parser. No clap.
//!
//! Sprint 0 recognizes a minimal set (`-o`, `-e`, `-arch`, positional inputs)
//! and errors on anything else with a precise diagnostic. Sprint 19 grows this
//! into the full `ld`-compatible surface described in `.docs/sprints/sprint19.md`.

use std::path::PathBuf;

use crate::resolve::{levenshtein, UndefinedTreatment};
use crate::{FrameworkSpec, IcfMode, LinkOptions, OutputKind, PlatformVersion, ThunkMode};

const KNOWN_FLAGS: &[&str] = &[
    "-o",
    "-e",
    "-arch",
    "-l",
    "-L",
    "-framework",
    "-weak_framework",
    "-ObjC",
    "-syslibroot",
    "-platform_version",
    "-r",
    "-bundle",
    "-undefined",
    "-rpath",
    "-install_name",
    "-current_version",
    "-compatibility_version",
    "-exported_symbols_list",
    "-unexported_symbols_list",
    "-exported_symbol",
    "-unexported_symbol",
    "-S",
    "-no_uuid",
    "-no_loh",
    "-thunks=none",
    "-thunks=safe",
    "-thunks=all",
    "-dead_strip",
    "-icf=safe",
    "-icf=none",
    "-icf=all",
    "-fixup_chains",
    "-no_fixup_chains",
    "-map",
    "-why_live",
    "-t",
    "-trace",
    "-v",
    "--version",
    "-h",
    "--help",
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
    UnknownFlag {
        flag: String,
        suggestion: Option<String>,
    },
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

fn parse_version_component(flag: &str, value: &str) -> Result<u32, ArgsError> {
    let mut parts = value.split('.');
    let parse_part = |piece: Option<&str>| -> Result<u32, ArgsError> {
        let raw = piece.unwrap_or("0");
        raw.parse::<u32>().map_err(|_| ArgsError::InvalidValue {
            flag: flag.to_string(),
            value: value.to_string(),
            expected: "version like <major>[.<minor>[.<patch>]]".into(),
        })
    };
    let major = parse_part(parts.next())?;
    let minor = parse_part(parts.next())?;
    let patch = parse_part(parts.next())?;
    if parts.next().is_some() {
        return Err(ArgsError::InvalidValue {
            flag: flag.to_string(),
            value: value.to_string(),
            expected: "version like <major>[.<minor>[.<patch>]]".into(),
        });
    }
    Ok((major << 16) | ((minor & 0xff) << 8) | (patch & 0xff))
}

pub fn parse(argv: &[String]) -> Result<LinkOptions, ArgsError> {
    let normalized = normalize_wl(argv);
    let mut opts = LinkOptions::default();
    let mut it = normalized.iter();
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
            "-l" => {
                opts.library_names.push(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-l".into()))?
                        .clone(),
                );
            }
            s if s.starts_with("-l") && s.len() > 2 => {
                opts.library_names.push(s[2..].to_string());
            }
            "-L" => {
                opts.search_paths.push(PathBuf::from(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-L".into()))?,
                ));
            }
            "-framework" => {
                opts.frameworks.push(FrameworkSpec {
                    name: it
                        .next()
                        .ok_or_else(|| ArgsError::MissingValue("-framework".into()))?
                        .clone(),
                    weak: false,
                });
            }
            "-weak_framework" => {
                opts.frameworks.push(FrameworkSpec {
                    name: it
                        .next()
                        .ok_or_else(|| ArgsError::MissingValue("-weak_framework".into()))?
                        .clone(),
                    weak: true,
                });
            }
            "-ObjC" => {
                opts.objc_force_load = true;
            }
            "-syslibroot" => {
                opts.syslibroot =
                    Some(PathBuf::from(it.next().ok_or_else(|| {
                        ArgsError::MissingValue("-syslibroot".into())
                    })?));
            }
            "-platform_version" => {
                let platform = it
                    .next()
                    .ok_or_else(|| ArgsError::MissingValue("-platform_version".into()))?;
                if platform != "macos" {
                    return Err(ArgsError::InvalidValue {
                        flag: "-platform_version".into(),
                        value: platform.clone(),
                        expected: "platform `macos`".into(),
                    });
                }
                let minos_raw = it
                    .next()
                    .ok_or_else(|| ArgsError::MissingValue("-platform_version".into()))?;
                let sdk_raw = it
                    .next()
                    .ok_or_else(|| ArgsError::MissingValue("-platform_version".into()))?;
                opts.platform_version = Some(PlatformVersion {
                    minos: parse_version_component("-platform_version", minos_raw)?,
                    sdk: parse_version_component("-platform_version", sdk_raw)?,
                });
            }
            "-r" => {
                opts.relocatable = true;
            }
            "-bundle" => {
                opts.bundle = true;
            }
            "-undefined" => {
                let value = it
                    .next()
                    .ok_or_else(|| ArgsError::MissingValue("-undefined".into()))?;
                opts.undefined_treatment = match value.as_str() {
                    "error" => UndefinedTreatment::Error,
                    "warning" => UndefinedTreatment::Warning,
                    "suppress" => UndefinedTreatment::Suppress,
                    "dynamic_lookup" => UndefinedTreatment::DynamicLookup,
                    _ => {
                        return Err(ArgsError::InvalidValue {
                            flag: "-undefined".into(),
                            value: value.clone(),
                            expected: "`error`, `warning`, `suppress`, or `dynamic_lookup`".into(),
                        });
                    }
                };
            }
            "-rpath" => {
                opts.rpaths.push(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-rpath".into()))?
                        .clone(),
                );
            }
            "-install_name" => {
                opts.install_name = Some(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-install_name".into()))?
                        .clone(),
                );
            }
            "-current_version" => {
                let value = it
                    .next()
                    .ok_or_else(|| ArgsError::MissingValue("-current_version".into()))?;
                opts.current_version = Some(parse_version_component("-current_version", value)?);
            }
            "-compatibility_version" => {
                let value = it
                    .next()
                    .ok_or_else(|| ArgsError::MissingValue("-compatibility_version".into()))?;
                opts.compatibility_version =
                    Some(parse_version_component("-compatibility_version", value)?);
            }
            "-exported_symbols_list" => {
                opts.exported_symbols_lists
                    .push(PathBuf::from(it.next().ok_or_else(|| {
                        ArgsError::MissingValue("-exported_symbols_list".into())
                    })?));
            }
            "-unexported_symbols_list" => {
                opts.unexported_symbols_lists.push(PathBuf::from(
                    it.next().ok_or_else(|| {
                        ArgsError::MissingValue("-unexported_symbols_list".into())
                    })?,
                ));
            }
            "-exported_symbol" => {
                opts.exported_symbols.push(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-exported_symbol".into()))?
                        .clone(),
                );
            }
            "-unexported_symbol" => {
                opts.unexported_symbols.push(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-unexported_symbol".into()))?
                        .clone(),
                );
            }
            "-S" => {
                opts.strip_debug = true;
            }
            "-no_uuid" => {
                opts.emit_uuid = false;
            }
            "-no_loh" => {
                opts.no_loh = true;
            }
            s if s.starts_with("-thunks=") => {
                opts.thunks = match s {
                    "-thunks=none" => ThunkMode::None,
                    "-thunks=safe" => ThunkMode::Safe,
                    "-thunks=all" => ThunkMode::All,
                    _ => {
                        let value = s.trim_start_matches("-thunks=").to_string();
                        return Err(ArgsError::InvalidValue {
                            flag: "-thunks".into(),
                            value,
                            expected: "`none`, `safe`, or `all`".into(),
                        });
                    }
                };
            }
            "-dead_strip" => {
                opts.dead_strip = true;
            }
            s if s.starts_with("-icf=") => {
                opts.icf_mode = match s {
                    "-icf=none" => IcfMode::None,
                    "-icf=safe" => IcfMode::Safe,
                    "-icf=all" => IcfMode::All,
                    _ => {
                        let value = s.trim_start_matches("-icf=").to_string();
                        return Err(ArgsError::InvalidValue {
                            flag: "-icf".into(),
                            value,
                            expected: "`safe`, `none`, or `all`".into(),
                        });
                    }
                };
            }
            "-fixup_chains" => {
                opts.fixup_chains = true;
            }
            "-no_fixup_chains" => {
                opts.fixup_chains = false;
            }
            "-map" => {
                opts.map = Some(PathBuf::from(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-map".into()))?,
                ));
            }
            "-why_live" => {
                opts.why_live.push(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-why_live".into()))?
                        .clone(),
                );
            }
            "-t" | "-trace" => {
                opts.trace_inputs = true;
            }
            "-v" | "--version" => {
                opts.show_version = true;
            }
            "-h" | "--help" => {
                opts.show_help = true;
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
                opts.force_load_archives
                    .push(PathBuf::from(it.next().ok_or_else(|| {
                        ArgsError::MissingValue("-force_load".into())
                    })?));
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

fn normalize_wl(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    for arg in argv {
        if let Some(rest) = arg.strip_prefix("-Wl,") {
            out.extend(
                rest.split(',')
                    .filter(|piece| !piece.is_empty())
                    .map(ToString::to_string),
            );
        } else {
            out.push(arg.clone());
        }
    }
    out
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
    fn deferred_output_flags_are_recorded() {
        let opts = parse(&argv(&["-r", "-bundle", "foo.o"])).unwrap();
        assert!(opts.relocatable);
        assert!(opts.bundle);
    }

    #[test]
    fn strip_locals_flag_is_recorded() {
        let opts = parse(&argv(&["-x", "foo.o"])).unwrap();
        assert!(opts.strip_locals);
    }

    #[test]
    fn strip_debug_and_uuid_flags_are_recorded() {
        let opts = parse(&argv(&["-S", "-no_uuid", "foo.o"])).unwrap();
        assert!(opts.strip_debug);
        assert!(!opts.emit_uuid);
    }

    #[test]
    fn no_loh_flag_is_recorded() {
        let opts = parse(&argv(&["-no_loh", "foo.o"])).unwrap();
        assert!(opts.no_loh);
    }

    #[test]
    fn dead_strip_icf_and_fixup_chain_flags_are_recorded() {
        let opts = parse(&argv(&[
            "-dead_strip",
            "-thunks=all",
            "-icf=safe",
            "-fixup_chains",
            "-no_fixup_chains",
            "-icf=none",
            "foo.o",
        ]))
        .unwrap();
        assert!(opts.dead_strip);
        assert_eq!(opts.thunks, ThunkMode::All);
        assert_eq!(opts.icf_mode, IcfMode::None);
        assert!(!opts.fixup_chains);
    }

    #[test]
    fn thunks_flag_rejects_unknown_modes() {
        let err = parse(&argv(&["-thunks=clustered", "main.o"])).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::InvalidValue {
                ref flag,
                ref value,
                ..
            } if flag == "-thunks" && value == "clustered"
        ));
    }

    #[test]
    fn icf_all_flag_is_recorded() {
        let opts = parse(&argv(&["-icf=all", "foo.o"])).unwrap();
        assert_eq!(opts.icf_mode, IcfMode::All);
    }

    #[test]
    fn icf_flag_rejects_unknown_modes() {
        let err = parse(&argv(&["-icf=aggressive", "main.o"])).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::InvalidValue {
                ref flag,
                ref value,
                ..
            } if flag == "-icf" && value == "aggressive"
        ));
    }

    #[test]
    fn l_flag_accepts_separate_value() {
        let opts = parse(&argv(&["-l", "System", "main.o"])).unwrap();
        assert_eq!(opts.library_names, vec!["System".to_string()]);
        assert_eq!(opts.inputs, vec![PathBuf::from("main.o")]);
    }

    #[test]
    fn l_flag_accepts_joined_value() {
        let opts = parse(&argv(&["-lSystem", "main.o"])).unwrap();
        assert_eq!(opts.library_names, vec!["System".to_string()]);
        assert_eq!(opts.inputs, vec![PathBuf::from("main.o")]);
    }

    #[test]
    fn search_path_and_syslibroot_flags_are_recorded() {
        let opts = parse(&argv(&["-L", "/tmp/lib", "-syslibroot", "/sdk", "main.o"])).unwrap();
        assert_eq!(opts.search_paths, vec![PathBuf::from("/tmp/lib")]);
        assert_eq!(opts.syslibroot, Some(PathBuf::from("/sdk")));
    }

    #[test]
    fn framework_flags_are_recorded_in_order() {
        let opts = parse(&argv(&[
            "-framework",
            "Foundation",
            "-weak_framework",
            "Metal",
            "main.o",
        ]))
        .unwrap();
        assert_eq!(
            opts.frameworks,
            vec![
                FrameworkSpec {
                    name: "Foundation".into(),
                    weak: false,
                },
                FrameworkSpec {
                    name: "Metal".into(),
                    weak: true,
                }
            ]
        );
        assert_eq!(opts.inputs, vec![PathBuf::from("main.o")]);
    }

    #[test]
    fn objc_flag_is_recorded() {
        let opts = parse(&argv(&["-ObjC", "main.o"])).unwrap();
        assert!(opts.objc_force_load);
    }

    #[test]
    fn platform_version_flag_is_recorded() {
        let opts = parse(&argv(&[
            "-platform_version",
            "macos",
            "13.2.1",
            "14.5",
            "main.o",
        ]))
        .unwrap();
        let platform = opts.platform_version.expect("platform version");
        assert_eq!(platform.minos, (13 << 16) | (2 << 8) | 1);
        assert_eq!(platform.sdk, (14 << 16) | (5 << 8));
    }

    #[test]
    fn platform_version_rejects_non_macos_platform() {
        let err = parse(&argv(&["-platform_version", "ios", "13.0", "13.0"])).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::InvalidValue {
                ref flag,
                ref value,
                ..
            } if flag == "-platform_version" && value == "ios"
        ));
    }

    #[test]
    fn platform_version_rejects_bad_version() {
        let err = parse(&argv(&["-platform_version", "macos", "13.bad", "14.0"])).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::InvalidValue {
                ref flag,
                ref value,
                ..
            } if flag == "-platform_version" && value == "13.bad"
        ));
    }

    #[test]
    fn undefined_flag_records_dynamic_lookup() {
        let opts = parse(&argv(&["-undefined", "dynamic_lookup", "main.o"])).unwrap();
        assert_eq!(opts.undefined_treatment, UndefinedTreatment::DynamicLookup);
    }

    #[test]
    fn undefined_flag_records_warning_and_suppress() {
        let warning = parse(&argv(&["-undefined", "warning", "main.o"])).unwrap();
        assert_eq!(warning.undefined_treatment, UndefinedTreatment::Warning);

        let suppress = parse(&argv(&["-undefined", "suppress", "main.o"])).unwrap();
        assert_eq!(suppress.undefined_treatment, UndefinedTreatment::Suppress);
    }

    #[test]
    fn undefined_flag_rejects_unknown_modes() {
        let err = parse(&argv(&["-undefined", "bogus", "main.o"])).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::InvalidValue {
                ref flag,
                ref value,
                ..
            } if flag == "-undefined" && value == "bogus"
        ));
    }

    #[test]
    fn dylib_metadata_flags_are_recorded() {
        let opts = parse(&argv(&[
            "-rpath",
            "@loader_path/../lib",
            "-install_name",
            "@rpath/libdemo.dylib",
            "-current_version",
            "2.3.4",
            "-compatibility_version",
            "1.2",
            "main.o",
        ]))
        .unwrap();
        assert_eq!(opts.rpaths, vec!["@loader_path/../lib".to_string()]);
        assert_eq!(opts.install_name.as_deref(), Some("@rpath/libdemo.dylib"));
        assert_eq!(opts.current_version, Some((2 << 16) | (3 << 8) | 4));
        assert_eq!(opts.compatibility_version, Some((1 << 16) | (2 << 8)));
    }

    #[test]
    fn export_visibility_flags_are_recorded() {
        let opts = parse(&argv(&[
            "-exported_symbols_list",
            "exports.txt",
            "-unexported_symbols_list",
            "hidden.txt",
            "-exported_symbol",
            "_keep",
            "-unexported_symbol",
            "_drop",
            "main.o",
        ]))
        .unwrap();
        assert_eq!(
            opts.exported_symbols_lists,
            vec![PathBuf::from("exports.txt")]
        );
        assert_eq!(
            opts.unexported_symbols_lists,
            vec![PathBuf::from("hidden.txt")]
        );
        assert_eq!(opts.exported_symbols, vec!["_keep".to_string()]);
        assert_eq!(opts.unexported_symbols, vec!["_drop".to_string()]);
    }

    #[test]
    fn map_flag_is_recorded() {
        let opts = parse(&argv(&["-map", "link.map", "main.o"])).unwrap();
        assert_eq!(opts.map.as_deref(), Some(std::path::Path::new("link.map")));
    }

    #[test]
    fn wl_normalizes_map_like_direct_flag() {
        let opts = parse(&argv(&["-Wl,-map,link.map", "main.o"])).unwrap();
        assert_eq!(opts.map.as_deref(), Some(std::path::Path::new("link.map")));
        assert_eq!(opts.inputs, vec![PathBuf::from("main.o")]);
    }

    #[test]
    fn trace_flags_are_recorded() {
        let opts = parse(&argv(&["-trace", "main.o"])).unwrap();
        assert!(opts.trace_inputs);
        let opts = parse(&argv(&["-t", "main.o"])).unwrap();
        assert!(opts.trace_inputs);
    }

    #[test]
    fn why_live_flag_accumulates_symbols() {
        let opts = parse(&argv(&[
            "-why_live",
            "_helper",
            "-why_live",
            "_leaf",
            "main.o",
        ]))
        .unwrap();
        assert_eq!(
            opts.why_live,
            vec!["_helper".to_string(), "_leaf".to_string()]
        );
    }

    #[test]
    fn help_and_version_flags_are_recorded() {
        let opts = parse(&argv(&["--help"])).unwrap();
        assert!(opts.show_help);
        let opts = parse(&argv(&["-h"])).unwrap();
        assert!(opts.show_help);
        let opts = parse(&argv(&["--version"])).unwrap();
        assert!(opts.show_version);
        let opts = parse(&argv(&["-v"])).unwrap();
        assert!(opts.show_version);
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
    fn missing_l_value_errors() {
        let err = parse(&argv(&["-l"])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue(ref f) if f == "-l"));
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
