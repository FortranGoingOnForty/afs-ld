//! Hand-rolled CLI parser. No clap.
//!
//! Sprint 0 recognizes a minimal set (`-o`, `-e`, `-arch`, positional inputs)
//! and errors on anything else with a precise diagnostic. Sprint 19 grows this
//! into the full `ld`-compatible surface described in `.docs/sprints/sprint19.md`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::resolve::{levenshtein, UndefinedTreatment};
use crate::{
    FrameworkSpec, IcfMode, InputSpec, LinkOptions, OutputKind, PlatformVersion, ThunkMode,
};

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
    "-headerpad",
    "-headerpad_max_install_names",
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
    "-j",
    "--dump",
    "--dump-archive",
    "--dump-dylib",
    "--dump-tbd",
];

const RESPONSE_FILE_DEPTH_LIMIT: usize = 8;
const PACKED_VERSION_MAJOR_MAX: u32 = u16::MAX as u32;
const PACKED_VERSION_MINOR_MAX: u32 = u8::MAX as u32;
const PACKED_VERSION_PATCH_MAX: u32 = u8::MAX as u32;
const PACKED_VERSION_FORMAT: &str =
    "version like <major>[.<minor>[.<patch>]] with major at most 65535 and minor/patch at most 255";

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
    /// A response file could not be read as UTF-8 text.
    ResponseFileRead {
        path: PathBuf,
        referenced_at: Option<(PathBuf, usize, usize)>,
        source: io::Error,
    },
    /// A response file contains malformed quoting.
    ResponseFileSyntax {
        path: PathBuf,
        line: usize,
        column: usize,
        message: String,
    },
    /// A response file includes itself, directly or indirectly.
    ResponseFileCycle {
        path: PathBuf,
        referenced_at: Option<(PathBuf, usize, usize)>,
    },
    /// Nested response files exceeded the defensive recursion bound.
    ResponseFileDepth {
        path: PathBuf,
        referenced_at: Option<(PathBuf, usize, usize)>,
        limit: usize,
    },
}

#[derive(Debug)]
pub struct ParsedArgs {
    pub options: LinkOptions,
    pub input_specs: Vec<InputSpec>,
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
            ArgsError::ResponseFileRead {
                path,
                referenced_at,
                source,
            } => {
                write!(
                    f,
                    "cannot read response file `{}`: {source}",
                    path.display()
                )?;
                write_response_reference(f, referenced_at.as_ref())
            }
            ArgsError::ResponseFileSyntax {
                path,
                line,
                column,
                message,
            } => write!(
                f,
                "cannot parse response file `{}` at {line}:{column}: {message}",
                path.display()
            ),
            ArgsError::ResponseFileCycle {
                path,
                referenced_at,
            } => {
                write!(
                    f,
                    "circular response file inclusion of `{}`",
                    path.display()
                )?;
                write_response_reference(f, referenced_at.as_ref())
            }
            ArgsError::ResponseFileDepth {
                path,
                referenced_at,
                limit,
            } => {
                write!(
                    f,
                    "response file nesting exceeds limit of {limit} at `{}`",
                    path.display()
                )?;
                write_response_reference(f, referenced_at.as_ref())
            }
        }
    }
}

fn write_response_reference(
    f: &mut std::fmt::Formatter<'_>,
    referenced_at: Option<&(PathBuf, usize, usize)>,
) -> std::fmt::Result {
    if let Some((path, line, column)) = referenced_at {
        write!(f, " (referenced at `{}`:{line}:{column})", path.display())?;
    }
    Ok(())
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

fn invalid_packed_version(flag: &str, value: &str, expected: String) -> ArgsError {
    ArgsError::InvalidValue {
        flag: flag.to_string(),
        value: value.to_string(),
        expected,
    }
}

fn parse_packed_version_part(
    flag: &str,
    value: &str,
    raw: &str,
    component: &str,
    maximum: u32,
) -> Result<u32, ArgsError> {
    let parsed = raw
        .parse::<u32>()
        .map_err(|_| invalid_packed_version(flag, value, PACKED_VERSION_FORMAT.to_string()))?;
    if parsed > maximum {
        return Err(invalid_packed_version(
            flag,
            value,
            format!("{component} component must be at most {maximum}"),
        ));
    }
    Ok(parsed)
}

fn parse_packed_version(flag: &str, value: &str) -> Result<u32, ArgsError> {
    let mut parts = value.split('.');
    let major = parse_packed_version_part(
        flag,
        value,
        parts.next().unwrap_or_default(),
        "major",
        PACKED_VERSION_MAJOR_MAX,
    )?;
    let minor = match parts.next() {
        Some(raw) => {
            parse_packed_version_part(flag, value, raw, "minor", PACKED_VERSION_MINOR_MAX)?
        }
        None => 0,
    };
    let patch = match parts.next() {
        Some(raw) => {
            parse_packed_version_part(flag, value, raw, "patch", PACKED_VERSION_PATCH_MAX)?
        }
        None => 0,
    };
    if parts.next().is_some() {
        return Err(invalid_packed_version(
            flag,
            value,
            PACKED_VERSION_FORMAT.to_string(),
        ));
    }
    Ok((major << 16) | (minor << 8) | patch)
}

fn parse_jobs(value: &str) -> Result<usize, ArgsError> {
    let jobs = value
        .parse::<usize>()
        .map_err(|_| ArgsError::InvalidValue {
            flag: "-j".into(),
            value: value.to_string(),
            expected: "positive integer job count".into(),
        })?;
    if jobs == 0 {
        return Err(ArgsError::InvalidValue {
            flag: "-j".into(),
            value: value.to_string(),
            expected: "positive integer job count".into(),
        });
    }
    Ok(jobs)
}

fn parse_header_pad(value: &str) -> Result<u64, ArgsError> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if digits.is_empty() {
        return Err(ArgsError::InvalidValue {
            flag: "-headerpad".into(),
            value: value.to_string(),
            expected: "hexadecimal byte count".into(),
        });
    }
    u64::from_str_radix(digits, 16).map_err(|_| ArgsError::InvalidValue {
        flag: "-headerpad".into(),
        value: value.to_string(),
        expected: "hexadecimal byte count".into(),
    })
}

#[derive(Debug)]
struct ResponseToken {
    value: String,
    line: usize,
    column: usize,
}

/// Normalize driver-wrapped flags and expand GNU-style `@file` arguments in
/// place before target-format routing.
///
/// Nested response paths are resolved relative to the file containing them.
/// `@@path` escapes a literal `@path`, and Darwin loader paths are never
/// interpreted as response files.
#[doc(hidden)]
pub fn preprocess_args(argv: &[String]) -> Result<Vec<String>, ArgsError> {
    let mut preprocessed = Vec::with_capacity(argv.len());
    let mut stack = Vec::new();
    for arg in argv {
        preprocess_arg(arg, None, None, 0, &mut stack, &mut preprocessed)?;
    }
    Ok(preprocessed)
}

fn preprocess_arg(
    arg: &str,
    base_dir: Option<&Path>,
    referenced_at: Option<(PathBuf, usize, usize)>,
    depth: usize,
    stack: &mut Vec<PathBuf>,
    preprocessed: &mut Vec<String>,
) -> Result<(), ArgsError> {
    if let Some(wrapped) = arg.strip_prefix("-Wl,") {
        for piece in wrapped.split(',').filter(|piece| !piece.is_empty()) {
            preprocess_arg(
                piece,
                base_dir,
                referenced_at.clone(),
                depth,
                stack,
                preprocessed,
            )?;
        }
        return Ok(());
    }
    if let Some(literal) = arg.strip_prefix("@@") {
        preprocessed.push(format!("@{literal}"));
        return Ok(());
    }
    if is_darwin_loader_path(arg) {
        preprocessed.push(arg.to_string());
        return Ok(());
    }
    let Some(path) = arg.strip_prefix('@') else {
        preprocessed.push(arg.to_string());
        return Ok(());
    };

    let resolved = resolve_response_path(path, base_dir);
    if depth >= RESPONSE_FILE_DEPTH_LIMIT {
        return Err(ArgsError::ResponseFileDepth {
            path: resolved,
            referenced_at,
            limit: RESPONSE_FILE_DEPTH_LIMIT,
        });
    }

    let canonical = fs::canonicalize(&resolved).unwrap_or_else(|_| resolved.clone());
    if stack.contains(&canonical) {
        return Err(ArgsError::ResponseFileCycle {
            path: resolved,
            referenced_at,
        });
    }

    let body = fs::read_to_string(&resolved).map_err(|source| ArgsError::ResponseFileRead {
        path: resolved.clone(),
        referenced_at: referenced_at.clone(),
        source,
    })?;
    let tokens = parse_response_tokens(&body, &resolved)?;
    let next_base = resolved.parent();

    stack.push(canonical);
    let result = tokens.into_iter().try_for_each(|token| {
        preprocess_arg(
            &token.value,
            next_base,
            Some((resolved.clone(), token.line, token.column)),
            depth + 1,
            stack,
            preprocessed,
        )
    });
    stack.pop();
    result
}

fn is_darwin_loader_path(arg: &str) -> bool {
    arg.starts_with("@rpath/")
        || arg.starts_with("@loader_path/")
        || arg.starts_with("@executable_path/")
}

fn resolve_response_path(path: &str, base_dir: Option<&Path>) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else if let Some(base_dir) = base_dir {
        base_dir.join(candidate)
    } else {
        candidate
    }
}

fn parse_response_tokens(body: &str, path: &Path) -> Result<Vec<ResponseToken>, ArgsError> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = body.chars().peekable();
    let mut line = 1usize;
    let mut column = 1usize;
    let mut token_start = None;
    let mut quote = None;

    while let Some(ch) = chars.next() {
        let ch_line = line;
        let ch_column = column;
        advance_response_position(ch, &mut line, &mut column);

        if let Some((delimiter, _, _)) = quote {
            match ch {
                '\\' => {
                    if let Some(escaped) = chars.next() {
                        advance_response_position(escaped, &mut line, &mut column);
                        current.push(escaped);
                    } else {
                        current.push('\\');
                    }
                }
                value if value == delimiter => quote = None,
                _ => current.push(ch),
            }
            continue;
        }

        match ch {
            '\'' | '"' => {
                token_start.get_or_insert((ch_line, ch_column));
                quote = Some((ch, ch_line, ch_column));
            }
            '\\' => {
                token_start.get_or_insert((ch_line, ch_column));
                if let Some(escaped) = chars.next() {
                    advance_response_position(escaped, &mut line, &mut column);
                    current.push(escaped);
                } else {
                    current.push('\\');
                }
            }
            whitespace if whitespace.is_whitespace() => {
                if let Some((start_line, start_column)) = token_start.take() {
                    tokens.push(ResponseToken {
                        value: std::mem::take(&mut current),
                        line: start_line,
                        column: start_column,
                    });
                }
            }
            _ => {
                token_start.get_or_insert((ch_line, ch_column));
                current.push(ch);
            }
        }
    }

    if let Some((delimiter, quote_line, quote_column)) = quote {
        return Err(ArgsError::ResponseFileSyntax {
            path: path.to_path_buf(),
            line: quote_line,
            column: quote_column,
            message: format!("unterminated {delimiter} quote"),
        });
    }
    if let Some((start_line, start_column)) = token_start {
        tokens.push(ResponseToken {
            value: current,
            line: start_line,
            column: start_column,
        });
    }
    Ok(tokens)
}

fn advance_response_position(ch: char, line: &mut usize, column: &mut usize) {
    if ch == '\n' {
        *line += 1;
        *column = 1;
    } else {
        *column += 1;
    }
}

#[deprecated(
    since = "0.1.0",
    note = "grouped LinkOptions cannot preserve mixed input order; use parse_ordered"
)]
pub fn parse(argv: &[String]) -> Result<LinkOptions, ArgsError> {
    parse_ordered(argv).map(|parsed| parsed.options)
}

pub fn parse_ordered(argv: &[String]) -> Result<ParsedArgs, ArgsError> {
    parse_ordered_with_force_loads(argv).map(|(parsed, _)| parsed)
}

#[doc(hidden)]
pub fn parse_ordered_with_force_loads(
    argv: &[String],
) -> Result<(ParsedArgs, Vec<usize>), ArgsError> {
    let preprocessed = preprocess_args(argv)?;
    parse_preprocessed_with_force_loads(&preprocessed)
}

/// Parse arguments that have already passed through [`preprocess_args`]. The
/// binary uses this entry point to avoid reading response files twice after it
/// performs target-format routing.
#[doc(hidden)]
pub fn parse_preprocessed_with_force_loads(
    argv: &[String],
) -> Result<(ParsedArgs, Vec<usize>), ArgsError> {
    let mut opts = LinkOptions::default();
    let mut input_specs = Vec::new();
    let mut force_load_positions = Vec::new();
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
            "-l" => {
                let name = it
                    .next()
                    .ok_or_else(|| ArgsError::MissingValue("-l".into()))?
                    .clone();
                opts.library_names.push(name.clone());
                input_specs.push(InputSpec::Library(name));
            }
            s if s.starts_with("-l") && s.len() > 2 => {
                let name = s[2..].to_string();
                opts.library_names.push(name.clone());
                input_specs.push(InputSpec::Library(name));
            }
            "-L" => {
                opts.search_paths.push(PathBuf::from(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-L".into()))?,
                ));
            }
            "-framework" => {
                let framework = FrameworkSpec {
                    name: it
                        .next()
                        .ok_or_else(|| ArgsError::MissingValue("-framework".into()))?
                        .clone(),
                    weak: false,
                };
                opts.frameworks.push(framework.clone());
                input_specs.push(InputSpec::Framework(framework));
            }
            "-weak_framework" => {
                let framework = FrameworkSpec {
                    name: it
                        .next()
                        .ok_or_else(|| ArgsError::MissingValue("-weak_framework".into()))?
                        .clone(),
                    weak: true,
                };
                opts.frameworks.push(framework.clone());
                input_specs.push(InputSpec::Framework(framework));
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
                    minos: parse_packed_version("-platform_version", minos_raw)?,
                    sdk: parse_packed_version("-platform_version", sdk_raw)?,
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
                opts.current_version = Some(parse_packed_version("-current_version", value)?);
            }
            "-compatibility_version" => {
                let value = it
                    .next()
                    .ok_or_else(|| ArgsError::MissingValue("-compatibility_version".into()))?;
                opts.compatibility_version =
                    Some(parse_packed_version("-compatibility_version", value)?);
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
            "-headerpad" => {
                let value = it
                    .next()
                    .ok_or_else(|| ArgsError::MissingValue("-headerpad".into()))?;
                opts.header_pad = parse_header_pad(value)?;
            }
            "-headerpad_max_install_names" => {
                opts.header_pad_max_install_names = true;
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
                let path = PathBuf::from(
                    it.next()
                        .ok_or_else(|| ArgsError::MissingValue("-force_load".into()))?,
                );
                opts.force_load_archives.push(path.clone());
                force_load_positions.push(input_specs.len());
                input_specs.push(InputSpec::Path(path));
            }
            "-j" => {
                let value = it
                    .next()
                    .ok_or_else(|| ArgsError::MissingValue("-j".into()))?;
                opts.jobs = Some(parse_jobs(value)?);
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
                let path = PathBuf::from(arg);
                opts.inputs.push(path.clone());
                input_specs.push(InputSpec::Path(path));
            }
        }
    }
    Ok((
        ParsedArgs {
            options: opts,
            input_specs,
        },
        force_load_positions,
    ))
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_RESPONSE_TEST_DIR: AtomicUsize = AtomicUsize::new(0);

    struct ResponseTestDir {
        path: PathBuf,
    }

    impl ResponseTestDir {
        fn new() -> Self {
            let id = NEXT_RESPONSE_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "afs_ld_response_test_{}_{}",
                std::process::id(),
                id
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }

        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, contents).unwrap();
            path
        }
    }

    impl Drop for ResponseTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_output_and_entry() {
        let opts = parse(&argv(&["-o", "out", "-e", "_start", "a.o", "b.o"])).unwrap();
        assert_eq!(opts.output.as_deref(), Some(std::path::Path::new("out")));
        assert_eq!(opts.entry.as_deref(), Some("_start"));
        assert_eq!(
            opts.inputs,
            vec![PathBuf::from("a.o"), PathBuf::from("b.o")]
        );
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
    fn headerpad_is_parsed_as_hexadecimal_bytes() {
        let opts = parse(&argv(&["-headerpad", "0x200", "foo.o"])).unwrap();
        assert_eq!(opts.header_pad, 0x200);

        let opts = parse(&argv(&["-headerpad", "200", "foo.o"])).unwrap();
        assert_eq!(opts.header_pad, 0x200);
    }

    #[test]
    fn headerpad_max_install_names_is_recorded() {
        let opts = parse(&argv(&[
            "-headerpad",
            "200",
            "-headerpad_max_install_names",
            "foo.o",
        ]))
        .unwrap();
        assert_eq!(opts.header_pad, 0x200);
        assert!(opts.header_pad_max_install_names);
    }

    #[test]
    fn headerpad_rejects_missing_or_non_hex_values() {
        let missing = parse(&argv(&["-headerpad"])).unwrap_err();
        assert!(matches!(
            missing,
            ArgsError::MissingValue(ref flag) if flag == "-headerpad"
        ));

        let invalid = parse(&argv(&["-headerpad", "12g", "foo.o"])).unwrap_err();
        assert!(matches!(
            invalid,
            ArgsError::InvalidValue {
                ref flag,
                ref value,
                ..
            } if flag == "-headerpad" && value == "12g"
        ));
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
                },
            ]
        );
        assert_eq!(opts.inputs, vec![PathBuf::from("main.o")]);
    }

    #[test]
    fn mixed_inputs_share_one_command_line_order() {
        let parsed = parse_ordered(&argv(&[
            "main.o",
            "-lA",
            "libB.a",
            "-weak_framework",
            "Metal",
            "tail.o",
        ]))
        .unwrap();
        assert_eq!(
            parsed.input_specs,
            vec![
                InputSpec::Path(PathBuf::from("main.o")),
                InputSpec::Library("A".into()),
                InputSpec::Path(PathBuf::from("libB.a")),
                InputSpec::Framework(FrameworkSpec {
                    name: "Metal".into(),
                    weak: true,
                }),
                InputSpec::Path(PathBuf::from("tail.o")),
            ]
        );
        assert_eq!(
            parsed.options.inputs,
            vec![
                PathBuf::from("main.o"),
                PathBuf::from("libB.a"),
                PathBuf::from("tail.o")
            ]
        );
        assert_eq!(parsed.options.library_names, vec!["A"]);
        assert_eq!(parsed.options.frameworks[0].name, "Metal");
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
    fn version_flags_accept_maximum_packed_components() {
        let opts = parse(&argv(&[
            "-platform_version",
            "macos",
            "65535.255.255",
            "65535.255.255",
            "-current_version",
            "65535.255.255",
            "-compatibility_version",
            "65535.255.255",
            "main.o",
        ]))
        .unwrap();

        let platform = opts.platform_version.expect("platform version");
        assert_eq!(platform.minos, u32::MAX);
        assert_eq!(platform.sdk, u32::MAX);
        assert_eq!(opts.current_version, Some(u32::MAX));
        assert_eq!(opts.compatibility_version, Some(u32::MAX));
    }

    #[test]
    fn version_flags_reject_component_overflow() {
        let cases = [
            (
                vec!["-platform_version", "macos", "65536.0.0", "1.0"],
                "-platform_version",
                "65536.0.0",
                "major component must be at most 65535",
            ),
            (
                vec!["-platform_version", "macos", "1.256.0", "1.0"],
                "-platform_version",
                "1.256.0",
                "minor component must be at most 255",
            ),
            (
                vec!["-platform_version", "macos", "1.0.256", "1.0"],
                "-platform_version",
                "1.0.256",
                "patch component must be at most 255",
            ),
            (
                vec!["-platform_version", "macos", "1.0", "65536.0.0"],
                "-platform_version",
                "65536.0.0",
                "major component must be at most 65535",
            ),
            (
                vec!["-current_version", "1.256.0"],
                "-current_version",
                "1.256.0",
                "minor component must be at most 255",
            ),
            (
                vec!["-compatibility_version", "1.0.256"],
                "-compatibility_version",
                "1.0.256",
                "patch component must be at most 255",
            ),
        ];

        for (args, expected_flag, expected_value, expected_reason) in cases {
            let err = parse(&argv(&args)).expect_err(expected_value);
            assert!(matches!(
                err,
                ArgsError::InvalidValue {
                    ref flag,
                    ref value,
                    ref expected,
                } if flag == expected_flag
                    && value == expected_value
                    && expected.contains(expected_reason)
            ));
        }
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
    fn wl_and_response_preprocessing_compose_recursively_in_place() {
        let dir = ResponseTestDir::new();
        dir.write("inner.rsp", "-Wl,middle.o,-lSystem\n");
        let outer = dir.write("outer.rsp", "-Wl,@inner.rsp\n");

        let parsed = parse_ordered(&[
            "before.o".into(),
            format!("-Wl,@{}", outer.display()),
            "after.o".into(),
        ])
        .unwrap();

        assert_eq!(
            parsed.input_specs,
            vec![
                InputSpec::Path(PathBuf::from("before.o")),
                InputSpec::Path(PathBuf::from("middle.o")),
                InputSpec::Library("System".into()),
                InputSpec::Path(PathBuf::from("after.o")),
            ]
        );
    }

    #[test]
    fn empty_wl_fields_do_not_disturb_input_order() {
        let parsed =
            parse_ordered(&argv(&["before.o", "-Wl,,middle.o,,-lSystem,,", "after.o"])).unwrap();
        assert_eq!(
            parsed.input_specs,
            vec![
                InputSpec::Path(PathBuf::from("before.o")),
                InputSpec::Path(PathBuf::from("middle.o")),
                InputSpec::Library("System".into()),
                InputSpec::Path(PathBuf::from("after.o")),
            ]
        );
    }

    #[test]
    fn wl_wrapping_preserves_escaped_at_and_darwin_loader_paths() {
        let parsed =
            parse_ordered(&argv(&["-Wl,@@response.o,@rpath/libdependency.dylib"])).unwrap();
        assert_eq!(
            parsed.options.inputs,
            vec![
                PathBuf::from("@response.o"),
                PathBuf::from("@rpath/libdependency.dylib"),
            ]
        );
    }

    #[test]
    fn response_files_expand_in_place_with_quotes_escapes_and_nesting() {
        let dir = ResponseTestDir::new();
        dir.write(
            "inner.rsp",
            "\"middle object.o\" escaped\\ object.o -lSystem\n",
        );
        let outer = dir.write(
            "outer.rsp",
            "-force_load \"forced archive.a\"\n@inner.rsp\n",
        );

        let (parsed, force_load_positions) = parse_ordered_with_force_loads(&[
            "before.o".into(),
            format!("@{}", outer.display()),
            "after.o".into(),
        ])
        .unwrap();

        assert_eq!(
            parsed.input_specs,
            vec![
                InputSpec::Path(PathBuf::from("before.o")),
                InputSpec::Path(PathBuf::from("forced archive.a")),
                InputSpec::Path(PathBuf::from("middle object.o")),
                InputSpec::Path(PathBuf::from("escaped object.o")),
                InputSpec::Library("System".into()),
                InputSpec::Path(PathBuf::from("after.o")),
            ]
        );
        assert_eq!(force_load_positions, vec![1]);
    }

    #[test]
    fn empty_response_file_contributes_no_arguments() {
        let dir = ResponseTestDir::new();
        let response = dir.write("empty.rsp", " \n\t");
        let opts = parse(&[
            "before.o".into(),
            format!("@{}", response.display()),
            "after.o".into(),
        ])
        .unwrap();
        assert_eq!(
            opts.inputs,
            vec![PathBuf::from("before.o"), PathBuf::from("after.o")]
        );
    }

    #[test]
    fn escaped_at_and_darwin_loader_paths_remain_literal() {
        let parsed = parse_ordered(&argv(&[
            "@@response.o",
            "@rpath/libdependency.dylib",
            "@loader_path/libdependency.dylib",
            "@executable_path/libdependency.dylib",
        ]))
        .unwrap();
        assert_eq!(
            parsed.options.inputs,
            vec![
                PathBuf::from("@response.o"),
                PathBuf::from("@rpath/libdependency.dylib"),
                PathBuf::from("@loader_path/libdependency.dylib"),
                PathBuf::from("@executable_path/libdependency.dylib"),
            ]
        );
    }

    #[test]
    fn unreadable_response_file_is_a_hard_parse_error() {
        let dir = ResponseTestDir::new();
        let missing = dir.path.join("missing.rsp");
        let err = parse(&[format!("@{}", missing.display())]).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::ResponseFileRead { ref path, .. } if path == &missing
        ));
        assert!(err.to_string().contains("cannot read response file"));
    }

    #[test]
    fn response_file_syntax_errors_name_the_exact_location() {
        let dir = ResponseTestDir::new();
        let response = dir.write("malformed.rsp", "before.o\n\"unterminated\n");
        let err = parse(&[format!("@{}", response.display())]).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::ResponseFileSyntax {
                ref path,
                line: 2,
                column: 1,
                ..
            } if path == &response
        ));
        assert!(err.to_string().contains("at 2:1: unterminated \" quote"));
    }

    #[test]
    fn response_file_cycles_are_rejected() {
        let dir = ResponseTestDir::new();
        let first = dir.write("first.rsp", "@second.rsp\n");
        let second = dir.write("second.rsp", "@first.rsp\n");
        let err = parse(&[format!("@{}", first.display())]).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::ResponseFileCycle {
                ref path,
                referenced_at: Some((ref source, 1, 1)),
            } if path == &first && source == &second
        ));
    }

    #[test]
    fn response_file_nesting_is_bounded() {
        let dir = ResponseTestDir::new();
        let files = (0..=RESPONSE_FILE_DEPTH_LIMIT)
            .map(|index| dir.path.join(format!("{index}.rsp")))
            .collect::<Vec<_>>();
        for (index, file) in files.iter().take(RESPONSE_FILE_DEPTH_LIMIT).enumerate() {
            fs::write(file, format!("@{}.rsp\n", index + 1)).unwrap();
        }
        fs::write(&files[RESPONSE_FILE_DEPTH_LIMIT], "main.o\n").unwrap();

        let err = parse(&[format!("@{}", files[0].display())]).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::ResponseFileDepth {
                ref path,
                limit: RESPONSE_FILE_DEPTH_LIMIT,
                ..
            } if path == &files[RESPONSE_FILE_DEPTH_LIMIT]
        ));
    }

    #[test]
    fn quoted_empty_response_arguments_are_preserved() {
        let tokens = parse_response_tokens("\"\" '' value", Path::new("inline.rsp")).unwrap();
        assert_eq!(
            tokens
                .into_iter()
                .map(|token| token.value)
                .collect::<Vec<_>>(),
            vec!["", "", "value"]
        );
    }

    #[test]
    fn large_response_file_preserves_every_input_in_order() {
        const INPUT_COUNT: usize = 16_384;

        let dir = ResponseTestDir::new();
        let contents = (0..INPUT_COUNT)
            .map(|index| format!("object_{index:05}.o"))
            .collect::<Vec<_>>()
            .join("\n");
        let response = dir.write("large.rsp", &contents);
        let parsed = parse_ordered(&[format!("@{}", response.display())]).unwrap();

        assert_eq!(parsed.input_specs.len(), INPUT_COUNT);
        assert_eq!(
            parsed.input_specs.first(),
            Some(&InputSpec::Path(PathBuf::from("object_00000.o")))
        );
        assert_eq!(
            parsed.input_specs.last(),
            Some(&InputSpec::Path(PathBuf::from("object_16383.o")))
        );
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
    fn force_load_stays_at_its_command_line_position() {
        let (parsed, force_load_positions) = parse_ordered_with_force_loads(&argv(&[
            "main.o",
            "-force_load",
            "libforced.a",
            "liblater.a",
        ]))
        .unwrap();
        assert_eq!(
            parsed.input_specs,
            vec![
                InputSpec::Path(PathBuf::from("main.o")),
                InputSpec::Path(PathBuf::from("libforced.a")),
                InputSpec::Path(PathBuf::from("liblater.a")),
            ]
        );
        assert_eq!(force_load_positions, vec![1]);
    }

    #[test]
    fn jobs_flag_records_positive_worker_limit() {
        let opts = parse(&argv(&["-j", "1", "main.o"])).unwrap();
        assert_eq!(opts.jobs, Some(1));
        assert_eq!(opts.inputs, vec![PathBuf::from("main.o")]);
    }

    #[test]
    fn jobs_flag_rejects_zero_or_non_numeric_values() {
        let err = parse(&argv(&["-j", "0"])).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::InvalidValue {
                ref flag,
                ref value,
                ..
            } if flag == "-j" && value == "0"
        ));
        let err = parse(&argv(&["-j", "many"])).unwrap_err();
        assert!(matches!(
            err,
            ArgsError::InvalidValue {
                ref flag,
                ref value,
                ..
            } if flag == "-j" && value == "many"
        ));
    }

    #[test]
    fn missing_jobs_value_errors() {
        let err = parse(&argv(&["-j"])).unwrap_err();
        assert!(matches!(err, ArgsError::MissingValue(ref f) if f == "-j"));
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
        assert!(opts.library_names.is_empty());
        assert!(opts.frameworks.is_empty());
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
