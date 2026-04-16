//! TBD v4 decoder.
//!
//! Consumes the generic `Value` tree from `tbd_yaml` and produces a
//! strongly-typed `Tbd` that mirrors Apple's TAPI v4 schema. Targets are
//! `arch-platform` strings; each "scoped" field narrows to a subset of
//! targets.
//!
//! Unknown mapping keys (e.g. `uuids`, `swift-abi-version`) are skipped
//! silently — TBD grows new sections over releases and we don't need
//! most of them to produce a linker-side view. A later sprint can tighten
//! this into strict mode if parity testing flags divergences.

use super::tbd_yaml::{parse_documents, Document, Value, YamlError};

#[derive(Debug)]
pub enum TbdError {
    Yaml(YamlError),
    Schema { msg: String },
}

impl std::fmt::Display for TbdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TbdError::Yaml(e) => write!(f, "{e}"),
            TbdError::Schema { msg } => write!(f, "TBD schema error: {msg}"),
        }
    }
}

impl From<YamlError> for TbdError {
    fn from(e: YamlError) -> Self {
        TbdError::Yaml(e)
    }
}

impl std::error::Error for TbdError {}

/// One TBD document. A single `.tbd` file may contain several of these
/// (libSystem.tbd has one per re-exported sub-dylib).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tbd {
    pub version: u32,
    pub targets: Vec<Target>,
    pub install_name: String,
    /// Textual — may be `"1351"` or `"1.2.3"`. Packed to u32 via `parse_version`.
    pub current_version: Option<String>,
    pub compatibility_version: Option<String>,
    pub parent_umbrella: Vec<Scoped<String>>,
    pub allowable_clients: Vec<Scoped<Vec<String>>>,
    pub reexported_libraries: Vec<Scoped<Vec<String>>>,
    pub exports: Vec<Scoped<SymbolLists>>,
    pub reexports: Vec<Scoped<SymbolLists>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub arch: Arch,
    pub platform: Platform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arch {
    Arm64,
    Arm64e,
    X86_64,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Ios,
    WatchOs,
    TvOs,
    DriverKit,
    MacCatalyst,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scoped<T> {
    pub targets: Vec<Target>,
    pub value: T,
}

/// Six symbol lists, one per TAPI symbol category. All are flat arrays of
/// names; kinds (objc vs plain, weak vs regular) are encoded by which
/// list carries the name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolLists {
    pub symbols: Vec<String>,
    pub weak_symbols: Vec<String>,
    pub thread_local_symbols: Vec<String>,
    pub objc_classes: Vec<String>,
    pub objc_eh_types: Vec<String>,
    pub objc_ivars: Vec<String>,
}

impl SymbolLists {
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
            && self.weak_symbols.is_empty()
            && self.thread_local_symbols.is_empty()
            && self.objc_classes.is_empty()
            && self.objc_eh_types.is_empty()
            && self.objc_ivars.is_empty()
    }

    /// Total symbol count across every list. Handy for sanity-checking
    /// against `nm -g` during integration tests.
    pub fn total(&self) -> usize {
        self.symbols.len()
            + self.weak_symbols.len()
            + self.thread_local_symbols.len()
            + self.objc_classes.len()
            + self.objc_eh_types.len()
            + self.objc_ivars.len()
    }
}

/// Parse a TBD file's raw bytes into one `Tbd` per `--- !tapi-tbd` document.
pub fn parse_tbd(input: &str) -> Result<Vec<Tbd>, TbdError> {
    let docs = parse_documents(input)?;
    let mut out = Vec::with_capacity(docs.len());
    for d in docs {
        out.push(decode_document(&d)?);
    }
    Ok(out)
}

fn decode_document(doc: &Document) -> Result<Tbd, TbdError> {
    let m = doc
        .root
        .as_mapping()
        .ok_or_else(|| schema("top level of a TBD document must be a mapping"))?;

    let mut tbd = Tbd::default();
    for (k, v) in m {
        match k.as_str() {
            "tbd-version" => tbd.version = scalar_u32(v, "tbd-version")?,
            "targets" => tbd.targets = decode_target_list(v)?,
            "install-name" => tbd.install_name = scalar_string(v, "install-name")?,
            "current-version" => tbd.current_version = Some(scalar_string(v, "current-version")?),
            "compatibility-version" => {
                tbd.compatibility_version = Some(scalar_string(v, "compatibility-version")?)
            }
            "parent-umbrella" => tbd.parent_umbrella = decode_scoped_umbrella(v)?,
            "allowable-clients" => tbd.allowable_clients = decode_scoped_string_list(v, "clients")?,
            "reexported-libraries" => {
                tbd.reexported_libraries = decode_scoped_string_list(v, "libraries")?;
            }
            "exports" => tbd.exports = decode_scoped_symbols(v)?,
            "reexports" => tbd.reexports = decode_scoped_symbols(v)?,
            // Known-but-ignored keys (grow this list as TAPI adds them).
            "uuids"
            | "flags"
            | "swift-abi-version"
            | "rpaths"
            | "objc-constraint"
            | "parent-libraries" => {}
            _ => {
                // Silently accept unknown keys — TAPI can add new ones in
                // future releases without breaking our reader.
            }
        }
    }
    // Minimum required by every real TAPI TBD.
    if tbd.install_name.is_empty() {
        return Err(schema("TBD document missing required 'install-name'"));
    }
    if tbd.targets.is_empty() {
        return Err(schema("TBD document missing required 'targets'"));
    }
    Ok(tbd)
}

fn decode_target_list(v: &Value) -> Result<Vec<Target>, TbdError> {
    let seq = v
        .as_sequence()
        .ok_or_else(|| schema("'targets' must be a sequence"))?;
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let s = item.as_str().ok_or_else(|| schema("target must be a scalar"))?;
        out.push(parse_target(s)?);
    }
    Ok(out)
}

fn parse_target(s: &str) -> Result<Target, TbdError> {
    // `arch-platform`. Arch may contain a hyphen (none today, but armv7k
    // in the wild) — split on the *last* `-`.
    let hyphen = s.rfind('-').ok_or_else(|| schema(&format!(
        "target {s:?} is not `arch-platform`"
    )))?;
    let arch = match &s[..hyphen] {
        "arm64" => Arch::Arm64,
        "arm64e" => Arch::Arm64e,
        "x86_64" => Arch::X86_64,
        other => Arch::Other(other.to_string()),
    };
    let platform = match &s[hyphen + 1..] {
        "macos" => Platform::MacOs,
        "ios" => Platform::Ios,
        "watchos" => Platform::WatchOs,
        "tvos" => Platform::TvOs,
        "driverkit" => Platform::DriverKit,
        "maccatalyst" => Platform::MacCatalyst,
        other => Platform::Other(other.to_string()),
    };
    Ok(Target { arch, platform })
}

fn decode_scoped_umbrella(v: &Value) -> Result<Vec<Scoped<String>>, TbdError> {
    let seq = v
        .as_sequence()
        .ok_or_else(|| schema("'parent-umbrella' must be a sequence of scoped mappings"))?;
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let m = item
            .as_mapping()
            .ok_or_else(|| schema("parent-umbrella entry must be a mapping"))?;
        let targets = lookup_required(m, "targets").and_then(decode_target_list)?;
        let umbrella = lookup_required(m, "umbrella")
            .and_then(|v| scalar_string(v, "umbrella"))?;
        out.push(Scoped {
            targets,
            value: umbrella,
        });
    }
    Ok(out)
}

fn decode_scoped_string_list(
    v: &Value,
    inner_key: &str,
) -> Result<Vec<Scoped<Vec<String>>>, TbdError> {
    let seq = v
        .as_sequence()
        .ok_or_else(|| schema("expected a sequence of scoped mappings"))?;
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let m = item
            .as_mapping()
            .ok_or_else(|| schema("scoped entry must be a mapping"))?;
        let targets = lookup_required(m, "targets").and_then(decode_target_list)?;
        let value = match m.iter().find(|(k, _)| k == inner_key) {
            Some((_, v)) => decode_string_list(v, inner_key)?,
            None => Vec::new(),
        };
        out.push(Scoped { targets, value });
    }
    Ok(out)
}

fn decode_scoped_symbols(v: &Value) -> Result<Vec<Scoped<SymbolLists>>, TbdError> {
    let seq = v
        .as_sequence()
        .ok_or_else(|| schema("'exports'/'reexports' must be a sequence"))?;
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let m = item
            .as_mapping()
            .ok_or_else(|| schema("exports entry must be a mapping"))?;
        let targets = lookup_required(m, "targets").and_then(decode_target_list)?;
        let mut lists = SymbolLists::default();
        for (k, v) in m {
            match k.as_str() {
                "targets" => {}
                "symbols" => lists.symbols = decode_string_list(v, "symbols")?,
                "weak-symbols" => lists.weak_symbols = decode_string_list(v, "weak-symbols")?,
                "thread-local-symbols" => {
                    lists.thread_local_symbols = decode_string_list(v, "thread-local-symbols")?;
                }
                "objc-classes" => lists.objc_classes = decode_string_list(v, "objc-classes")?,
                "objc-eh-types" => lists.objc_eh_types = decode_string_list(v, "objc-eh-types")?,
                "objc-ivars" => lists.objc_ivars = decode_string_list(v, "objc-ivars")?,
                _ => {} // ignore unknown inner keys
            }
        }
        out.push(Scoped {
            targets,
            value: lists,
        });
    }
    Ok(out)
}

fn decode_string_list(v: &Value, context: &str) -> Result<Vec<String>, TbdError> {
    match v {
        Value::Sequence(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(scalar_string(it, context)?);
            }
            Ok(out)
        }
        Value::Null => Ok(Vec::new()),
        _ => Err(schema(&format!("{context} must be a sequence of scalars"))),
    }
}

fn lookup_required<'a>(m: &'a [(String, Value)], key: &str) -> Result<&'a Value, TbdError> {
    m.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .ok_or_else(|| schema(&format!("missing required key {key:?}")))
}

fn scalar_u32(v: &Value, context: &str) -> Result<u32, TbdError> {
    let s = v
        .as_str()
        .ok_or_else(|| schema(&format!("{context} must be a scalar")))?;
    s.parse()
        .map_err(|_| schema(&format!("{context} must parse as a u32: {s:?}")))
}

fn scalar_string(v: &Value, context: &str) -> Result<String, TbdError> {
    match v {
        Value::Scalar(s) => Ok(s.clone()),
        _ => Err(schema(&format!("{context} must be a scalar"))),
    }
}

fn schema(msg: &str) -> TbdError {
    TbdError::Schema { msg: msg.to_string() }
}

/// Pack a `"X.Y.Z"` / `"X.Y"` / `"X"` / `"1351"` version string to
/// Mach-O's 0xXXXXYYZZ form. Missing fields become 0; extra components
/// are truncated. Plain integers like `1351` become `1351 << 16`.
pub fn parse_version(s: &str) -> u32 {
    let mut parts = s.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let x = parts.next().unwrap_or(0);
    let y = parts.next().unwrap_or(0);
    let z = parts.next().unwrap_or(0);
    (x << 16) | ((y & 0xff) << 8) | (z & 0xff)
}

impl Target {
    /// Exactly matches the TBD string form: `arch-platform`.
    pub fn as_string(&self) -> String {
        let arch = match &self.arch {
            Arch::Arm64 => "arm64".to_string(),
            Arch::Arm64e => "arm64e".to_string(),
            Arch::X86_64 => "x86_64".to_string(),
            Arch::Other(s) => s.clone(),
        };
        let plat = match &self.platform {
            Platform::MacOs => "macos".to_string(),
            Platform::Ios => "ios".to_string(),
            Platform::WatchOs => "watchos".to_string(),
            Platform::TvOs => "tvos".to_string(),
            Platform::DriverKit => "driverkit".to_string(),
            Platform::MacCatalyst => "maccatalyst".to_string(),
            Platform::Other(s) => s.clone(),
        };
        format!("{arch}-{plat}")
    }

    /// Apple SDK TBDs sometimes scope umbrella documents to `arm64e-macos`
    /// only even though the same symbols are consumable by plain `arm64`
    /// linkers on Apple Silicon. Treat that as compatible for our arm64-only
    /// linker, while still requiring the platform to match exactly.
    pub fn matches_requested(&self, wanted: &Target) -> bool {
        if self.platform != wanted.platform {
            return false;
        }
        self.arch == wanted.arch
            || matches!((&self.arch, &wanted.arch), (Arch::Arm64e, Arch::Arm64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_tbd_v4() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets: [ arm64-macos ]\n\
                   install-name: '/usr/lib/libfoo.dylib'\n\
                   ...\n";
        let docs = parse_tbd(src).unwrap();
        assert_eq!(docs.len(), 1);
        let tbd = &docs[0];
        assert_eq!(tbd.version, 4);
        assert_eq!(
            tbd.targets,
            vec![Target {
                arch: Arch::Arm64,
                platform: Platform::MacOs,
            }]
        );
        assert_eq!(tbd.install_name, "/usr/lib/libfoo.dylib");
    }

    #[test]
    fn parses_scoped_exports_with_multiple_lists() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets: [ arm64-macos, x86_64-macos ]\n\
                   install-name: '/usr/lib/libfoo.dylib'\n\
                   exports:\n\
                   \x20 - targets: [ arm64-macos ]\n\
                   \x20   symbols: [ _a, _b, _c ]\n\
                   \x20   weak-symbols: [ _weak_one ]\n\
                   \x20   objc-classes: [ _OBJC_CLASS_$_Foo ]\n";
        let tbd = &parse_tbd(src).unwrap()[0];
        assert_eq!(tbd.exports.len(), 1);
        let scoped = &tbd.exports[0];
        assert_eq!(
            scoped.targets,
            vec![Target {
                arch: Arch::Arm64,
                platform: Platform::MacOs,
            }]
        );
        assert_eq!(scoped.value.symbols, vec!["_a", "_b", "_c"]);
        assert_eq!(scoped.value.weak_symbols, vec!["_weak_one"]);
        assert_eq!(scoped.value.objc_classes, vec!["_OBJC_CLASS_$_Foo"]);
        assert_eq!(scoped.value.total(), 5);
    }

    #[test]
    fn parses_reexported_libraries() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets: [ arm64-macos ]\n\
                   install-name: '/usr/lib/libSystem.B.dylib'\n\
                   reexported-libraries:\n\
                   \x20 - targets: [ arm64-macos ]\n\
                   \x20   libraries: [ '/usr/lib/system/libcache.dylib', '/usr/lib/system/libxpc.dylib' ]\n";
        let tbd = &parse_tbd(src).unwrap()[0];
        assert_eq!(tbd.reexported_libraries.len(), 1);
        assert_eq!(
            tbd.reexported_libraries[0].value,
            vec!["/usr/lib/system/libcache.dylib", "/usr/lib/system/libxpc.dylib"]
        );
    }

    #[test]
    fn parses_parent_umbrella() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets: [ arm64-macos ]\n\
                   install-name: '/usr/lib/system/libcache.dylib'\n\
                   parent-umbrella:\n\
                   \x20 - targets: [ arm64-macos ]\n\
                   \x20   umbrella: System\n";
        let tbd = &parse_tbd(src).unwrap()[0];
        assert_eq!(tbd.parent_umbrella.len(), 1);
        assert_eq!(tbd.parent_umbrella[0].value, "System");
    }

    #[test]
    fn unknown_keys_are_tolerated() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets: [ arm64-macos ]\n\
                   install-name: 'x'\n\
                   future-key: [ a, b ]\n";
        let tbd = &parse_tbd(src).unwrap()[0];
        assert_eq!(tbd.version, 4);
    }

    #[test]
    fn target_as_string_roundtrip() {
        let t = Target {
            arch: Arch::Arm64e,
            platform: Platform::MacCatalyst,
        };
        assert_eq!(t.as_string(), "arm64e-maccatalyst");
    }

    #[test]
    fn arm64_request_accepts_arm64e_scope() {
        let scoped = Target {
            arch: Arch::Arm64e,
            platform: Platform::MacOs,
        };
        let wanted = Target {
            arch: Arch::Arm64,
            platform: Platform::MacOs,
        };
        assert!(scoped.matches_requested(&wanted));
    }

    #[test]
    fn arm64_request_still_rejects_wrong_platform() {
        let scoped = Target {
            arch: Arch::Arm64e,
            platform: Platform::MacCatalyst,
        };
        let wanted = Target {
            arch: Arch::Arm64,
            platform: Platform::MacOs,
        };
        assert!(!scoped.matches_requested(&wanted));
    }

    #[test]
    fn parse_version_packs_major_dot_minor_dot_patch() {
        assert_eq!(parse_version("1.2.3"), (1 << 16) | (2 << 8) | 3);
        assert_eq!(parse_version("11"), 11 << 16);
        assert_eq!(parse_version("14.0"), 14 << 16);
        assert_eq!(parse_version("1351"), 1351 << 16);
    }

    #[test]
    fn missing_required_key_errors() {
        let src = "--- !tapi-tbd\ntbd-version: 4\n";
        let err = parse_tbd(src).unwrap_err();
        assert!(format!("{err}").contains("install-name") || format!("{err}").contains("targets"));
    }

    #[test]
    fn parses_libsystem_like_shape() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets:         [ x86_64-macos, arm64-macos, arm64e-macos ]\n\
                   install-name:    '/usr/lib/libSystem.B.dylib'\n\
                   current-version: 1351\n\
                   reexported-libraries:\n\
                   \x20 - targets:         [ arm64-macos, x86_64-macos ]\n\
                   \x20   libraries:       [ '/usr/lib/system/libcache.dylib',\n\
                   \x20                      '/usr/lib/system/libxpc.dylib' ]\n\
                   exports:\n\
                   \x20 - targets:         [ arm64-macos, x86_64-macos ]\n\
                   \x20   symbols:         [ _dyld_stub_binder, _malloc, _free,\n\
                   \x20                      _printf, _fprintf ]\n\
                   ...\n";
        let tbd = &parse_tbd(src).unwrap()[0];
        assert_eq!(tbd.install_name, "/usr/lib/libSystem.B.dylib");
        assert_eq!(tbd.current_version.as_deref(), Some("1351"));
        assert_eq!(tbd.exports[0].value.symbols.len(), 5);
    }
}
