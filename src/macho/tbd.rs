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
    /// Mach-O `0xMMMMmmpp` packed versions, validated while decoding.
    pub current_version: Option<u32>,
    pub compatibility_version: Option<u32>,
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
        out.push(decode_document(d)?);
    }
    Ok(out)
}

/// Parse a TBD for the linker hot path, keeping only documents and scoped
/// symbol lists that can satisfy `target`.
///
/// The fast path handles Apple's emitted TAPI v4 shape directly and avoids
/// constructing the generic YAML `Value` tree for the thousands of symbols in
/// libSystem.tbd. If it sees a shape outside that subset, it falls back to the
/// generic decoder and applies the same target filter afterward.
pub fn parse_tbd_for_target(input: &str, target: &Target) -> Result<Vec<Tbd>, TbdError> {
    match parse_tbd_for_target_direct(input, target, true) {
        Ok(docs) => Ok(docs),
        Err(_) => {
            let docs = parse_tbd(input)?;
            Ok(filter_docs_for_target(docs, target))
        }
    }
}

/// Parse only load-command-relevant TBD metadata for `target`.
///
/// This is used for links that have no unresolved dylib symbols; emitting the
/// requested `LC_LOAD_DYLIB` does not require materializing libSystem's full
/// export surface.
pub fn parse_tbd_metadata_for_target(input: &str, target: &Target) -> Result<Vec<Tbd>, TbdError> {
    match parse_tbd_for_target_direct(input, target, false) {
        Ok(docs) => Ok(docs),
        Err(_) => {
            let docs = parse_tbd(input)?;
            Ok(filter_docs_for_target_metadata(docs, target))
        }
    }
}

fn filter_docs_for_target(mut docs: Vec<Tbd>, target: &Target) -> Vec<Tbd> {
    docs.retain(|doc| targets_match(&doc.targets, target));
    for doc in &mut docs {
        doc.parent_umbrella
            .retain(|scoped| targets_match(&scoped.targets, target));
        doc.allowable_clients
            .retain(|scoped| targets_match(&scoped.targets, target));
        doc.reexported_libraries
            .retain(|scoped| targets_match(&scoped.targets, target));
        doc.exports
            .retain(|scoped| targets_match(&scoped.targets, target));
        doc.reexports
            .retain(|scoped| targets_match(&scoped.targets, target));
    }
    docs
}

fn filter_docs_for_target_metadata(docs: Vec<Tbd>, target: &Target) -> Vec<Tbd> {
    let mut docs = filter_docs_for_target(docs, target);
    for doc in &mut docs {
        doc.reexported_libraries.clear();
        doc.exports.clear();
        doc.reexports.clear();
    }
    docs
}

fn parse_tbd_for_target_direct(
    input: &str,
    target: &Target,
    include_exports: bool,
) -> Result<Vec<Tbd>, TbdError> {
    let lines: Vec<&str> = input.lines().collect();
    let mut docs = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let Some(trimmed) = direct_trimmed(lines[i]) else {
            i += 1;
            continue;
        };
        if trimmed.starts_with("%YAML") || trimmed.starts_with("...") {
            i += 1;
            continue;
        }
        if trimmed.starts_with("---") {
            i += 1;
        }

        let (doc, next) = parse_direct_document(&lines, i, target, include_exports)?;
        i = next;
        if doc.install_name.is_empty() && doc.targets.is_empty() {
            continue;
        }
        if targets_match(&doc.targets, target) {
            docs.push(doc);
        }
    }
    Ok(docs)
}

fn parse_direct_document(
    lines: &[&str],
    mut i: usize,
    target: &Target,
    include_exports: bool,
) -> Result<(Tbd, usize), TbdError> {
    let mut tbd = Tbd::default();
    while i < lines.len() {
        let Some(trimmed) = direct_trimmed(lines[i]) else {
            i += 1;
            continue;
        };
        if trimmed.starts_with("---") || trimmed.starts_with("...") {
            break;
        }
        if direct_indent(lines[i]) != 0 {
            return Err(schema("unexpected nested TBD line at document root"));
        }
        let (key, rest) =
            direct_key_value(trimmed).ok_or_else(|| schema("expected top-level TBD key"))?;
        match key {
            "tbd-version" => {
                tbd.version = parse_direct_scalar(rest)
                    .parse()
                    .map_err(|_| schema(&format!("tbd-version must parse as a u32: {rest:?}")))?;
                i += 1;
            }
            "targets" => {
                let (targets, next) = parse_direct_targets(lines, i, rest)?;
                tbd.targets = targets;
                i = next;
            }
            "install-name" => {
                tbd.install_name = parse_direct_scalar(rest);
                i += 1;
            }
            "current-version" => {
                let value = parse_direct_scalar(rest);
                tbd.current_version = Some(parse_version_field(&value, "current-version")?);
                i += 1;
            }
            "compatibility-version" => {
                let value = parse_direct_scalar(rest);
                tbd.compatibility_version =
                    Some(parse_version_field(&value, "compatibility-version")?);
                i += 1;
            }
            "parent-umbrella" => {
                let (value, next) = parse_direct_scoped_scalars(lines, i + 1, target, "umbrella")?;
                tbd.parent_umbrella = value;
                i = next;
            }
            "allowable-clients" => {
                let (value, next) = parse_direct_scoped_lists(lines, i + 1, target, "clients")?;
                tbd.allowable_clients = value;
                i = next;
            }
            "reexported-libraries" if include_exports => {
                let (value, next) = parse_direct_scoped_lists(lines, i + 1, target, "libraries")?;
                tbd.reexported_libraries = value;
                i = next;
            }
            "reexported-libraries" => {
                i = skip_direct_value(lines, i + 1);
            }
            "exports" if include_exports => {
                let (value, next) = parse_direct_scoped_symbols(lines, i + 1, target)?;
                tbd.exports = value;
                i = next;
            }
            "exports" => {
                i = skip_direct_value(lines, i + 1);
            }
            "reexports" if include_exports => {
                let (value, next) = parse_direct_scoped_symbols(lines, i + 1, target)?;
                tbd.reexports = value;
                i = next;
            }
            "reexports" => {
                i = skip_direct_value(lines, i + 1);
            }
            _ => {
                i = skip_direct_value(lines, i + 1);
            }
        }
    }

    if !tbd.install_name.is_empty() || !tbd.targets.is_empty() {
        if tbd.install_name.is_empty() {
            return Err(schema("TBD document missing required 'install-name'"));
        }
        if tbd.targets.is_empty() {
            return Err(schema("TBD document missing required 'targets'"));
        }
    }
    Ok((tbd, i))
}

fn parse_direct_scoped_scalars(
    lines: &[&str],
    mut i: usize,
    target: &Target,
    value_key: &str,
) -> Result<(Vec<Scoped<String>>, usize), TbdError> {
    let mut out = Vec::new();
    let ctx = DirectCtx { lines, target };
    while let Some(entry) = direct_entry_start(lines, i) {
        let mut state = DirectScopeState::default();
        let mut value = None;
        let (key, rest) = entry?;
        apply_direct_scalar_pair((key, rest), ctx, &mut i, &mut state, value_key, &mut value)?;
        while let Some((key, rest)) = direct_nested_pair(lines, i) {
            apply_direct_scalar_pair((key, rest), ctx, &mut i, &mut state, value_key, &mut value)?;
        }
        if state.include == Some(true) {
            out.push(Scoped {
                targets: state
                    .targets
                    .ok_or_else(|| schema("missing required key \"targets\""))?,
                value: value.unwrap_or_default(),
            });
        }
    }
    Ok((out, i))
}

type DirectScopedList = Vec<Scoped<Vec<String>>>;
type DirectScopedListResult = Result<(DirectScopedList, usize), TbdError>;

#[derive(Clone, Copy)]
struct DirectCtx<'a, 't> {
    lines: &'a [&'a str],
    target: &'t Target,
}

#[derive(Default)]
struct DirectScopeState {
    targets: Option<Vec<Target>>,
    include: Option<bool>,
}

fn parse_direct_scoped_lists(
    lines: &[&str],
    mut i: usize,
    target: &Target,
    value_key: &str,
) -> DirectScopedListResult {
    let mut out = Vec::new();
    let ctx = DirectCtx { lines, target };
    while let Some(entry) = direct_entry_start(lines, i) {
        let mut state = DirectScopeState::default();
        let mut value = Vec::new();
        let (key, rest) = entry?;
        apply_direct_list_pair((key, rest), ctx, &mut i, &mut state, value_key, &mut value)?;
        while let Some((key, rest)) = direct_nested_pair(lines, i) {
            apply_direct_list_pair((key, rest), ctx, &mut i, &mut state, value_key, &mut value)?;
        }
        if state.include == Some(true) {
            out.push(Scoped {
                targets: state
                    .targets
                    .ok_or_else(|| schema("missing required key \"targets\""))?,
                value,
            });
        }
    }
    Ok((out, i))
}

fn parse_direct_scoped_symbols(
    lines: &[&str],
    mut i: usize,
    target: &Target,
) -> Result<(Vec<Scoped<SymbolLists>>, usize), TbdError> {
    let mut out = Vec::new();
    let ctx = DirectCtx { lines, target };
    while let Some(entry) = direct_entry_start(lines, i) {
        let mut state = DirectScopeState::default();
        let mut lists = SymbolLists::default();
        let (key, rest) = entry?;
        apply_direct_symbol_pair((key, rest), ctx, &mut i, &mut state, &mut lists)?;
        while let Some((key, rest)) = direct_nested_pair(lines, i) {
            apply_direct_symbol_pair((key, rest), ctx, &mut i, &mut state, &mut lists)?;
        }
        if state.include == Some(true) {
            out.push(Scoped {
                targets: state
                    .targets
                    .ok_or_else(|| schema("missing required key \"targets\""))?,
                value: lists,
            });
        }
    }
    Ok((out, i))
}

fn apply_direct_scalar_pair(
    pair: (&str, &str),
    ctx: DirectCtx<'_, '_>,
    i: &mut usize,
    state: &mut DirectScopeState,
    value_key: &str,
    value: &mut Option<String>,
) -> Result<(), TbdError> {
    let (key, rest) = pair;
    if key == "targets" {
        let (parsed, next) = parse_direct_targets(ctx.lines, *i, rest)?;
        state.include = Some(targets_match(&parsed, ctx.target));
        state.targets = Some(parsed);
        *i = next;
    } else if key == value_key {
        if state.include != Some(false) {
            *value = Some(parse_direct_scalar(rest));
        }
        *i += 1;
    } else {
        *i = skip_direct_inline_value(ctx.lines, *i, rest)?;
    }
    Ok(())
}

fn apply_direct_list_pair(
    pair: (&str, &str),
    ctx: DirectCtx<'_, '_>,
    i: &mut usize,
    state: &mut DirectScopeState,
    value_key: &str,
    value: &mut Vec<String>,
) -> Result<(), TbdError> {
    let (key, rest) = pair;
    if key == "targets" {
        let (parsed, next) = parse_direct_targets(ctx.lines, *i, rest)?;
        state.include = Some(targets_match(&parsed, ctx.target));
        state.targets = Some(parsed);
        *i = next;
    } else if key == value_key {
        if state.include == Some(false) {
            *i = skip_direct_flow(ctx.lines, *i, rest)?;
        } else {
            let (parsed, next) = parse_direct_string_list(ctx.lines, *i, rest)?;
            *value = parsed;
            *i = next;
        }
    } else {
        *i = skip_direct_inline_value(ctx.lines, *i, rest)?;
    }
    Ok(())
}

fn apply_direct_symbol_pair(
    pair: (&str, &str),
    ctx: DirectCtx<'_, '_>,
    i: &mut usize,
    state: &mut DirectScopeState,
    lists: &mut SymbolLists,
) -> Result<(), TbdError> {
    let (key, rest) = pair;
    if key == "targets" {
        let (parsed, next) = parse_direct_targets(ctx.lines, *i, rest)?;
        state.include = Some(targets_match(&parsed, ctx.target));
        state.targets = Some(parsed);
        *i = next;
        return Ok(());
    }

    let slot = match key {
        "symbols" => Some(&mut lists.symbols),
        "weak-symbols" => Some(&mut lists.weak_symbols),
        "thread-local-symbols" => Some(&mut lists.thread_local_symbols),
        "objc-classes" => Some(&mut lists.objc_classes),
        "objc-eh-types" => Some(&mut lists.objc_eh_types),
        "objc-ivars" => Some(&mut lists.objc_ivars),
        _ => None,
    };
    if let Some(slot) = slot {
        if state.include == Some(false) {
            *i = skip_direct_flow(ctx.lines, *i, rest)?;
        } else {
            let (parsed, next) = parse_direct_string_list(ctx.lines, *i, rest)?;
            *slot = parsed;
            *i = next;
        }
    } else {
        *i = skip_direct_inline_value(ctx.lines, *i, rest)?;
    }
    Ok(())
}

type DirectEntry<'a> = Result<(&'a str, &'a str), TbdError>;

fn direct_entry_start<'a>(lines: &'a [&str], i: usize) -> Option<DirectEntry<'a>> {
    let trimmed = direct_trimmed(lines.get(i)?)?;
    if trimmed.starts_with("---") || trimmed.starts_with("...") || direct_indent(lines[i]) == 0 {
        return None;
    }
    if direct_indent(lines[i]) != 2 || !trimmed.starts_with('-') {
        return Some(Err(schema("expected scoped TBD entry")));
    }
    let rest = trimmed.strip_prefix('-').unwrap_or("").trim_start();
    if rest.is_empty() {
        return Some(Err(schema("empty scoped TBD entries are not supported")));
    }
    Some(direct_key_value(rest).ok_or_else(|| schema("expected scoped TBD key")))
}

fn direct_nested_pair<'a>(lines: &'a [&str], i: usize) -> Option<(&'a str, &'a str)> {
    let trimmed = direct_trimmed(lines.get(i)?)?;
    if trimmed.starts_with("---") || trimmed.starts_with("...") {
        return None;
    }
    let indent = direct_indent(lines[i]);
    if indent <= 2 {
        return None;
    }
    direct_key_value(trimmed)
}

fn parse_direct_targets(
    lines: &[&str],
    i: usize,
    rest: &str,
) -> Result<(Vec<Target>, usize), TbdError> {
    let (items, next) = parse_direct_string_list(lines, i, rest)?;
    let mut targets = Vec::with_capacity(items.len());
    for item in items {
        targets.push(parse_target(&item)?);
    }
    Ok((targets, next))
}

fn parse_direct_string_list(
    lines: &[&str],
    i: usize,
    rest: &str,
) -> Result<(Vec<String>, usize), TbdError> {
    let (flow, next) = collect_direct_flow(lines, i, rest)?;
    Ok((split_direct_flow_scalars(&flow)?, next))
}

fn collect_direct_flow(lines: &[&str], i: usize, rest: &str) -> Result<(String, usize), TbdError> {
    let (flow, next) = consume_direct_flow(lines, i, rest, true)?;
    Ok((
        flow.expect("collecting a direct flow must produce text"),
        next,
    ))
}

fn skip_direct_flow(lines: &[&str], i: usize, rest: &str) -> Result<usize, TbdError> {
    consume_direct_flow(lines, i, rest, false).map(|(_, next)| next)
}

fn consume_direct_flow(
    lines: &[&str],
    i: usize,
    rest: &str,
    collect: bool,
) -> Result<(Option<String>, usize), TbdError> {
    let start_line = i + 1;
    let rest = rest.trim();
    if !rest.starts_with('[') {
        return Err(schema("expected a flow sequence"));
    }
    let mut flow = collect.then(|| rest.to_string());
    let mut balance = DirectFlowBalance::default();
    balance.scan(rest);
    let mut ends_with_close = rest.ends_with(']');
    let mut next_i = if direct_trimmed(lines.get(i).copied().unwrap_or_default())
        .map(|line| line.contains(rest))
        .unwrap_or(false)
    {
        i + 1
    } else {
        i
    };
    while balance.is_unbalanced() {
        let Some(next) = lines.get(next_i).and_then(|line| direct_trimmed(line)) else {
            return Err(schema(&format!(
                "unterminated flow sequence from line {} near line {}: {:?}",
                start_line,
                next_i + 1,
                flow.as_deref().unwrap_or(rest)
            )));
        };
        if next.starts_with("---") || next.starts_with("...") {
            return Err(schema(&format!(
                "unterminated flow sequence from line {} before line {}: {:?}",
                start_line,
                next_i + 1,
                flow.as_deref().unwrap_or(rest)
            )));
        }
        balance.scan(" ");
        balance.scan(next);
        if let Some(flow) = &mut flow {
            flow.push(' ');
            flow.push_str(next);
        }
        ends_with_close = next.ends_with(']');
        next_i += 1;
    }
    if !ends_with_close {
        return Err(schema("flow sequence must end with ']'"));
    }
    Ok((flow, next_i))
}

#[derive(Default)]
struct DirectFlowBalance {
    depth: i32,
    in_single: bool,
    in_double: bool,
    escape_next: bool,
}

impl DirectFlowBalance {
    fn scan(&mut self, fragment: &str) {
        for byte in fragment.bytes() {
            if self.escape_next {
                self.escape_next = false;
                continue;
            }
            match byte {
                b'\\' if self.in_double => self.escape_next = true,
                b'\'' if !self.in_double => self.in_single = !self.in_single,
                b'"' if !self.in_single => self.in_double = !self.in_double,
                b'[' | b'{' if !self.in_single && !self.in_double => self.depth += 1,
                b']' | b'}' if !self.in_single && !self.in_double => self.depth -= 1,
                _ => {}
            }
        }
    }

    fn is_unbalanced(&self) -> bool {
        self.depth != 0
    }
}

fn skip_direct_inline_value(lines: &[&str], i: usize, rest: &str) -> Result<usize, TbdError> {
    if rest.trim_start().starts_with('[') {
        skip_direct_flow(lines, i, rest)
    } else {
        Ok(i + 1)
    }
}

fn skip_direct_value(lines: &[&str], mut i: usize) -> usize {
    while i < lines.len() {
        let Some(trimmed) = direct_trimmed(lines[i]) else {
            i += 1;
            continue;
        };
        if trimmed.starts_with("---") || trimmed.starts_with("...") || direct_indent(lines[i]) == 0
        {
            break;
        }
        i += 1;
    }
    i
}

fn split_direct_flow_scalars(flow: &str) -> Result<Vec<String>, TbdError> {
    let inner = flow
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| schema("flow sequence must be bracketed"))?;
    let bytes = inner.as_bytes();
    let mut out = Vec::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'\\' if in_double && i + 1 < bytes.len() => {
                i += 2;
                continue;
            }
            b'[' | b'{' if !in_single && !in_double => depth += 1,
            b']' | b'}' if !in_single && !in_double => depth -= 1,
            b',' if !in_single && !in_double && depth == 0 => {
                push_direct_flow_scalar(&mut out, &inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start <= inner.len() {
        push_direct_flow_scalar(&mut out, &inner[start..]);
    }
    Ok(out)
}

fn push_direct_flow_scalar(out: &mut Vec<String>, item: &str) {
    let item = item.trim();
    if !item.is_empty() {
        out.push(parse_direct_scalar(item));
    }
}

fn parse_direct_scalar(raw: &str) -> String {
    let raw = raw.trim();
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        raw[1..raw.len() - 1].replace("''", "'")
    } else if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        parse_direct_double_quoted(&raw[1..raw.len() - 1])
    } else {
        raw.to_string()
    }
}

fn parse_direct_double_quoted(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let Some(escaped) = chars.next() else {
                out.push(ch);
                break;
            };
            out.push(match escaped {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '"' => '"',
                '\\' => '\\',
                other => other,
            });
        } else {
            out.push(ch);
        }
    }
    out
}

fn direct_key_value(s: &str) -> Option<(&str, &str)> {
    let (key, rest) = s.split_once(':')?;
    Some((key.trim(), rest.trim_start()))
}

fn direct_trimmed(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        None
    } else {
        Some(trimmed)
    }
}

fn direct_indent(line: &str) -> usize {
    line.bytes().take_while(|b| *b == b' ').count()
}

fn targets_match(targets: &[Target], target: &Target) -> bool {
    targets.iter().any(|t| t.matches_requested(target))
}

fn decode_document(doc: Document) -> Result<Tbd, TbdError> {
    let Value::Mapping(m) = doc.root else {
        return Err(schema("top level of a TBD document must be a mapping"));
    };
    let mut tbd = Tbd::default();
    for (k, v) in m {
        match k.as_str() {
            "tbd-version" => tbd.version = scalar_u32(v, "tbd-version")?,
            "targets" => tbd.targets = decode_target_list(v)?,
            "install-name" => tbd.install_name = scalar_string(v, "install-name")?,
            "current-version" => {
                tbd.current_version = Some(scalar_packed_version(v, "current-version")?)
            }
            "compatibility-version" => {
                tbd.compatibility_version = Some(scalar_packed_version(v, "compatibility-version")?)
            }
            "parent-umbrella" => tbd.parent_umbrella = decode_scoped_umbrella(v)?,
            "allowable-clients" => tbd.allowable_clients = decode_scoped_string_list(v, "clients")?,
            "reexported-libraries" => {
                tbd.reexported_libraries = decode_scoped_string_list(v, "libraries")?;
            }
            "exports" => tbd.exports = decode_scoped_symbols(v)?,
            "reexports" => tbd.reexports = decode_scoped_symbols(v)?,
            // Known-but-ignored keys (grow this list as TAPI adds them).
            "uuids" | "flags" | "swift-abi-version" | "rpaths" | "objc-constraint"
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

fn decode_target_list(v: Value) -> Result<Vec<Target>, TbdError> {
    let Value::Sequence(seq) = v else {
        return Err(schema("'targets' must be a sequence"));
    };
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        out.push(parse_target(&scalar_string(item, "target")?)?);
    }
    Ok(out)
}

fn parse_target(s: &str) -> Result<Target, TbdError> {
    // `arch-platform`. Arch may contain a hyphen (none today, but armv7k
    // in the wild) — split on the *last* `-`.
    let hyphen = s
        .rfind('-')
        .ok_or_else(|| schema(&format!("target {s:?} is not `arch-platform`")))?;
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

fn decode_scoped_umbrella(v: Value) -> Result<Vec<Scoped<String>>, TbdError> {
    let Value::Sequence(seq) = v else {
        return Err(schema(
            "'parent-umbrella' must be a sequence of scoped mappings",
        ));
    };
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let Value::Mapping(m) = item else {
            return Err(schema("parent-umbrella entry must be a mapping"));
        };
        let mut targets = None;
        let mut umbrella = None;
        for (k, v) in m {
            match k.as_str() {
                "targets" => targets = Some(decode_target_list(v)?),
                "umbrella" => umbrella = Some(scalar_string(v, "umbrella")?),
                _ => {}
            }
        }
        let targets = targets.ok_or_else(|| schema("missing required key \"targets\""))?;
        let umbrella = umbrella.ok_or_else(|| schema("missing required key \"umbrella\""))?;
        out.push(Scoped {
            targets,
            value: umbrella,
        });
    }
    Ok(out)
}

fn decode_scoped_string_list(
    v: Value,
    inner_key: &str,
) -> Result<Vec<Scoped<Vec<String>>>, TbdError> {
    let Value::Sequence(seq) = v else {
        return Err(schema("expected a sequence of scoped mappings"));
    };
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let Value::Mapping(m) = item else {
            return Err(schema("scoped entry must be a mapping"));
        };
        let mut targets = None;
        let mut value = Vec::new();
        for (k, v) in m {
            if k == "targets" {
                targets = Some(decode_target_list(v)?);
            } else if k == inner_key {
                value = decode_string_list(v, inner_key)?;
            }
        }
        let targets = targets.ok_or_else(|| schema("missing required key \"targets\""))?;
        out.push(Scoped { targets, value });
    }
    Ok(out)
}

fn decode_scoped_symbols(v: Value) -> Result<Vec<Scoped<SymbolLists>>, TbdError> {
    let Value::Sequence(seq) = v else {
        return Err(schema("'exports'/'reexports' must be a sequence"));
    };
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let Value::Mapping(m) = item else {
            return Err(schema("exports entry must be a mapping"));
        };
        let mut targets = None;
        let mut lists = SymbolLists::default();
        for (k, v) in m {
            match k.as_str() {
                "targets" => targets = Some(decode_target_list(v)?),
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
        let targets = targets.ok_or_else(|| schema("missing required key \"targets\""))?;
        out.push(Scoped {
            targets,
            value: lists,
        });
    }
    Ok(out)
}

fn decode_string_list(v: Value, context: &str) -> Result<Vec<String>, TbdError> {
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

fn scalar_u32(v: Value, context: &str) -> Result<u32, TbdError> {
    let s = scalar_string(v, context)?;
    s.parse()
        .map_err(|_| schema(&format!("{context} must parse as a u32: {s:?}")))
}

fn scalar_packed_version(v: Value, context: &str) -> Result<u32, TbdError> {
    let value = scalar_string(v, context)?;
    parse_version_field(&value, context)
}

fn scalar_string(v: Value, context: &str) -> Result<String, TbdError> {
    match v {
        Value::Scalar(s) => Ok(s),
        _ => Err(schema(&format!("{context} must be a scalar"))),
    }
}

fn schema(msg: &str) -> TbdError {
    TbdError::Schema {
        msg: msg.to_string(),
    }
}

/// Parse one to three decimal components into Mach-O's `0xMMMMmmpp`
/// packed-version representation.
pub fn parse_version(s: &str) -> Result<u32, TbdError> {
    parse_version_field(s, "version")
}

fn parse_version_field(s: &str, context: &str) -> Result<u32, TbdError> {
    let mut parts = s.split('.');
    let major = parse_version_part(parts.next().unwrap_or_default(), u16::MAX.into())
        .ok_or_else(|| invalid_packed_version(context, s))?;
    let minor = match parts.next() {
        Some(part) => parse_version_part(part, u8::MAX.into())
            .ok_or_else(|| invalid_packed_version(context, s))?,
        None => 0,
    };
    let patch = match parts.next() {
        Some(part) => parse_version_part(part, u8::MAX.into())
            .ok_or_else(|| invalid_packed_version(context, s))?,
        None => 0,
    };
    if parts.next().is_some() {
        return Err(invalid_packed_version(context, s));
    }
    Ok((major << 16) | (minor << 8) | patch)
}

fn invalid_packed_version(context: &str, value: &str) -> TbdError {
    schema(&format!(
        "{context} must be 1 to 3 decimal components with major <= 65535 and minor/patch <= 255: {value:?}"
    ))
}

fn parse_version_part(part: &str, maximum: u32) -> Option<u32> {
    if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value = part.parse::<u32>().ok()?;
    (value <= maximum).then_some(value)
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

    fn arm64_macos() -> Target {
        Target {
            arch: Arch::Arm64,
            platform: Platform::MacOs,
        }
    }

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
            vec![
                "/usr/lib/system/libcache.dylib",
                "/usr/lib/system/libxpc.dylib"
            ]
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
    fn target_fast_path_keeps_matching_multiline_exports() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets: [ x86_64-macos, arm64e-macos ]\n\
                   install-name: '/usr/lib/libfoo.dylib'\n\
                   exports:\n\
                   \x20 - targets: [ x86_64-macos ]\n\
                   \x20   symbols: [ _x86_only ]\n\
                   \x20 - targets: [ x86_64-macos, arm64e-macos ]\n\
                   \x20   symbols: [ _arm_one,\n\
                   \x20              _arm_two ]\n";
        let docs = parse_tbd_for_target(src, &arm64_macos()).unwrap();
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].exports.len(), 1);
        assert_eq!(docs[0].exports[0].value.symbols, ["_arm_one", "_arm_two"]);
    }

    #[test]
    fn target_fast_path_scans_large_multiline_exports_once() {
        let mut src = String::from(
            "--- !tapi-tbd\n\
             tbd-version: 4\n\
             targets: [ arm64-macos ]\n\
             install-name: '/usr/lib/liblarge.dylib'\n\
             exports:\n\
             \x20 - targets: [ x86_64-macos ]\n\
             \x20   symbols: [\n",
        );
        for symbol in 0..4096 {
            src.push_str(&format!("    '_x86_symbol_{symbol}[quoted]',\n"));
        }
        src.push_str(
            "    _x86_last_symbol ]\n\
             \x20 - targets: [ arm64-macos ]\n\
             \x20   symbols: [\n",
        );
        for symbol in 0..4096 {
            src.push_str(&format!("    '_symbol_{symbol}[quoted]',\n"));
        }
        src.push_str("    _last_symbol ]\n");

        let docs = parse_tbd_for_target_direct(&src, &arm64_macos(), true).unwrap();
        assert_eq!(docs.len(), 1);
        let symbols = &docs[0].exports[0].value.symbols;
        assert_eq!(symbols.len(), 4097);
        assert_eq!(symbols[0], "_symbol_0[quoted]");
        assert_eq!(symbols[4095], "_symbol_4095[quoted]");
        assert_eq!(symbols[4096], "_last_symbol");
    }

    #[test]
    fn direct_flow_balance_carries_escapes_between_fragments() {
        let mut balance = DirectFlowBalance::default();
        balance.scan("[ \"_quoted");
        balance.scan("\\");
        balance.scan(" ");
        balance.scan("_continued\", _tail ]");
        assert!(!balance.is_unbalanced());
    }

    #[test]
    fn target_fast_path_preserves_utf8_in_double_quoted_scalars() {
        let src = r#"--- !tapi-tbd
tbd-version: 4
targets: [ arm64-macos ]
install-name: "/usr/lib/libcafé.dylib"
exports:
  - targets: [ arm64-macos ]
    symbols: [ "_café", "_snowman_☃", "_crab_🦀", "_escaped_\t_é" ]
...
"#;

        let generic = filter_docs_for_target(parse_tbd(src).unwrap(), &arm64_macos());
        let direct = parse_tbd_for_target_direct(src, &arm64_macos(), true).unwrap();

        assert_eq!(direct, generic);
        assert_eq!(direct[0].install_name, "/usr/lib/libcafé.dylib");
        assert_eq!(
            direct[0].exports[0].value.symbols,
            ["_café", "_snowman_☃", "_crab_🦀", "_escaped_\t_é"]
        );
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
    fn all_tbd_decoders_reject_malformed_packed_versions() {
        let cases = [
            ("empty", ""),
            ("nondigit", "1.x.3"),
            ("leading-empty-component", ".1"),
            ("middle-empty-component", "1..3"),
            ("trailing-empty-component", "1."),
            ("extra-component", "1.2.3.4"),
            ("major-overflow", "65536"),
            ("minor-overflow", "1.256"),
            ("patch-overflow", "1.2.256"),
            ("integer-overflow", "4294967296"),
        ];

        for field in ["current-version", "compatibility-version"] {
            for (case, value) in cases {
                let src = format!(
                    "--- !tapi-tbd\n\
                     tbd-version: 4\n\
                     targets: [ arm64-macos ]\n\
                     install-name: '/usr/lib/libbad.dylib'\n\
                     {field}: '{value}'\n\
                     ...\n"
                );
                let expected_value = format!("{value:?}");
                for (decoder, result) in [
                    ("generic", parse_tbd(&src)),
                    (
                        "direct",
                        parse_tbd_for_target_direct(&src, &arm64_macos(), true),
                    ),
                    ("target", parse_tbd_for_target(&src, &arm64_macos())),
                    (
                        "metadata",
                        parse_tbd_metadata_for_target(&src, &arm64_macos()),
                    ),
                ] {
                    let error = match result {
                        Ok(_) => panic!("{decoder} decoder accepted {case} {field} {value:?}"),
                        Err(error) => error,
                    };
                    let diagnostic = error.to_string();
                    assert!(
                        diagnostic.contains(field) && diagnostic.contains(&expected_value),
                        "{decoder} decoder returned an unhelpful {case} {field} diagnostic: {diagnostic}"
                    );
                }
            }
        }
    }

    #[test]
    fn parse_version_packs_major_dot_minor_dot_patch() {
        assert_eq!(parse_version("1.2.3").unwrap(), (1 << 16) | (2 << 8) | 3);
        assert_eq!(parse_version("11").unwrap(), 11 << 16);
        assert_eq!(parse_version("14.0").unwrap(), 14 << 16);
        assert_eq!(parse_version("1351").unwrap(), 1351 << 16);
        assert_eq!(parse_version("65535.255.255").unwrap(), u32::MAX);
    }

    #[test]
    fn parse_version_rejects_invalid_text_and_component_overflow() {
        for value in [
            "",
            "+1",
            " 1",
            "1 ",
            ".1",
            "1.",
            "1..3",
            "1.x.3",
            "1.2.3.4",
            "65536",
            "1.256",
            "1.2.256",
            "4294967296",
        ] {
            assert!(
                parse_version(value).is_err(),
                "accepted malformed packed version {value:?}"
            );
        }
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
        assert_eq!(tbd.current_version, Some(1351 << 16));
        assert_eq!(tbd.exports[0].value.symbols.len(), 5);
    }
}
