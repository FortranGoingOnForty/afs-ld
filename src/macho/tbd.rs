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

use std::borrow::Cow;
use std::collections::HashSet;

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
    match parse_tbd_for_target_direct(input, target, true, None) {
        Ok(docs) => Ok(docs),
        Err(_) => {
            let docs = parse_tbd(input)?;
            Ok(filter_docs_for_target(docs, target))
        }
    }
}

/// Parse a TBD for the linker hot path, keeping only target-compatible
/// exports whose linker-visible names are present in `names`.
pub fn parse_tbd_for_target_matching(
    input: &str,
    target: &Target,
    names: &HashSet<String>,
) -> Result<Vec<Tbd>, TbdError> {
    match parse_tbd_for_target_direct(input, target, true, Some(names)) {
        Ok(docs) => Ok(retain_metadata_and_matching_export_docs(docs)),
        Err(_) => {
            let docs = parse_tbd(input)?;
            Ok(retain_metadata_and_matching_export_docs(
                filter_docs_for_target_matching(docs, target, names),
            ))
        }
    }
}

/// Parse only load-command-relevant TBD metadata for `target`.
///
/// This is used for links that have no unresolved dylib symbols; emitting the
/// requested `LC_LOAD_DYLIB` does not require materializing libSystem's full
/// export surface.
pub fn parse_tbd_metadata_for_target(input: &str, target: &Target) -> Result<Vec<Tbd>, TbdError> {
    match parse_tbd_for_target_direct(input, target, false, None) {
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

fn filter_docs_for_target_matching(
    mut docs: Vec<Tbd>,
    target: &Target,
    names: &HashSet<String>,
) -> Vec<Tbd> {
    docs = filter_docs_for_target(docs, target);
    for doc in &mut docs {
        for scoped in &mut doc.exports {
            filter_symbol_lists_for_names(&mut scoped.value, names);
        }
        for scoped in &mut doc.reexports {
            filter_symbol_lists_for_names(&mut scoped.value, names);
        }
    }
    docs
}

fn retain_metadata_and_matching_export_docs(mut docs: Vec<Tbd>) -> Vec<Tbd> {
    let canonical_idx = docs
        .iter()
        .position(|doc| doc.parent_umbrella.is_empty())
        .unwrap_or(0);
    let mut idx = 0usize;
    docs.retain(|doc| {
        let keep = idx == canonical_idx
            || doc
                .exports
                .iter()
                .chain(doc.reexports.iter())
                .any(|scoped| !scoped.value.is_empty());
        idx += 1;
        keep
    });
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
    symbol_filter: Option<&HashSet<String>>,
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

        let (doc, next) = parse_direct_document(&lines, i, target, include_exports, symbol_filter)?;
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
    symbol_filter: Option<&HashSet<String>>,
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
                tbd.current_version = Some(parse_direct_scalar(rest));
                i += 1;
            }
            "compatibility-version" => {
                tbd.compatibility_version = Some(parse_direct_scalar(rest));
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
                let (value, next) =
                    parse_direct_scoped_symbols(lines, i + 1, target, symbol_filter)?;
                tbd.exports = value;
                i = next;
            }
            "exports" => {
                i = skip_direct_value(lines, i + 1);
            }
            "reexports" if include_exports => {
                let (value, next) =
                    parse_direct_scoped_symbols(lines, i + 1, target, symbol_filter)?;
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
    symbol_filter: Option<&HashSet<String>>,
) -> Result<(Vec<Scoped<SymbolLists>>, usize), TbdError> {
    let mut out = Vec::new();
    let ctx = DirectCtx { lines, target };
    while let Some(entry) = direct_entry_start(lines, i) {
        let mut state = DirectScopeState::default();
        let mut lists = SymbolLists::default();
        let (key, rest) = entry?;
        apply_direct_symbol_pair(
            (key, rest),
            ctx,
            &mut i,
            &mut state,
            &mut lists,
            symbol_filter,
        )?;
        while let Some((key, rest)) = direct_nested_pair(lines, i) {
            apply_direct_symbol_pair(
                (key, rest),
                ctx,
                &mut i,
                &mut state,
                &mut lists,
                symbol_filter,
            )?;
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
    symbol_filter: Option<&HashSet<String>>,
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
            let (parsed, next) = parse_direct_symbol_list(ctx.lines, *i, rest, key, symbol_filter)?;
            *slot = parsed;
            *i = next;
        }
    } else {
        *i = skip_direct_inline_value(ctx.lines, *i, rest)?;
    }
    Ok(())
}

fn parse_direct_symbol_list(
    lines: &[&str],
    i: usize,
    rest: &str,
    key: &str,
    symbol_filter: Option<&HashSet<String>>,
) -> Result<(Vec<String>, usize), TbdError> {
    let Some(symbol_filter) = symbol_filter else {
        return parse_direct_string_list(lines, i, rest);
    };
    parse_direct_symbol_list_matching(lines, i, rest, key, symbol_filter)
}

fn parse_direct_symbol_list_matching(
    lines: &[&str],
    i: usize,
    rest: &str,
    key: &str,
    symbol_filter: &HashSet<String>,
) -> Result<(Vec<String>, usize), TbdError> {
    let start_line = i + 1;
    let first = rest.trim();
    if !first.starts_with('[') {
        return Err(schema("expected a flow sequence"));
    }

    let mut out = Vec::new();
    let mut item = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut depth = 0i32;
    let mut line_idx = i;

    loop {
        let segment = if line_idx == i {
            first
        } else {
            let Some(segment) = lines.get(line_idx).and_then(|line| direct_trimmed(line)) else {
                return Err(schema(&format!(
                    "unterminated flow sequence from line {} near line {}",
                    start_line,
                    line_idx + 1
                )));
            };
            if segment.starts_with("---") || segment.starts_with("...") {
                return Err(schema(&format!(
                    "unterminated flow sequence from line {} before line {}",
                    start_line,
                    line_idx + 1
                )));
            }
            if depth > 0 && !item.is_empty() {
                item.push(' ');
            }
            segment
        };

        let bytes = segment.as_bytes();
        let mut j = 0usize;
        while j < bytes.len() {
            let b = bytes[j];
            match b {
                b'\'' if !in_double => {
                    in_single = !in_single;
                    if depth > 0 {
                        item.push(b as char);
                    }
                }
                b'"' if !in_single => {
                    in_double = !in_double;
                    if depth > 0 {
                        item.push(b as char);
                    }
                }
                b'\\' if in_double && j + 1 < bytes.len() => {
                    if depth > 0 {
                        item.push(b as char);
                        item.push(bytes[j + 1] as char);
                    }
                    j += 2;
                    continue;
                }
                b'[' if !in_single && !in_double => {
                    if depth == 0 {
                        depth = 1;
                    } else {
                        depth += 1;
                        item.push(b as char);
                    }
                }
                b']' if !in_single && !in_double => {
                    if depth <= 0 {
                        return Err(schema("unexpected closing bracket in flow sequence"));
                    }
                    if depth == 1 {
                        push_direct_symbol_item_matching(&mut out, &item, key, symbol_filter);
                        return Ok((out, line_idx + 1));
                    }
                    depth -= 1;
                    item.push(b as char);
                }
                b',' if !in_single && !in_double && depth == 1 => {
                    push_direct_symbol_item_matching(&mut out, &item, key, symbol_filter);
                    item.clear();
                }
                _ => {
                    if depth > 0 {
                        item.push(b as char);
                    }
                }
            }
            j += 1;
        }

        line_idx += 1;
    }
}

fn push_direct_symbol_item_matching(
    out: &mut Vec<String>,
    item: &str,
    key: &str,
    symbol_filter: &HashSet<String>,
) {
    let item = item.trim();
    if !item.is_empty() && direct_symbol_scalar_matches(key, item, symbol_filter) {
        out.push(parse_direct_scalar(item));
    }
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
    let start_line = i + 1;
    let mut flow = rest.trim().to_string();
    if !flow.starts_with('[') {
        return Err(schema("expected a flow sequence"));
    }
    let mut next_i = if direct_trimmed(lines.get(i).copied().unwrap_or_default())
        .map(|line| line.contains(rest.trim()))
        .unwrap_or(false)
    {
        i + 1
    } else {
        i
    };
    while direct_flow_unbalanced(&flow) {
        let Some(next) = lines.get(next_i).and_then(|line| direct_trimmed(line)) else {
            return Err(schema(&format!(
                "unterminated flow sequence from line {} near line {}: {:?}",
                start_line,
                next_i + 1,
                flow
            )));
        };
        if next.starts_with("---") || next.starts_with("...") {
            return Err(schema(&format!(
                "unterminated flow sequence from line {} before line {}: {:?}",
                start_line,
                next_i + 1,
                flow
            )));
        }
        flow.push(' ');
        flow.push_str(next);
        next_i += 1;
    }
    if !flow.ends_with(']') {
        return Err(schema("flow sequence must end with ']'"));
    }
    Ok((flow, next_i))
}

fn skip_direct_flow(lines: &[&str], i: usize, rest: &str) -> Result<usize, TbdError> {
    collect_direct_flow(lines, i, rest).map(|(_, next)| next)
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
    split_direct_flow_scalars_matching(flow, |_| true)
}

fn split_direct_flow_scalars_matching(
    flow: &str,
    mut keep: impl FnMut(&str) -> bool,
) -> Result<Vec<String>, TbdError> {
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
                push_direct_flow_scalar_matching(&mut out, &inner[start..i], &mut keep);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start <= inner.len() {
        push_direct_flow_scalar_matching(&mut out, &inner[start..], &mut keep);
    }
    Ok(out)
}

fn push_direct_flow_scalar_matching(
    out: &mut Vec<String>,
    item: &str,
    keep: &mut impl FnMut(&str) -> bool,
) {
    let item = item.trim();
    if !item.is_empty() && keep(item) {
        out.push(parse_direct_scalar(item));
    }
}

fn direct_symbol_scalar_matches(key: &str, raw: &str, names: &HashSet<String>) -> bool {
    if names.is_empty() {
        return false;
    }
    match key {
        "symbols" | "weak-symbols" | "thread-local-symbols" => {
            direct_scalar_name_matches(raw, names)
        }
        "objc-classes" => direct_prefixed_symbol_matches("_OBJC_CLASS_$_", raw, names),
        "objc-eh-types" => direct_prefixed_symbol_matches("_OBJC_EHTYPE_$_", raw, names),
        "objc-ivars" => direct_prefixed_symbol_matches("_OBJC_IVAR_$_", raw, names),
        _ => false,
    }
}

fn direct_scalar_name_matches(raw: &str, names: &HashSet<String>) -> bool {
    match direct_simple_scalar(raw) {
        Some(name) => names.contains(name),
        None => names.contains(parse_direct_scalar(raw).as_str()),
    }
}

fn direct_prefixed_symbol_matches(prefix: &str, raw: &str, names: &HashSet<String>) -> bool {
    let name = match direct_simple_scalar(raw) {
        Some(name) => Cow::Borrowed(name),
        None => Cow::Owned(parse_direct_scalar(raw)),
    };
    names.contains(format!("{prefix}{name}").as_str())
}

fn direct_simple_scalar(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        let inner = &raw[1..raw.len() - 1];
        if !inner.contains("''") {
            return Some(inner);
        }
    } else if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        let inner = &raw[1..raw.len() - 1];
        if !inner.contains('\\') {
            return Some(inner);
        }
    } else {
        return Some(raw);
    }
    None
}

fn filter_symbol_lists_for_names(lists: &mut SymbolLists, names: &HashSet<String>) {
    lists.symbols.retain(|name| names.contains(name));
    lists.weak_symbols.retain(|name| names.contains(name));
    lists
        .thread_local_symbols
        .retain(|name| names.contains(name));
    lists
        .objc_classes
        .retain(|name| names.contains(format!("_OBJC_CLASS_$_{name}").as_str()));
    lists
        .objc_eh_types
        .retain(|name| names.contains(format!("_OBJC_EHTYPE_$_{name}").as_str()));
    lists
        .objc_ivars
        .retain(|name| names.contains(format!("_OBJC_IVAR_$_{name}").as_str()));
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
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let ch = match bytes[i + 1] {
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'"' => '"',
                b'\\' => '\\',
                other => other as char,
            };
            out.push(ch);
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
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

fn direct_flow_unbalanced(s: &str) -> bool {
    let mut depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let bytes = s.as_bytes();
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
            _ => {}
        }
        i += 1;
    }
    depth != 0
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
    fn target_matching_fast_path_keeps_only_requested_exports() {
        let src = "--- !tapi-tbd\n\
                   tbd-version: 4\n\
                   targets: [ arm64-macos ]\n\
                   install-name: '/usr/lib/libfoo.dylib'\n\
                   exports:\n\
                   \x20 - targets: [ arm64-macos ]\n\
                   \x20   symbols: [ _keep,\n\
                   \x20              _drop,\n\
                   \x20              '_quoted_keep' ]\n\
                   \x20   weak-symbols: [ _weak_keep, _weak_drop ]\n\
                   \x20   thread-local-symbols: [ _tlv_keep, _tlv_drop ]\n\
                   \x20   objc-classes: [ Foo, Bar ]\n\
                   ...\n";
        let names = HashSet::from([
            "_keep".to_string(),
            "_quoted_keep".to_string(),
            "_weak_keep".to_string(),
            "_tlv_keep".to_string(),
            "_OBJC_CLASS_$_Foo".to_string(),
        ]);
        let docs = parse_tbd_for_target_matching(src, &arm64_macos(), &names).unwrap();
        assert_eq!(docs.len(), 1);
        let lists = &docs[0].exports[0].value;
        assert_eq!(lists.symbols, ["_keep", "_quoted_keep"]);
        assert_eq!(lists.weak_symbols, ["_weak_keep"]);
        assert_eq!(lists.thread_local_symbols, ["_tlv_keep"]);
        assert_eq!(lists.objc_classes, ["Foo"]);
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
