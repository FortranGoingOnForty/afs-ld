//! Minimal YAML parser tuned for TAPI TBD files.
//!
//! TAPI writes a constrained dialect: block mappings, block sequences, flow
//! sequences (often spanning multiple source lines), plain scalars, and
//! single- or double-quoted scalars. No anchors, no aliases, no folded or
//! literal block scalars, no flow mappings (TAPI doesn't emit them in
//! practice). Multiple documents per file are common — libSystem.tbd
//! ships the main dylib plus every re-exported system sub-dylib.
//!
//! We are **not** building a general YAML parser. If a TBD in the wild
//! uses a feature outside this subset, the parser fails loudly with a
//! `line:col` diagnostic pointing at the offending bytes.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Empty value (e.g. `key:` with no inline content and no nested block).
    Null,
    Scalar(String),
    Sequence(Vec<Value>),
    /// Preserves insertion order — TBD consumers rely on this to walk
    /// mapping keys deterministically.
    Mapping(Vec<(String, Value)>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Scalar(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_sequence(&self) -> Option<&[Value]> {
        match self {
            Value::Sequence(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_mapping(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Mapping(m) => Some(m),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_mapping()
            .and_then(|m| m.iter().find(|(k, _)| k == key).map(|(_, v)| v))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub tag: Option<String>,
    pub root: Value,
}

#[derive(Debug)]
pub struct YamlError {
    pub line: usize,
    pub col: usize,
    pub msg: String,
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "YAML error at line {}, col {}: {}",
            self.line, self.col, self.msg
        )
    }
}

impl std::error::Error for YamlError {}

/// Parse every document in the input. TBD files may contain several
/// `--- !tapi-tbd` documents separated by doc terminators.
pub fn parse_documents(input: &str) -> Result<Vec<Document>, YamlError> {
    let lines = tokenize_lines(input)?;
    let mut docs = Vec::new();
    let mut cursor = 0usize;
    while cursor < lines.len() {
        // Skip stray directives and separators.
        if lines[cursor].content.starts_with("%YAML") {
            cursor += 1;
            continue;
        }
        let (tag, content_start) = if let Some(rest) = lines[cursor].content.strip_prefix("---") {
            let tag = parse_tag(rest);
            cursor += 1;
            (tag, cursor)
        } else {
            (None, cursor)
        };
        // Scan until next `---` or `...` or end of input.
        let mut end = content_start;
        while end < lines.len()
            && !lines[end].content.starts_with("---")
            && !lines[end].content.starts_with("...")
        {
            end += 1;
        }
        if end > content_start {
            let root = parse_block(&lines[content_start..end], &mut 0usize, 0)?;
            docs.push(Document { tag, root });
        }
        cursor = end;
        // Consume a `...` terminator if present.
        if cursor < lines.len() && lines[cursor].content.starts_with("...") {
            cursor += 1;
        }
    }
    Ok(docs)
}

// ---------------------------------------------------------------------------
// Line tokenizer — produces logical lines with flow brackets joined across
// source newlines. Comments (`# ...` at BOL or after a space) are stripped.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LogicalLine {
    indent: usize,
    content: String,
    line_no: usize, // 1-based
}

fn tokenize_lines(input: &str) -> Result<Vec<LogicalLine>, YamlError> {
    let mut out = Vec::new();
    let raw_lines: Vec<&str> = input.split('\n').collect();
    let mut i = 0usize;
    while i < raw_lines.len() {
        let start_line_no = i + 1;
        let raw = raw_lines[i];
        // Skip blank / comment-only lines.
        let stripped = strip_trailing_ws(raw);
        if stripped.is_empty() || stripped.trim_start().starts_with('#') {
            i += 1;
            continue;
        }
        let indent = stripped.chars().take_while(|c| *c == ' ').count();
        let mut content = stripped[indent..].to_string();
        strip_eol_comment(&mut content);
        // Flow-continuation: if the line opens `[` or `{` without closing it,
        // append subsequent lines until the brackets balance.
        while flow_unbalanced(&content) {
            i += 1;
            if i >= raw_lines.len() {
                return Err(YamlError {
                    line: start_line_no,
                    col: 1,
                    msg: "unterminated flow collection".into(),
                });
            }
            let next = strip_trailing_ws(raw_lines[i]);
            let mut next_owned = next.trim_start().to_string();
            strip_eol_comment(&mut next_owned);
            content.push(' ');
            content.push_str(&next_owned);
        }
        out.push(LogicalLine {
            indent,
            content,
            line_no: start_line_no,
        });
        i += 1;
    }
    Ok(out)
}

fn strip_trailing_ws(s: &str) -> &str {
    let end = s
        .bytes()
        .rposition(|b| b != b' ' && b != b'\t' && b != b'\r')
        .map(|p| p + 1)
        .unwrap_or(0);
    &s[..end]
}

/// Remove everything from the first `#` that's not inside quotes. Leaves
/// quoted content untouched (otherwise single-quoted paths like
/// `'/usr/lib/#funny'` would be mangled — unlikely but sound).
fn strip_eol_comment(s: &mut String) {
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
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
            b'#' if !in_single
                && !in_double
                && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') =>
            {
                s.truncate(i);
                // Trim trailing whitespace left by the strip.
                let trimmed_len = s.trim_end().len();
                s.truncate(trimmed_len);
                return;
            }
            _ => {}
        }
        i += 1;
    }
}

fn flow_unbalanced(s: &str) -> bool {
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

fn parse_tag(rest: &str) -> Option<String> {
    let rest = rest.trim_start();
    if let Some(tag) = rest.strip_prefix('!') {
        let end = tag.chars().take_while(|c| !c.is_whitespace()).count();
        Some(format!("!{}", &tag[..end]))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Block-structure parser.
// ---------------------------------------------------------------------------

fn parse_block(
    lines: &[LogicalLine],
    cursor: &mut usize,
    indent: usize,
) -> Result<Value, YamlError> {
    if *cursor >= lines.len() {
        return Ok(Value::Null);
    }
    let line = &lines[*cursor];
    if line.indent < indent {
        return Ok(Value::Null);
    }
    if line.content.starts_with("- ") || line.content == "-" {
        parse_block_sequence(lines, cursor, line.indent)
    } else {
        parse_block_mapping(lines, cursor, line.indent)
    }
}

fn parse_block_mapping(
    lines: &[LogicalLine],
    cursor: &mut usize,
    indent: usize,
) -> Result<Value, YamlError> {
    let mut out = Vec::new();
    while *cursor < lines.len() {
        let line = &lines[*cursor];
        if line.indent < indent {
            break;
        }
        if line.indent > indent {
            return Err(YamlError {
                line: line.line_no,
                col: line.indent + 1,
                msg: format!(
                    "unexpected indentation {} when mapping expected {}",
                    line.indent, indent
                ),
            });
        }
        if line.content.starts_with("- ") || line.content == "-" {
            break;
        }
        let (key, rest) = split_key(&line.content, line.line_no, line.indent)?;
        *cursor += 1;
        let value = if rest.is_empty() {
            // Nested block or null.
            if *cursor < lines.len() && lines[*cursor].indent > indent {
                let child_indent = lines[*cursor].indent;
                parse_block(lines, cursor, child_indent)?
            } else {
                Value::Null
            }
        } else {
            parse_inline_value(&rest, line.line_no, indent + key.len() + 2)?
        };
        out.push((key, value));
    }
    Ok(Value::Mapping(out))
}

fn parse_block_sequence(
    lines: &[LogicalLine],
    cursor: &mut usize,
    indent: usize,
) -> Result<Value, YamlError> {
    let mut out = Vec::new();
    while *cursor < lines.len() {
        let line = &lines[*cursor];
        if line.indent < indent {
            break;
        }
        if line.indent > indent || !line.content.starts_with('-') {
            break;
        }
        // `- ` or `-` marker.
        let after_marker = if line.content == "-" {
            ""
        } else if let Some(rest) = line.content.strip_prefix("- ") {
            rest
        } else {
            return Err(YamlError {
                line: line.line_no,
                col: indent + 1,
                msg: "sequence marker must be '-' or '- '".into(),
            });
        };
        // The entry's inner indent is `indent + 2` (the `- ` takes two chars).
        let inner_indent = indent + 2;
        *cursor += 1;
        if after_marker.is_empty() {
            // Nested block follows (mapping or sequence).
            if *cursor < lines.len() && lines[*cursor].indent > indent {
                out.push(parse_block(lines, cursor, lines[*cursor].indent)?);
            } else {
                out.push(Value::Null);
            }
            continue;
        }
        // The remainder could be:
        //   - `- foo`          → plain scalar
        //   - `- [ ... ]`      → flow sequence
        //   - `- '...'`        → quoted scalar
        //   - `- key: value`   → start of a mapping entry (with possible continuation lines)
        if let Some(colon_pos) = find_top_level_mapping_colon(after_marker) {
            // Reconstruct a synthetic "mapping at indent inner_indent" starting
            // with the first pair on this line, then subsequent lines whose
            // indent equals inner_indent.
            let mut pairs = Vec::new();
            let key = after_marker[..colon_pos].trim().to_string();
            let rest = after_marker[colon_pos + 1..].trim_start();
            let first_value = if rest.is_empty() {
                if *cursor < lines.len() && lines[*cursor].indent > inner_indent {
                    let ci = lines[*cursor].indent;
                    parse_block(lines, cursor, ci)?
                } else {
                    Value::Null
                }
            } else {
                parse_inline_value(rest, line.line_no, inner_indent + key.len() + 2)?
            };
            pairs.push((key, first_value));
            // Continuation keys at inner_indent.
            while *cursor < lines.len() {
                let nl = &lines[*cursor];
                if nl.indent != inner_indent {
                    break;
                }
                if nl.content.starts_with("- ") || nl.content == "-" {
                    break;
                }
                let (k, r) = split_key(&nl.content, nl.line_no, nl.indent)?;
                *cursor += 1;
                let v = if r.is_empty() {
                    if *cursor < lines.len() && lines[*cursor].indent > inner_indent {
                        let ci = lines[*cursor].indent;
                        parse_block(lines, cursor, ci)?
                    } else {
                        Value::Null
                    }
                } else {
                    parse_inline_value(&r, nl.line_no, inner_indent + k.len() + 2)?
                };
                pairs.push((k, v));
            }
            out.push(Value::Mapping(pairs));
        } else {
            out.push(parse_inline_value(after_marker, line.line_no, indent + 2)?);
        }
    }
    Ok(Value::Sequence(out))
}

/// Find the first `:` that's at the "top level" of the string — i.e. not
/// inside a flow collection or a quoted scalar. Apple's TBD writes
/// `key: value` where `value` may itself be a flow, so we only care about
/// the first such split.
fn find_top_level_mapping_colon(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut depth = 0i32;
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
            b':' if !in_single
                && !in_double
                && depth == 0
                && (i + 1 == bytes.len() || bytes[i + 1] == b' ' || bytes[i + 1] == b'\t') =>
            {
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn split_key(content: &str, line_no: usize, col: usize) -> Result<(String, String), YamlError> {
    let colon = find_top_level_mapping_colon(content).ok_or(YamlError {
        line: line_no,
        col: col + 1,
        msg: "expected 'key: value' at block-mapping indent".into(),
    })?;
    let key = content[..colon].trim().to_string();
    let rest = content[colon + 1..].trim_start().to_string();
    Ok((key, rest))
}

// ---------------------------------------------------------------------------
// Inline value parser.
// ---------------------------------------------------------------------------

fn parse_inline_value(s: &str, line: usize, col: usize) -> Result<Value, YamlError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Value::Null);
    }
    match s.as_bytes()[0] {
        b'[' => parse_flow_sequence(s, line, col),
        b'{' => Err(YamlError {
            line,
            col,
            msg: "flow mappings are not part of the TBD subset".into(),
        }),
        b'\'' => parse_single_quoted(s, line, col).map(Value::Scalar),
        b'"' => parse_double_quoted(s, line, col).map(Value::Scalar),
        _ => Ok(Value::Scalar(s.to_string())),
    }
}

fn parse_flow_sequence(s: &str, line: usize, col: usize) -> Result<Value, YamlError> {
    if !s.starts_with('[') || !s.ends_with(']') {
        return Err(YamlError {
            line,
            col,
            msg: "flow sequence must be bracketed by '[' and ']'".into(),
        });
    }
    let inner = &s[1..s.len() - 1];
    let items = split_flow_items(inner);
    let mut out = Vec::with_capacity(items.len());
    for piece in items {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        // Recursive: flow sequences can hold scalars or further flow sequences.
        out.push(parse_inline_value(piece, line, col)?);
    }
    Ok(Value::Sequence(out))
}

fn split_flow_items(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let bytes = s.as_bytes();
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
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start <= s.len() {
        parts.push(&s[start..]);
    }
    parts
}

fn parse_single_quoted(s: &str, line: usize, col: usize) -> Result<String, YamlError> {
    if !s.starts_with('\'') || !s.ends_with('\'') || s.len() < 2 {
        return Err(YamlError {
            line,
            col,
            msg: "single-quoted scalar must begin and end with '".into(),
        });
    }
    // `''` inside single-quoted strings represents one literal `'`.
    let inner = &s[1..s.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            if chars.peek() == Some(&'\'') {
                out.push('\'');
                chars.next();
            } else {
                return Err(YamlError {
                    line,
                    col,
                    msg: "unescaped ' inside single-quoted scalar".into(),
                });
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

fn parse_double_quoted(s: &str, line: usize, col: usize) -> Result<String, YamlError> {
    if !s.starts_with('"') || !s.ends_with('"') || s.len() < 2 {
        return Err(YamlError {
            line,
            col,
            msg: "double-quoted scalar must begin and end with \"".into(),
        });
    }
    let inner = &s[1..s.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('0') => out.push('\0'),
                Some(other) => out.push(other), // best-effort pass-through
                None => {
                    return Err(YamlError {
                        line,
                        col,
                        msg: "trailing backslash in double-quoted scalar".into(),
                    })
                }
            }
        } else if c == '"' {
            return Err(YamlError {
                line,
                col,
                msg: "unescaped \" inside double-quoted scalar".into(),
            });
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one(src: &str) -> Document {
        let mut docs = parse_documents(src).unwrap();
        assert_eq!(docs.len(), 1);
        docs.pop().unwrap()
    }

    #[test]
    fn parses_flat_mapping() {
        let doc = parse_one("key1: value1\nkey2: value2\n");
        let m = doc.root.as_mapping().unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].0, "key1");
        assert_eq!(m[0].1, Value::Scalar("value1".into()));
        assert_eq!(m[1].0, "key2");
        assert_eq!(m[1].1, Value::Scalar("value2".into()));
    }

    #[test]
    fn nested_mapping_via_indentation() {
        let doc = parse_one("a:\n  b: 1\n  c: 2\n");
        let a = doc.root.get("a").unwrap();
        let m = a.as_mapping().unwrap();
        assert_eq!(m[0], ("b".into(), Value::Scalar("1".into())));
        assert_eq!(m[1], ("c".into(), Value::Scalar("2".into())));
    }

    #[test]
    fn flow_sequence_on_one_line() {
        let doc = parse_one("xs: [ a, b, c ]\n");
        let xs = doc.root.get("xs").unwrap();
        let s = xs.as_sequence().unwrap();
        assert_eq!(s[0], Value::Scalar("a".into()));
        assert_eq!(s[1], Value::Scalar("b".into()));
        assert_eq!(s[2], Value::Scalar("c".into()));
    }

    #[test]
    fn flow_sequence_spans_lines() {
        let doc = parse_one("xs: [ a, b,\n      c, d ]\n");
        let s = doc.root.get("xs").unwrap().as_sequence().unwrap();
        assert_eq!(s.len(), 4);
    }

    #[test]
    fn single_quoted_scalar_unescapes_doubled_apostrophe() {
        let doc = parse_one("path: 'can''t'\n");
        assert_eq!(
            doc.root.get("path").unwrap(),
            &Value::Scalar("can't".into())
        );
    }

    #[test]
    fn double_quoted_scalar_applies_escapes() {
        let doc = parse_one(r#"msg: "a\tb\n""#);
        assert_eq!(
            doc.root.get("msg").unwrap(),
            &Value::Scalar("a\tb\n".into())
        );
    }

    #[test]
    fn block_sequence_of_mappings() {
        let doc = parse_one("items:\n  - name: alpha\n    size: 1\n  - name: beta\n    size: 2\n");
        let items = doc.root.get("items").unwrap().as_sequence().unwrap();
        assert_eq!(items.len(), 2);
        let a = items[0].as_mapping().unwrap();
        assert_eq!(a[0], ("name".into(), Value::Scalar("alpha".into())));
        assert_eq!(a[1], ("size".into(), Value::Scalar("1".into())));
        let b = items[1].as_mapping().unwrap();
        assert_eq!(b[0], ("name".into(), Value::Scalar("beta".into())));
    }

    #[test]
    fn block_sequence_entries_with_flow_values() {
        let doc =
            parse_one("exports:\n  - targets: [ arm64-macos ]\n    symbols: [ _foo, _bar ]\n");
        let e = doc.root.get("exports").unwrap().as_sequence().unwrap();
        let entry = e[0].as_mapping().unwrap();
        assert_eq!(
            entry[0].1.as_sequence().unwrap()[0],
            Value::Scalar("arm64-macos".into())
        );
        assert_eq!(
            entry[1].1.as_sequence().unwrap()[1],
            Value::Scalar("_bar".into())
        );
    }

    #[test]
    fn multi_document_split_by_triple_dash() {
        let src = "--- !tapi-tbd\nkey: a\n--- !tapi-tbd\nkey: b\n...\n";
        let docs = parse_documents(src).unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0].tag.as_deref(), Some("!tapi-tbd"));
        assert_eq!(docs[0].root.get("key"), Some(&Value::Scalar("a".into())));
        assert_eq!(docs[1].root.get("key"), Some(&Value::Scalar("b".into())));
    }

    #[test]
    fn comment_lines_are_skipped() {
        let doc = parse_one("# a comment\nkey: value\n# another\n");
        assert_eq!(doc.root.get("key"), Some(&Value::Scalar("value".into())));
    }

    #[test]
    fn eol_comments_are_stripped() {
        let doc = parse_one("key: value  # trailing\n");
        assert_eq!(doc.root.get("key"), Some(&Value::Scalar("value".into())));
    }

    #[test]
    fn unterminated_flow_errors_cleanly() {
        let err = parse_documents("xs: [ a, b,\n").unwrap_err();
        assert!(err.msg.contains("unterminated"));
    }

    #[test]
    fn wrong_indentation_errors() {
        // Second key at a greater indent than the first without a parent.
        let err = parse_documents("a: 1\n   b: 2\n").unwrap_err();
        assert!(err.msg.contains("indentation"));
    }
}
