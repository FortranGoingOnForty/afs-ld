//! Diagnostics. Sprint 0 has the minimum surface the CLI and tests need:
//! a single `error(msg)` helper that writes a prefixed line to stderr.
//! Sprint 30 grows this into path + byte-offset + caret output mirroring
//! `afs-as/src/diag*.rs` style.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::macho::reader::ReadError;
use crate::ColorMode;

const COLOR_AUTO: u8 = 0;
const COLOR_ALWAYS: u8 = 1;
const COLOR_NEVER: u8 = 2;

static COLOR_MODE: AtomicU8 = AtomicU8::new(COLOR_AUTO);

pub fn configure_from_argv(argv: &[String]) {
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--color" => {
                if let Some(value) = iter.next() {
                    set_color_mode(parse_color_mode(value));
                }
            }
            _ => {
                if let Some(value) = arg.strip_prefix("--color=") {
                    set_color_mode(parse_color_mode(value));
                }
            }
        }
    }
}

pub fn set_color_mode(mode: ColorMode) {
    let value = match mode {
        ColorMode::Auto => COLOR_AUTO,
        ColorMode::Always => COLOR_ALWAYS,
        ColorMode::Never => COLOR_NEVER,
    };
    COLOR_MODE.store(value, Ordering::Relaxed);
}

fn parse_color_mode(value: &str) -> ColorMode {
    match value {
        "always" => ColorMode::Always,
        "never" => ColorMode::Never,
        _ => ColorMode::Auto,
    }
}

pub fn error(msg: &str) {
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    let _ = write_prefixed(&mut h, "error", "\x1b[31m", msg);
}

pub fn error_verbatim(msg: &str) {
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    let _ = writeln!(h, "{msg}");
}

pub fn warning(msg: &str) {
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    let _ = write_prefixed(&mut h, "warning", "\x1b[33m", msg);
}

pub fn warning_verbatim(msg: &str) {
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    let _ = writeln!(h, "{msg}");
}

pub fn binary_error(path: &Path, bytes: &[u8], error: &ReadError) {
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    let offset = error.primary_offset();
    let _ = write_prefixed(
        &mut h,
        "error",
        "\x1b[31m",
        &format!("in {} at byte 0x{offset:x}: {error}", path.display()),
    );
    let _ = writeln!(h);
    let _ = write_hex_caret(&mut h, bytes, offset, error.primary_len());
}

fn write_prefixed(h: &mut impl Write, kind: &str, color: &str, msg: &str) -> std::io::Result<()> {
    if should_color_stderr() {
        writeln!(h, "{color}afs-ld: {kind}:\x1b[0m {msg}")
    } else {
        writeln!(h, "afs-ld: {kind}: {msg}")
    }
}

fn should_color_stderr() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    match COLOR_MODE.load(Ordering::Relaxed) {
        COLOR_ALWAYS => true,
        COLOR_NEVER => false,
        _ => std::io::stderr().is_terminal(),
    }
}

fn write_hex_caret(
    h: &mut impl Write,
    bytes: &[u8],
    offset: usize,
    len: usize,
) -> std::io::Result<()> {
    if bytes.is_empty() {
        return writeln!(h, "  <empty input>\n  ^");
    }

    let clamped = offset.min(bytes.len() - 1);
    let line_start = (clamped / 16) * 16;
    let line_end = (line_start + 16).min(bytes.len());
    let prefix = format!("  0x{line_start:04x}: ");
    write!(h, "{prefix}")?;
    for (idx, byte) in bytes[line_start..line_end].iter().enumerate() {
        if idx > 0 {
            write!(h, " ")?;
        }
        write!(h, "{byte:02x}")?;
    }
    writeln!(h)?;

    let highlight_start = offset.clamp(line_start, line_end.saturating_sub(1));
    let highlight_end = (offset.saturating_add(len))
        .max(highlight_start + 1)
        .min(line_end);
    let byte_columns = (highlight_start - line_start) * 3;
    let width = ((highlight_end - highlight_start) * 3)
        .saturating_sub(1)
        .max(1);
    writeln!(
        h,
        "{}{}{}",
        " ".repeat(prefix.len()),
        " ".repeat(byte_columns),
        "^".repeat(width)
    )
}
