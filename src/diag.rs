//! Diagnostics. Sprint 0 has the minimum surface the CLI and tests need:
//! a single `error(msg)` helper that writes a prefixed line to stderr.
//! Sprint 30 grows this into path + byte-offset + caret output mirroring
//! `afs-as/src/diag*.rs` style.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicU8, Ordering};

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
