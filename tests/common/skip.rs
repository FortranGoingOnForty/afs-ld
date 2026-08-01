//! Shared skip and fixture-failure policy for integration tests.

#![allow(dead_code, unused_macros)]

use std::fmt;

#[track_caller]
pub fn record_skip(reason: fmt::Arguments<'_>) {
    let current = std::thread::current();
    let test = current
        .name()
        .expect("integration-test skip emitted outside a named libtest thread");
    let reason = reason.to_string();

    eprintln!(
        "\n{}",
        format_skip_record(env!("CARGO_CRATE_NAME"), test, &reason)
    );
}

pub fn format_skip_record(suite: &str, test: &str, reason: &str) -> String {
    assert_skip_identity("suite", suite);
    assert_skip_identity("test", test);
    format!(
        "HARNESS_SKIP suite={suite} test={test} count=1 reason=\"{}\"",
        reason.escape_default()
    )
}

fn assert_skip_identity(field: &str, value: &str) {
    assert!(
        !value.is_empty() && !value.chars().any(char::is_whitespace),
        "HARNESS_SKIP {field} identity must be non-empty and whitespace-free: {value:?}"
    );
}

macro_rules! harness_skip {
    ($($arg:tt)*) => {{
        $crate::test_skip::record_skip(format_args!($($arg)*));
    }};
}

macro_rules! require_fixture {
    ($operation:literal, $result:expr) => {{
        $result.unwrap_or_else(|error| panic!("{} failed: {error}", $operation))
    }};
}
