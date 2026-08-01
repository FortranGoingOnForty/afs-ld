#[macro_use]
#[path = "common/skip.rs"]
mod test_skip;

use std::any::Any;
use std::fs;
use std::path::Path;

#[test]
fn post_prerequisite_fixture_failures_are_fatal() {
    let panic = std::panic::catch_unwind(|| {
        require_fixture!(
            "assembler fixture",
            Result::<(), &str>::Err("injected assembler failure")
        );
    })
    .expect_err("fixture failure unexpectedly returned to the test");

    assert_eq!(
        panic_message(&panic),
        "assembler fixture failed: injected assembler failure"
    );
}

#[test]
fn genuine_skip_records_have_machine_readable_identity() {
    let record =
        test_skip::format_skip_record("linker_run", "requires_macos_sdk", "SDK missing\nfrom host");

    assert_eq!(
        record,
        "HARNESS_SKIP suite=linker_run test=requires_macos_sdk count=1 reason=\"SDK missing\\nfrom host\""
    );
}

#[test]
fn integration_sources_cannot_restore_unstructured_or_failure_skips() {
    visit_rust_sources(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .as_path(),
    );
}

fn visit_rust_sources(path: &Path) {
    for entry in fs::read_dir(path).unwrap_or_else(|error| {
        panic!(
            "failed to enumerate integration-test source {}: {error}",
            path.display()
        )
    }) {
        let entry = entry.expect("failed to read integration-test directory entry");
        let path = entry.path();
        if path.is_dir() {
            visit_rust_sources(&path);
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs")
            || path.file_name().and_then(|name| name.to_str()) == Some("fixture_policy.rs")
        {
            continue;
        }

        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let compact: String = source
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let legacy_skip = ["eprintln!(\"", "skipping", ":"].concat();
        assert!(
            !compact.contains(&legacy_skip),
            "{} contains an unstructured passing skip",
            path.display()
        );

        for (_, tail) in source.match_indices("harness_skip!(") {
            let invocation = tail
                .split_once(");")
                .map(|(invocation, _)| invocation)
                .unwrap_or(tail)
                .to_ascii_lowercase();
            for forbidden in ["failed", "failure", "error", "could not"] {
                assert!(
                    !invocation.contains(forbidden),
                    "{} routes a post-prerequisite {forbidden} through harness_skip!",
                    path.display()
                );
            }
        }
    }
}

fn panic_message(panic: &Box<dyn Any + Send>) -> &str {
    if let Some(message) = panic.downcast_ref::<String>() {
        message
    } else if let Some(message) = panic.downcast_ref::<&str>() {
        message
    } else {
        "<non-string panic>"
    }
}
