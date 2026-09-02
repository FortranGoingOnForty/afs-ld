use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_LOG_ID: AtomicU64 = AtomicU64::new(0);

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ci/check_skips.sh")
}

fn run(log: &str, profile: &str) -> Output {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before Unix epoch")
        .as_nanos();
    let log_id = NEXT_LOG_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "afs-ld-check-skips-{}-{nonce}-{log_id}.log",
        std::process::id()
    ));
    fs::write(&path, log).expect("write skip-gate fixture");
    let output = Command::new(script())
        .arg(&path)
        .arg(profile)
        .output()
        .expect("run afs-ld skip gate");
    let _ = fs::remove_file(path);
    output
}

fn valid_log(reason: &str) -> String {
    format!(
        "HARNESS_SKIP suite=linker_run test=off_platform_case count=1 reason=\"{reason}\"\n\
         test result: ok. 1 passed; 0 failed; 0 ignored\n"
    )
}

#[test]
fn accepts_structured_off_platform_skip() {
    let output = run(&valid_log("xcrun unavailable"), "linux");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rejects_unstructured_passing_skip() {
    let legacy = format!(
        "{}: assemble failed\ntest result: ok. 1 passed; 0 failed\n",
        "skipping"
    );
    let output = run(&legacy, "linux");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unstructured passing skip"));
}

#[test]
fn rejects_post_prerequisite_failure_skip() {
    let output = run(&valid_log("assemble failed: injected failure"), "linux");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("post-prerequisite failure"));
}

#[test]
fn rejects_malformed_and_duplicate_records() {
    let malformed = run(
        "HARNESS_SKIP suite=linker_run test=case count=zero reason=\"missing tool\"\n\
         test result: ok. 1 passed; 0 failed\n",
        "linux",
    );
    assert!(!malformed.status.success());

    let duplicate = run(
        "HARNESS_SKIP suite=linker_run test=case count=1 reason=\"xcrun unavailable\"\n\
         HARNESS_SKIP suite=linker_run test=case count=1 reason=\"SDK unavailable\"\n\
         test result: ok. 1 passed; 0 failed\n",
        "linux",
    );
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("duplicate skip identity"));
}

#[test]
fn rejects_native_platform_prerequisite_skips() {
    let macos = run(&valid_log("xcrun as unavailable"), "macos");
    assert!(!macos.status.success());
    assert!(String::from_utf8_lossy(&macos.stderr).contains("native-platform"));

    let linux = run(&valid_log("no GNU assembler on this host"), "linux");
    assert!(!linux.status.success());
    assert!(String::from_utf8_lossy(&linux.stderr).contains("native-platform"));
}
