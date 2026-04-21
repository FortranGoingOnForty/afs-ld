//! Differential parity matrix against Apple `ld`.
//!
//! Sprint 27 starts with a tiny executable-only corpus so the reusable harness,
//! on-disk case format, and runtime parity path all exist before we scale up to
//! the full corpus promised by the sprint doc.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::harness::{
    compare_command_details, compare_command_ids, compare_page_refs, compare_runtime,
    compare_sections, ensure_absent_load_commands, ensure_absent_sections, have_xcrun,
    have_xcrun_tool, link_both, load_corpus, LinkCase,
};

#[test]
fn parity_corpus() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        eprintln!("skipping: xcrun as/ld unavailable");
        return;
    }
    let started = Instant::now();

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("parity_corpus");
    let cases = load_corpus(&root).expect("load parity corpus");
    assert!(
        cases.len() >= 50,
        "expected at least 50 parity corpus cases under {}, found {}",
        root.display(),
        cases.len()
    );

    let artifact_dir = std::env::var_os("PARITY_MATRIX_ARTIFACT_DIR").map(PathBuf::from);
    if let Some(dir) = artifact_dir.as_ref() {
        fs::create_dir_all(dir).expect("create parity artifact dir");
    }

    let mut case_reports = Vec::new();
    let mut failures = Vec::new();

    for case in cases {
        let report = run_case(&case);
        if let Some(dir) = artifact_dir.as_ref() {
            write_case_artifact(dir, &case, &report).expect("write case artifact");
        }
        if let Some(error) = report.error_message() {
            failures.push(error);
        }
        case_reports.push((case, report));
    }

    if let Some(dir) = artifact_dir.as_ref() {
        write_index_artifact(dir, &case_reports).expect("write parity index");
    }

    assert!(
        failures.is_empty(),
        "Parity matrix failures ({} cases):\n{}",
        failures.len(),
        failures.join("\n\n")
    );

    if let Some(limit) = parity_matrix_time_limit() {
        let elapsed = started.elapsed();
        assert!(
            elapsed <= limit,
            "parity matrix exceeded scale budget: {:?} > {:?}",
            elapsed,
            limit
        );
    }
}

#[derive(Debug)]
struct CaseStep {
    name: &'static str,
    error: Option<String>,
}

#[derive(Debug, Default)]
struct CaseReport {
    steps: Vec<CaseStep>,
}

impl CaseReport {
    fn push(&mut self, name: &'static str, result: Result<(), String>) -> bool {
        match result {
            Ok(()) => {
                self.steps.push(CaseStep { name, error: None });
                true
            }
            Err(error) => {
                self.steps.push(CaseStep {
                    name,
                    error: Some(error),
                });
                false
            }
        }
    }

    fn passed(&self) -> bool {
        self.steps.iter().all(|step| step.error.is_none())
    }

    fn error_message(&self) -> Option<String> {
        self.steps.iter().find_map(|step| {
            step.error
                .as_ref()
                .map(|error| format!("{} failed:\n{}", step.name, error))
        })
    }
}

fn run_case(case: &LinkCase) -> CaseReport {
    let mut report = CaseReport::default();
    let outputs = match link_both(case) {
        Ok(outputs) => {
            report.push("link", Ok(()));
            outputs
        }
        Err(error) => {
            report.push(
                "link",
                Err(format!(
                    "failed to link parity case from {}:\n{}",
                    case.dir.display(),
                    error
                )),
            );
            return report;
        }
    };

    if !report.push(
        "load-command ids",
        compare_command_ids(&outputs.ours, &outputs.theirs, &case.ignored_load_commands),
    ) {
        return report;
    }
    if !report.push(
        "command details",
        compare_command_details(&outputs.ours, &outputs.theirs, &case.command_checks),
    ) {
        return report;
    }
    if !report.push(
        "afs-ld absent commands",
        ensure_absent_load_commands(&outputs.ours, &case.absent_load_commands, "afs-ld"),
    ) {
        return report;
    }
    if !report.push(
        "Apple absent commands",
        ensure_absent_load_commands(&outputs.theirs, &case.absent_load_commands, "Apple ld"),
    ) {
        return report;
    }
    if !report.push(
        "afs-ld absent sections",
        ensure_absent_sections(&outputs.ours, &case.absent_sections, "afs-ld"),
    ) {
        return report;
    }
    if !report.push(
        "Apple absent sections",
        ensure_absent_sections(&outputs.theirs, &case.absent_sections, "Apple ld"),
    ) {
        return report;
    }
    if !report.push(
        "section parity",
        compare_sections(
            &outputs.ours,
            &outputs.theirs,
            &case.section_checks,
            &case.case_tolerances,
        ),
    ) {
        return report;
    }
    if !report.push(
        "page-ref parity",
        compare_page_refs(&outputs.ours, &outputs.theirs, &case.page_ref_checks),
    ) {
        return report;
    }
    if !case.runtime_args.is_empty() || case.dir.join("runtime.txt").exists() {
        report.push(
            "runtime parity",
            compare_runtime(&outputs.our_path, &outputs.their_path, &case.runtime_args),
        );
    }

    report
}

fn write_case_artifact(dir: &Path, case: &LinkCase, report: &CaseReport) -> Result<(), String> {
    let path = dir.join(format!("{}.html", slug(&case.name)));
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\">");
    html.push_str(&format!(
        "<title>{}</title><style>body{{font-family:ui-monospace,Menlo,monospace;padding:2rem;}} .ok{{color:#0a0;}} .fail{{color:#a00;}} pre{{background:#f6f8fa;padding:1rem;white-space:pre-wrap;}}</style></head><body>",
        escape_html(&case.name)
    ));
    html.push_str(&format!("<h1>{}</h1>", escape_html(&case.name)));
    html.push_str(&format!(
        "<p>Status: <strong class=\"{}\">{}</strong></p>",
        if report.passed() { "ok" } else { "fail" },
        if report.passed() { "PASS" } else { "FAIL" }
    ));
    html.push_str("<h2>Steps</h2><ul>");
    for step in &report.steps {
        match &step.error {
            None => html.push_str(&format!(
                "<li><span class=\"ok\">PASS</span> {}</li>",
                escape_html(step.name)
            )),
            Some(error) => html.push_str(&format!(
                "<li><span class=\"fail\">FAIL</span> {}<pre>{}</pre></li>",
                escape_html(step.name),
                escape_html(error)
            )),
        }
    }
    html.push_str("</ul>");
    html.push_str("<h2>Args</h2><pre>");
    html.push_str(&escape_html(&case.args.join("\n")));
    html.push_str("</pre>");
    if let Some(notes) = &case.notes {
        html.push_str("<h2>Notes</h2><pre>");
        html.push_str(&escape_html(notes));
        html.push_str("</pre>");
    }
    html.push_str("</body></html>");
    fs::write(&path, html).map_err(|e| format!("write {}: {e}", path.display()))
}

fn write_index_artifact(dir: &Path, cases: &[(LinkCase, CaseReport)]) -> Result<(), String> {
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\">");
    html.push_str("<title>Parity Matrix</title><style>body{font-family:ui-monospace,Menlo,monospace;padding:2rem;} .ok{color:#0a0;} .fail{color:#a00;}</style></head><body>");
    html.push_str("<h1>Parity Matrix</h1><ul>");
    for (case, report) in cases {
        let slug = slug(&case.name);
        html.push_str(&format!(
            "<li><a href=\"{}.html\">{}</a> <strong class=\"{}\">{}</strong></li>",
            slug,
            escape_html(&case.name),
            if report.passed() { "ok" } else { "fail" },
            if report.passed() { "PASS" } else { "FAIL" }
        ));
    }
    html.push_str("</ul></body></html>");
    let path = dir.join("index.html");
    fs::write(&path, html).map_err(|e| format!("write {}: {e}", path.display()))
}

fn slug(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn parity_matrix_time_limit() -> Option<Duration> {
    let raw = std::env::var("PARITY_MATRIX_MAX_SECONDS").ok()?;
    let seconds = raw.parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds))
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
