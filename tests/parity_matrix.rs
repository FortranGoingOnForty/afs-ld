//! Differential parity matrix against Apple `ld`.
//!
//! Sprint 27 starts with a tiny executable-only corpus so the reusable harness,
//! on-disk case format, and runtime parity path all exist before we scale up to
//! the full corpus promised by the sprint doc.

mod common;

#[macro_use]
#[path = "common/skip.rs"]
mod test_skip;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use common::harness::{
    compare_command_details, compare_command_ids, compare_page_refs, compare_runtime,
    compare_sections, ensure_absent_load_commands, ensure_absent_sections, have_xcrun,
    have_xcrun_tool, link_both, load_corpus, LinkCase,
};

#[test]
fn parity_corpus() {
    if !have_xcrun() || !have_xcrun_tool("ld") {
        harness_skip!("xcrun as/ld unavailable");
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

    let mut failures = Vec::new();
    let case_reports = run_cases(cases);

    for (case, report) in &case_reports {
        if let Some(dir) = artifact_dir.as_ref() {
            write_case_artifact(dir, case, report).expect("write case artifact");
        }
        if let Some(error) = report.error_message(&case.name) {
            eprintln!("parity failure:\n{error}\n");
            failures.push(error);
        }
    }
    print_timing_summary(started.elapsed(), &case_reports);

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

fn run_cases(cases: Vec<LinkCase>) -> Vec<(LinkCase, CaseReport)> {
    let job_count = parity_matrix_jobs(cases.len());
    if job_count <= 1 || cases.len() <= 1 {
        return cases
            .into_iter()
            .map(|case| {
                let report = run_case(&case);
                (case, report)
            })
            .collect();
    }

    let queue = Arc::new(Mutex::new(cases.into_iter().enumerate()));
    let (tx, rx) = mpsc::channel();
    thread::scope(|scope| {
        for _ in 0..job_count {
            let queue = Arc::clone(&queue);
            let tx = tx.clone();
            scope.spawn(move || loop {
                let Some((index, case)) = queue
                    .lock()
                    .expect("parity case queue mutex poisoned")
                    .next()
                else {
                    break;
                };
                let report = run_case(&case);
                tx.send((index, case, report))
                    .expect("parity result receiver should stay live");
            });
        }
        drop(tx);
        let mut reports: Vec<_> = rx.into_iter().collect();
        reports.sort_by_key(|(index, _, _)| *index);
        reports
            .into_iter()
            .map(|(_, case, report)| (case, report))
            .collect()
    })
}

#[derive(Debug)]
struct CaseStep {
    name: &'static str,
    duration: Duration,
    error: Option<String>,
}

#[derive(Debug, Default)]
struct CaseReport {
    steps: Vec<CaseStep>,
    elapsed: Duration,
}

impl CaseReport {
    fn push(&mut self, name: &'static str, result: Result<(), String>) -> bool {
        self.push_timed(name, Duration::ZERO, result)
    }

    fn push_timed(
        &mut self,
        name: &'static str,
        duration: Duration,
        result: Result<(), String>,
    ) -> bool {
        match result {
            Ok(()) => {
                self.steps.push(CaseStep {
                    name,
                    duration,
                    error: None,
                });
                true
            }
            Err(error) => {
                self.steps.push(CaseStep {
                    name,
                    duration,
                    error: Some(error),
                });
                false
            }
        }
    }

    fn measure<F>(&mut self, name: &'static str, action: F) -> bool
    where
        F: FnOnce() -> Result<(), String>,
    {
        let started = Instant::now();
        let result = action();
        self.push_timed(name, started.elapsed(), result)
    }

    fn finish(&mut self, elapsed: Duration) {
        self.elapsed = elapsed;
    }

    fn passed(&self) -> bool {
        self.steps.iter().all(|step| step.error.is_none())
    }

    fn slowest_step(&self) -> Option<&CaseStep> {
        self.steps.iter().max_by_key(|step| step.duration)
    }

    fn error_message(&self, case_name: &str) -> Option<String> {
        self.steps.iter().find_map(|step| {
            step.error
                .as_ref()
                .map(|error| format!("[{case_name}] {} failed:\n{}", step.name, error))
        })
    }
}

#[test]
fn case_report_error_message_includes_case_name() {
    let mut report = CaseReport::default();
    report.push("section parity", Err("stub bytes differ".into()));
    assert_eq!(
        report.error_message("classic_lazy_branch_only_calls"),
        Some(
            "[classic_lazy_branch_only_calls] section parity failed:\nstub bytes differ"
                .to_string()
        )
    );
}

fn run_case(case: &LinkCase) -> CaseReport {
    let case_started = Instant::now();
    let mut report = CaseReport::default();
    let link_started = Instant::now();
    let outputs = match link_both(case) {
        Ok(outputs) => {
            report.push_timed("link", link_started.elapsed(), Ok(()));
            outputs
        }
        Err(error) => {
            report.push_timed(
                "link",
                link_started.elapsed(),
                Err(format!(
                    "failed to link parity case from {}:\n{}",
                    case.dir.display(),
                    error
                )),
            );
            return finish_case(report, case_started);
        }
    };

    if !report.measure("load-command ids", || {
        compare_command_ids(&outputs.ours, &outputs.theirs, &case.ignored_load_commands)
    }) {
        return finish_case(report, case_started);
    }
    if !report.measure("command details", || {
        compare_command_details(&outputs.ours, &outputs.theirs, &case.command_checks)
    }) {
        return finish_case(report, case_started);
    }
    if !report.measure("afs-ld absent commands", || {
        ensure_absent_load_commands(&outputs.ours, &case.absent_load_commands, "afs-ld")
    }) {
        return finish_case(report, case_started);
    }
    if !report.measure("Apple absent commands", || {
        ensure_absent_load_commands(&outputs.theirs, &case.absent_load_commands, "Apple ld")
    }) {
        return finish_case(report, case_started);
    }
    if !report.measure("afs-ld absent sections", || {
        ensure_absent_sections(&outputs.ours, &case.absent_sections, "afs-ld")
    }) {
        return finish_case(report, case_started);
    }
    if !report.measure("Apple absent sections", || {
        ensure_absent_sections(&outputs.theirs, &case.absent_sections, "Apple ld")
    }) {
        return finish_case(report, case_started);
    }
    if !report.measure("section parity", || {
        compare_sections(
            &outputs.ours,
            &outputs.theirs,
            &case.section_checks,
            &case.case_tolerances,
        )
    }) {
        return finish_case(report, case_started);
    }
    if !report.measure("page-ref parity", || {
        compare_page_refs(&outputs.ours, &outputs.theirs, &case.page_ref_checks)
    }) {
        return finish_case(report, case_started);
    }
    if !case.runtime_args.is_empty() || case.dir.join("runtime.txt").exists() {
        report.measure("runtime parity", || {
            compare_runtime(&outputs.our_path, &outputs.their_path, &case.runtime_args)
        });
    }

    finish_case(report, case_started)
}

fn finish_case(mut report: CaseReport, started: Instant) -> CaseReport {
    report.finish(started.elapsed());
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
    html.push_str(&format!(
        "<p>Total: <strong>{}</strong></p>",
        format_duration(report.elapsed)
    ));
    html.push_str("<h2>Steps</h2><ul>");
    for step in &report.steps {
        match &step.error {
            None => html.push_str(&format!(
                "<li><span class=\"ok\">PASS</span> {} <span class=\"time\">{}</span></li>",
                escape_html(step.name),
                format_duration(step.duration)
            )),
            Some(error) => html.push_str(&format!(
                "<li><span class=\"fail\">FAIL</span> {} <span class=\"time\">{}</span><pre>{}</pre></li>",
                escape_html(step.name),
                format_duration(step.duration),
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
    html.push_str("<title>Parity Matrix</title><style>body{font-family:ui-monospace,Menlo,monospace;padding:2rem;} .ok{color:#0a0;} .fail{color:#a00;} .time{color:#57606a;} table{border-collapse:collapse;margin:1rem 0;} td,th{border:1px solid #d0d7de;padding:.35rem .6rem;text-align:left;}</style></head><body>");
    html.push_str("<h1>Parity Matrix</h1>");
    html.push_str("<h2>Slowest Cases</h2><table><thead><tr><th>Case</th><th>Total</th><th>Slowest Step</th></tr></thead><tbody>");
    for (case, report) in slowest_cases(cases, 10) {
        let slowest = report
            .slowest_step()
            .map(|step| format!("{} {}", step.name, format_duration(step.duration)))
            .unwrap_or_else(|| "n/a".to_string());
        html.push_str(&format!(
            "<tr><td><a href=\"{}.html\">{}</a></td><td>{}</td><td>{}</td></tr>",
            slug(&case.name),
            escape_html(&case.name),
            format_duration(report.elapsed),
            escape_html(&slowest)
        ));
    }
    html.push_str("</tbody></table><h2>Cases</h2><ul>");
    for (case, report) in cases {
        let slug = slug(&case.name);
        html.push_str(&format!(
            "<li><a href=\"{}.html\">{}</a> <strong class=\"{}\">{}</strong> <span class=\"time\">{}</span></li>",
            slug,
            escape_html(&case.name),
            if report.passed() { "ok" } else { "fail" },
            if report.passed() { "PASS" } else { "FAIL" },
            format_duration(report.elapsed)
        ));
    }
    html.push_str("</ul></body></html>");
    let path = dir.join("index.html");
    fs::write(&path, html).map_err(|e| format!("write {}: {e}", path.display()))
}

fn print_timing_summary(elapsed: Duration, cases: &[(LinkCase, CaseReport)]) {
    eprintln!(
        "parity matrix timing: {} case(s) in {}",
        cases.len(),
        format_duration(elapsed)
    );
    for (case, report) in slowest_cases(cases, 10) {
        let slowest = report
            .slowest_step()
            .map(|step| {
                format!(
                    "; slowest step: {} {}",
                    step.name,
                    format_duration(step.duration)
                )
            })
            .unwrap_or_default();
        eprintln!(
            "  {:>9} {}{}",
            format_duration(report.elapsed),
            case.name,
            slowest
        );
    }
}

fn slowest_cases(cases: &[(LinkCase, CaseReport)], limit: usize) -> Vec<(&LinkCase, &CaseReport)> {
    let mut timed: Vec<_> = cases.iter().map(|(case, report)| (case, report)).collect();
    timed.sort_by(|a, b| {
        b.1.elapsed
            .cmp(&a.1.elapsed)
            .then_with(|| a.0.name.cmp(&b.0.name))
    });
    timed.truncate(limit);
    timed
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

fn parity_matrix_jobs(case_count: usize) -> usize {
    if case_count == 0 {
        return 1;
    }
    let requested = std::env::var("PARITY_MATRIX_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|jobs| *jobs > 0)
        .unwrap_or_else(|| {
            thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1)
        });
    requested.min(case_count).max(1)
}

fn format_duration(duration: Duration) -> String {
    let millis = duration.as_secs_f64() * 1000.0;
    if millis >= 1000.0 {
        format!("{:.2}s", duration.as_secs_f64())
    } else {
        format!("{millis:.1}ms")
    }
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
