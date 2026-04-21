//! Differential harness shared by parity-oriented integration tests.
//!
//! The early scaffold only diffed arbitrary byte slices. Sprint 27 starts
//! turning it into a real Apple-`ld` matrix harness with a tiny corpus, basic
//! tolerated-diff rules, and reusable link/runtime helpers.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use afs_ld::macho::constants::{
    LC_BUILD_VERSION, LC_CODE_SIGNATURE, LC_DYLD_INFO_ONLY, LC_DYSYMTAB, LC_LOAD_DYLIB,
    LC_SEGMENT_64, LC_SYMTAB, LC_UUID,
};
use afs_ld::macho::dylib::DylibFile;
use afs_ld::macho::exports::ExportKind;
use afs_ld::macho::reader::{
    parse_commands, parse_header, u32_le, BuildVersionCmd, DyldInfoCmd, LoadCommand,
};
use afs_ld::string_table::StringTable;
use afs_ld::symbol::{parse_nlist_table, SymKind};

#[derive(Debug, Clone)]
pub struct LinkCase {
    pub name: String,
    pub dir: PathBuf,
    pub inputs: Vec<PathBuf>,
    pub args: Vec<String>,
    pub section_checks: Vec<(String, String)>,
    pub page_ref_checks: Vec<PageRefCheck>,
    pub command_checks: Vec<CommandCheck>,
    artifacts: Vec<ArtifactSpec>,
    pub ignored_load_commands: Vec<u32>,
    pub absent_load_commands: Vec<u32>,
    pub runtime_args: Vec<String>,
    pub notes: Option<String>,
    pub case_tolerances: Vec<CaseTolerance>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandCheck {
    BuildVersion,
    LoadDylibNames,
    ExportRecords,
    SymbolRecordMap,
    DyldInfoRebase,
    DyldInfoBind,
    DyldInfoWeakBind,
    DyldInfoLazyBind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRefCheck {
    pub segname: String,
    pub sectname: String,
    pub site_offset: u64,
    pub kind: PageRefKind,
    pub symbol: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageRefKind {
    Add,
    Load,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseTolerance {
    pub region: ToleranceRegion,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToleranceRegion {
    SectionBytes {
        segname: String,
        sectname: Option<String>,
        start: usize,
        end_inclusive: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactSpec {
    src_name: String,
    out_name: String,
    kind: ArtifactKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactKind {
    ClangDylib,
}

pub struct LinkOutputs {
    pub ours: Vec<u8>,
    pub theirs: Vec<u8>,
    pub our_path: PathBuf,
    pub their_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffCategory {
    /// A diff we expect: UUID bytes, code-signature hashes, etc.
    Tolerated(&'static str),
    /// Anything else. Fails the parity test.
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffChunk {
    pub offset: usize,
    pub len: usize,
    pub reason: String,
    pub category: DiffCategory,
}

#[derive(Debug, Default)]
pub struct DiffReport {
    pub tolerated: Vec<DiffChunk>,
    pub critical: Vec<DiffChunk>,
}

impl DiffReport {
    pub fn is_clean(&self) -> bool {
        self.critical.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

type NormalizedBuildVersion = (u32, u32, u32, Vec<u32>);

pub fn have_xcrun() -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg("as")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn have_xcrun_tool(tool: &str) -> bool {
    Command::new("xcrun")
        .arg("-f")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn have_tool(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success() || !o.stderr.is_empty())
        .unwrap_or(false)
}

pub fn sdk_path() -> Option<String> {
    let out = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn sdk_version() -> Option<String> {
    let out = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-version"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("afs-ld-parity-{}-{name}", std::process::id()))
}

pub fn assemble(src: &str, out: &PathBuf) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-parity-{}-{}.s",
        std::process::id(),
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("t")
    ));
    fs::write(&tmp, src).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    let output = Command::new("xcrun")
        .args(["--sdk", "macosx", "as", "-arch", "arm64"])
        .arg(&tmp)
        .arg("-o")
        .arg(out)
        .output()
        .map_err(|e| format!("spawn xcrun as: {e}"))?;
    let _ = fs::remove_file(&tmp);
    if !output.status.success() {
        return Err(format!(
            "xcrun as failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

pub fn compile_c(src: &str, out: &PathBuf) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-parity-{}-{}.c",
        std::process::id(),
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("t")
    ));
    fs::write(&tmp, src).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    let output = Command::new("xcrun")
        .args(["--sdk", "macosx", "clang", "-arch", "arm64", "-c"])
        .arg(&tmp)
        .arg("-o")
        .arg(out)
        .output()
        .map_err(|e| format!("spawn xcrun clang: {e}"))?;
    let _ = fs::remove_file(&tmp);
    if !output.status.success() {
        return Err(format!(
            "xcrun clang failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn compile_dylib_c(src: &str, out: &PathBuf) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "afs-ld-parity-{}-{}.c",
        std::process::id(),
        out.file_stem().and_then(|s| s.to_str()).unwrap_or("lib")
    ));
    fs::write(&tmp, src).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    let install_name = out.to_string_lossy().to_string();
    let output = Command::new("xcrun")
        .args(["--sdk", "macosx", "clang", "-arch", "arm64", "-dynamiclib"])
        .arg(&tmp)
        .arg(format!("-Wl,-install_name,{install_name}"))
        .arg("-o")
        .arg(out)
        .output()
        .map_err(|e| format!("spawn xcrun clang dylib: {e}"))?;
    let _ = fs::remove_file(&tmp);
    if !output.status.success() {
        return Err(format!(
            "xcrun clang dylib failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

pub fn load_corpus(root: &Path) -> Result<Vec<LinkCase>, String> {
    let mut cases = Vec::new();
    let entries =
        fs::read_dir(root).map_err(|e| format!("read parity corpus {}: {e}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read parity corpus entry: {e}"))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("invalid UTF-8 case directory {}", path.display()))?
            .to_string();
        let inputs_dir = path.join("inputs");
        let mut inputs = Vec::new();
        let input_entries = fs::read_dir(&inputs_dir)
            .map_err(|e| format!("read inputs for {}: {e}", path.display()))?;
        for input in input_entries {
            let input = input.map_err(|e| format!("read input entry for {}: {e}", name))?;
            let input_path = input.path();
            match input_path.extension().and_then(|s| s.to_str()) {
                Some("s") | Some("c") => inputs.push(input_path),
                _ => {}
            }
        }
        inputs.sort();
        if inputs.is_empty() {
            return Err(format!(
                "parity corpus case {} has no supported source inputs",
                path.display()
            ));
        }

        let args = read_tokens(&path.join("args.txt"))?;
        let section_checks = read_sections(&path.join("sections.txt"))?;
        let page_ref_checks = read_page_refs(&path.join("page_refs.txt"))?;
        let command_checks = read_command_checks(&path.join("command_checks.txt"))?;
        let artifacts = read_artifacts(&path.join("artifacts.txt"))?;
        let ignored_load_commands =
            read_load_command_names(&path.join("ignored_load_commands.txt"))?;
        let absent_load_commands = read_load_command_names(&path.join("absent_load_commands.txt"))?;
        let runtime_args = read_tokens_if_present(&path.join("runtime.txt"))?;
        let notes = fs::read_to_string(path.join("notes.md")).ok();
        let case_tolerances = parse_case_tolerances(notes.as_deref())?;

        cases.push(LinkCase {
            name,
            dir: path,
            inputs,
            args,
            section_checks,
            page_ref_checks,
            command_checks,
            artifacts,
            ignored_load_commands,
            absent_load_commands,
            runtime_args,
            notes,
            case_tolerances,
        });
    }

    cases.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(cases)
}

pub fn link_both(case: &LinkCase) -> Result<LinkOutputs, String> {
    let sdk = sdk_path().ok_or_else(|| "xcrun --show-sdk-path unavailable".to_string())?;
    let sdk_ver =
        sdk_version().ok_or_else(|| "xcrun --show-sdk-version unavailable".to_string())?;
    let work_dir = unique_temp_dir(&case.name)?;
    let mut compiled = BTreeMap::new();
    let mut sidecars = BTreeMap::new();
    let mut artifacts = BTreeMap::new();
    for input in &case.inputs {
        let stem = input
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("invalid input stem {}", input.display()))?;
        let src = fs::read_to_string(input)
            .map_err(|e| format!("read parity input {}: {e}", input.display()))?;
        match input.extension().and_then(|s| s.to_str()) {
            Some("s") => {
                let obj = work_dir.join(format!("{stem}.o"));
                assemble(&src, &obj)?;
                compiled.insert(format!("{stem}.o"), obj);
            }
            Some("c") => {
                let obj = work_dir.join(format!("{stem}.o"));
                compile_c(&src, &obj)?;
                compiled.insert(format!("{stem}.o"), obj);
            }
            other => {
                return Err(format!(
                    "unsupported parity input extension {:?} for {}",
                    other,
                    input.display()
                ));
            }
        }
    }
    let files_dir = case.dir.join("files");
    if files_dir.is_dir() {
        for entry in fs::read_dir(&files_dir)
            .map_err(|e| format!("read sidecar files for {}: {e}", case.name))?
        {
            let entry = entry.map_err(|e| format!("read sidecar entry for {}: {e}", case.name))?;
            let src = entry.path();
            if !src.is_file() {
                continue;
            }
            let name = src
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| format!("invalid sidecar file name {}", src.display()))?
                .to_string();
            let dst = work_dir.join(&name);
            fs::copy(&src, &dst)
                .map_err(|e| format!("copy sidecar {} -> {}: {e}", src.display(), dst.display()))?;
            sidecars.insert(name, dst);
        }
    }
    for artifact in &case.artifacts {
        let src = case.dir.join("inputs").join(&artifact.src_name);
        let src_contents = fs::read_to_string(&src)
            .map_err(|e| format!("read artifact src {}: {e}", src.display()))?;
        let out = work_dir.join(&artifact.out_name);
        match artifact.kind {
            ArtifactKind::ClangDylib => compile_dylib_c(&src_contents, &out)?,
        }
        artifacts.insert(artifact.out_name.clone(), out);
    }

    let suffix = if case.args.iter().any(|arg| arg == "-dylib") {
        "dylib"
    } else {
        "out"
    };
    let our_path = work_dir.join(format!("ours.{suffix}"));
    let their_path = work_dir.join(format!("apple.{suffix}"));

    let our_args = expand_args(
        &case.args, &compiled, &sidecars, &artifacts, &our_path, &sdk, &sdk_ver,
    )?;
    let their_args = expand_args(
        &case.args,
        &compiled,
        &sidecars,
        &artifacts,
        &their_path,
        &sdk,
        &sdk_ver,
    )?;

    let our_output = Command::new(env!("CARGO_BIN_EXE_afs-ld"))
        .args(&our_args)
        .output()
        .map_err(|e| format!("spawn afs-ld: {e}"))?;
    if !our_output.status.success() {
        return Err(format!(
            "afs-ld failed for {}:\n{}",
            case.name,
            String::from_utf8_lossy(&our_output.stderr)
        ));
    }

    let their_output = Command::new("xcrun")
        .arg("ld")
        .args(&their_args)
        .output()
        .map_err(|e| format!("spawn xcrun ld: {e}"))?;
    if !their_output.status.success() {
        return Err(format!(
            "Apple ld failed for {}:\n{}",
            case.name,
            String::from_utf8_lossy(&their_output.stderr)
        ));
    }

    let ours = fs::read(&our_path)
        .map_err(|e| format!("read afs-ld output {}: {e}", our_path.display()))?;
    let theirs = fs::read(&their_path)
        .map_err(|e| format!("read Apple ld output {}: {e}", their_path.display()))?;

    Ok(LinkOutputs {
        ours,
        theirs,
        our_path,
        their_path,
    })
}

pub fn command_ids(bytes: &[u8]) -> Result<Vec<u32>, String> {
    let header = parse_header(bytes).map_err(|e| format!("parse header: {e}"))?;
    let commands = parse_commands(&header, bytes).map_err(|e| format!("parse commands: {e}"))?;
    Ok(commands
        .into_iter()
        .map(|cmd| match cmd {
            LoadCommand::Segment64(_) => LC_SEGMENT_64,
            LoadCommand::Symtab(_) => LC_SYMTAB,
            LoadCommand::Dysymtab(_) => LC_DYSYMTAB,
            LoadCommand::BuildVersion(_) => LC_BUILD_VERSION,
            LoadCommand::DyldInfoOnly(_) => LC_DYLD_INFO_ONLY,
            LoadCommand::Dylib(d) => d.cmd,
            LoadCommand::Raw { cmd, .. } => cmd,
            other => panic!("unexpected load command in command_ids helper: {other:?}"),
        })
        .collect())
}

pub fn compare_command_ids(ours: &[u8], theirs: &[u8], ignored: &[u32]) -> Result<(), String> {
    let our_ids: Vec<u32> = command_ids(ours)?
        .into_iter()
        .filter(|cmd| !ignored.contains(cmd))
        .collect();
    let their_ids: Vec<u32> = command_ids(theirs)?
        .into_iter()
        .filter(|cmd| !ignored.contains(cmd))
        .collect();
    if our_ids != their_ids {
        return Err(format!(
            "load-command ids differ:\nours:   {our_ids:#x?}\ntheirs: {their_ids:#x?}"
        ));
    }
    Ok(())
}

pub fn compare_command_details(
    ours: &[u8],
    theirs: &[u8],
    checks: &[CommandCheck],
) -> Result<(), String> {
    for check in checks {
        match check {
            CommandCheck::BuildVersion => {
                let ours = normalized_build_version(ours)?;
                let theirs = normalized_build_version(theirs)?;
                if ours != theirs {
                    return Err(format!(
                        "LC_BUILD_VERSION diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
                }
            }
            CommandCheck::LoadDylibNames => {
                let ours = load_dylib_names(ours)?;
                let theirs = load_dylib_names(theirs)?;
                if ours != theirs {
                    return Err(format!(
                        "LC_LOAD_DYLIB names diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
                }
            }
            CommandCheck::ExportRecords => {
                let ours = canonical_export_records(ours)?;
                let theirs = canonical_export_records(theirs)?;
                if ours != theirs {
                    return Err(format!(
                        "canonical export records diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
                }
            }
            CommandCheck::SymbolRecordMap => {
                let ours = canonical_symbol_record_map(ours)?;
                let theirs = canonical_symbol_record_map(theirs)?;
                if ours != theirs {
                    return Err(format!(
                        "canonical symbol record map diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
                }
            }
            CommandCheck::DyldInfoRebase => {
                let ours = dyld_info_stream(ours, DyldInfoStreamKind::Rebase)?;
                let theirs = dyld_info_stream(theirs, DyldInfoStreamKind::Rebase)?;
                if ours != theirs {
                    return Err("rebase stream diverged".to_string());
                }
            }
            CommandCheck::DyldInfoBind => {
                let ours = dyld_info_stream(ours, DyldInfoStreamKind::Bind)?;
                let theirs = dyld_info_stream(theirs, DyldInfoStreamKind::Bind)?;
                if ours != theirs {
                    return Err("bind stream diverged".to_string());
                }
            }
            CommandCheck::DyldInfoWeakBind => {
                let ours = dyld_info_stream(ours, DyldInfoStreamKind::WeakBind)?;
                let theirs = dyld_info_stream(theirs, DyldInfoStreamKind::WeakBind)?;
                if ours != theirs {
                    return Err("weak-bind stream diverged".to_string());
                }
            }
            CommandCheck::DyldInfoLazyBind => {
                let ours = dyld_info_stream(ours, DyldInfoStreamKind::LazyBind)?;
                let theirs = dyld_info_stream(theirs, DyldInfoStreamKind::LazyBind)?;
                if ours != theirs {
                    return Err("lazy-bind stream diverged".to_string());
                }
            }
        }
    }
    Ok(())
}

pub fn ensure_absent_load_commands(
    bytes: &[u8],
    commands: &[u32],
    side: &str,
) -> Result<(), String> {
    let ids = command_ids(bytes)?;
    for command in commands {
        if ids.contains(command) {
            return Err(format!(
                "{side} unexpectedly emitted {}",
                load_command_name(*command)
            ));
        }
    }
    Ok(())
}

pub fn output_section(bytes: &[u8], segname: &str, sectname: &str) -> Option<(u64, Vec<u8>)> {
    let header = parse_header(bytes).ok()?;
    let commands = parse_commands(&header, bytes).ok()?;
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            for section in seg.sections {
                if section.segname_str() == segname && section.sectname_str() == sectname {
                    let data = if section.offset == 0 {
                        Vec::new()
                    } else {
                        let start = section.offset as usize;
                        let end = start + section.size as usize;
                        bytes.get(start..end)?.to_vec()
                    };
                    return Some((section.addr, data));
                }
            }
        }
    }
    None
}

pub fn compare_sections(
    ours: &[u8],
    theirs: &[u8],
    sections: &[(String, String)],
    case_tolerances: &[CaseTolerance],
) -> Result<(), String> {
    for (segname, sectname) in sections {
        let (_, our_bytes) = output_section(ours, segname, sectname)
            .ok_or_else(|| format!("missing section {segname},{sectname} in afs-ld output"))?;
        let (_, their_bytes) = output_section(theirs, segname, sectname)
            .ok_or_else(|| format!("missing section {segname},{sectname} in Apple output"))?;
        let diff = apply_section_tolerances(
            diff_macho(&our_bytes, &their_bytes),
            segname,
            sectname,
            case_tolerances,
        );
        if !diff.is_clean() {
            return Err(format!(
                "section bytes differ for {segname},{sectname}: {:#?}",
                diff.critical
            ));
        }
    }
    Ok(())
}

pub fn compare_page_refs(
    ours: &[u8],
    theirs: &[u8],
    checks: &[PageRefCheck],
) -> Result<(), String> {
    if checks.is_empty() {
        return Ok(());
    }
    let our_symbols = symbol_values(ours)?;
    let their_symbols = symbol_values(theirs)?;
    for check in checks {
        let (our_addr, our_bytes) = output_section(ours, &check.segname, &check.sectname)
            .ok_or_else(|| {
                format!(
                    "missing section {},{} in afs-ld output",
                    check.segname, check.sectname
                )
            })?;
        let (their_addr, their_bytes) = output_section(theirs, &check.segname, &check.sectname)
            .ok_or_else(|| {
                format!(
                    "missing section {},{} in Apple output",
                    check.segname, check.sectname
                )
            })?;
        let our_target =
            decode_page_reference(&our_bytes, our_addr, check.site_offset, check.kind)?;
        let their_target =
            decode_page_reference(&their_bytes, their_addr, check.site_offset, check.kind)?;
        let expected_ours = *our_symbols
            .get(&check.symbol)
            .ok_or_else(|| format!("missing symbol {} in afs-ld output", check.symbol))?;
        let expected_theirs = *their_symbols
            .get(&check.symbol)
            .ok_or_else(|| format!("missing symbol {} in Apple output", check.symbol))?;
        if our_target != expected_ours || their_target != expected_theirs {
            return Err(format!(
                "page ref {},{}+0x{:x} -> {} diverged: ours=0x{:x} expected=0x{:x}; theirs=0x{:x} expected=0x{:x}",
                check.segname,
                check.sectname,
                check.site_offset,
                check.symbol,
                our_target,
                expected_ours,
                their_target,
                expected_theirs,
            ));
        }
    }
    Ok(())
}

pub fn run_program(path: &Path, args: &[String]) -> Result<ProgramOutput, String> {
    let output = Command::new(path)
        .args(args)
        .output()
        .map_err(|e| format!("run {}: {e}", path.display()))?;
    Ok(ProgramOutput {
        exit_code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

pub fn compare_runtime(our_path: &Path, their_path: &Path, args: &[String]) -> Result<(), String> {
    let ours = run_program(our_path, args)?;
    let theirs = run_program(their_path, args)?;
    if ours != theirs {
        return Err(format!(
            "runtime differs:\nours: exit={:?} stdout={:?} stderr={:?}\ntheirs: exit={:?} stdout={:?} stderr={:?}",
            ours.exit_code,
            String::from_utf8_lossy(&ours.stdout),
            String::from_utf8_lossy(&ours.stderr),
            theirs.exit_code,
            String::from_utf8_lossy(&theirs.stdout),
            String::from_utf8_lossy(&theirs.stderr),
        ));
    }
    Ok(())
}

/// Byte-level diff between two Mach-O images or section byte slices.
///
/// Sprint 27 starts tolerating a very small allowlist: UUID command bytes and
/// code-signature command/blob bytes at matching offsets. Unknown diffs remain
/// critical.
pub fn diff_macho(ours: &[u8], theirs: &[u8]) -> DiffReport {
    let mut report = DiffReport::default();

    if ours.len() != theirs.len() {
        report.critical.push(DiffChunk {
            offset: 0,
            len: ours.len().max(theirs.len()),
            reason: format!(
                "total size differs: ours = {}, theirs = {}",
                ours.len(),
                theirs.len()
            ),
            category: DiffCategory::Critical,
        });
        return report;
    }

    let our_mask = tolerated_mask(ours);
    let their_mask = tolerated_mask(theirs);

    let mut i = 0;
    while i < ours.len() {
        if ours[i] == theirs[i] {
            i += 1;
            continue;
        }

        let tolerated_reason = match (our_mask[i], their_mask[i]) {
            (Some(left), Some(right)) if left == right => Some(left),
            _ => None,
        };
        let start = i;
        i += 1;
        while i < ours.len() && ours[i] != theirs[i] {
            let same_category = match tolerated_reason {
                Some(reason) => matches!(
                    (our_mask[i], their_mask[i]),
                    (Some(left), Some(right)) if left == reason && right == reason
                ),
                None => !matches!(
                    (our_mask[i], their_mask[i]),
                    (Some(left), Some(right)) if left == right
                ),
            };
            if !same_category {
                break;
            }
            i += 1;
        }

        let len = i - start;
        if let Some(reason) = tolerated_reason {
            report.tolerated.push(DiffChunk {
                offset: start,
                len,
                reason: reason.to_string(),
                category: DiffCategory::Tolerated(reason),
            });
        } else {
            report.critical.push(DiffChunk {
                offset: start,
                len,
                reason: format!("{} byte(s) differ starting at 0x{start:x}", len),
                category: DiffCategory::Critical,
            });
        }
    }

    report
}

pub fn parse_case_tolerances(notes: Option<&str>) -> Result<Vec<CaseTolerance>, String> {
    let Some(notes) = notes else {
        return Ok(Vec::new());
    };

    let mut tolerances = Vec::new();
    let mut in_block = false;
    for raw_line in notes.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "tolerated:" {
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        if !line.starts_with("- region:") {
            // Stop once the simple tolerated block ends.
            if !line.starts_with('#') && !raw_line.starts_with(' ') && !raw_line.starts_with('\t') {
                break;
            }
            continue;
        }
        tolerances.push(parse_case_tolerance_line(line)?);
    }
    Ok(tolerances)
}

pub fn apply_section_tolerances(
    mut diff: DiffReport,
    segname: &str,
    sectname: &str,
    case_tolerances: &[CaseTolerance],
) -> DiffReport {
    if diff.critical.is_empty() || case_tolerances.is_empty() {
        return diff;
    }

    let mut remaining = Vec::new();
    for chunk in diff.critical.drain(..) {
        let tolerated = case_tolerances.iter().find(|tol| {
            tolerance_covers_chunk(tol, segname, sectname, chunk.offset, chunk.len)
        });
        if let Some(tol) = tolerated {
            diff.tolerated.push(DiffChunk {
                offset: chunk.offset,
                len: chunk.len,
                reason: tol.reason.clone(),
                category: DiffCategory::Tolerated("case-note"),
            });
        } else {
            remaining.push(chunk);
        }
    }
    diff.critical = remaining;
    diff
}

fn unique_temp_dir(case_name: &str) -> Result<PathBuf, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("clock error: {e}"))?
        .as_nanos();
    let safe_name = case_name.replace(['/', ' '], "-");
    let dir = std::env::temp_dir().join(format!(
        "afs-ld-parity-{}-{safe_name}-{stamp}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    Ok(dir)
}

fn parse_case_tolerance_line(line: &str) -> Result<CaseTolerance, String> {
    let rest = line
        .strip_prefix("- region:")
        .ok_or_else(|| format!("invalid tolerance line `{line}`"))?
        .trim();
    let (before_reason, reason_part) = rest
        .split_once(" reason:")
        .ok_or_else(|| format!("missing `reason:` in tolerance line `{line}`"))?;
    let (region_part, bytes_part) = before_reason
        .split_once(" bytes ")
        .ok_or_else(|| format!("missing `bytes` range in tolerance line `{line}`"))?;
    let reason = reason_part.trim().trim_matches('"').to_string();
    if reason.is_empty() {
        return Err(format!("empty tolerance reason in `{line}`"));
    }
    let (start, end_inclusive) = parse_tolerance_range(bytes_part.trim())?;
    let region_token = region_part.trim();
    let (segname, sectname) = match region_token.split_once(',') {
        Some((segname, sectname)) => (segname.trim().to_string(), Some(sectname.trim().to_string())),
        None => (region_token.to_string(), None),
    };
    if segname.is_empty() {
        return Err(format!("empty tolerance region in `{line}`"));
    }
    Ok(CaseTolerance {
        region: ToleranceRegion::SectionBytes {
            segname,
            sectname,
            start,
            end_inclusive,
        },
        reason,
    })
}

fn parse_tolerance_range(range: &str) -> Result<(usize, usize), String> {
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| format!("invalid tolerance range `{range}`"))?;
    let start = parse_usize(start.trim())?;
    let end = parse_usize(end.trim())?;
    if end < start {
        return Err(format!("tolerance range end before start in `{range}`"));
    }
    Ok((start, end))
}

fn parse_usize(token: &str) -> Result<usize, String> {
    if let Some(rest) = token.strip_prefix("0x") {
        usize::from_str_radix(rest, 16).map_err(|e| format!("parse usize `{token}`: {e}"))
    } else {
        token
            .parse::<usize>()
            .map_err(|e| format!("parse usize `{token}`: {e}"))
    }
}

fn tolerance_covers_chunk(
    tolerance: &CaseTolerance,
    segname: &str,
    sectname: &str,
    offset: usize,
    len: usize,
) -> bool {
    match &tolerance.region {
        ToleranceRegion::SectionBytes {
            segname: expected_seg,
            sectname: expected_sect,
            start,
            end_inclusive,
        } => {
            if expected_seg != segname {
                return false;
            }
            if let Some(expected_sect) = expected_sect {
                if expected_sect != sectname {
                    return false;
                }
            }
            let end = offset.saturating_add(len.saturating_sub(1));
            offset >= *start && end <= *end_inclusive
        }
    }
}

fn read_tokens(path: &Path) -> Result<Vec<String>, String> {
    let contents = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect())
}

fn read_tokens_if_present(path: &Path) -> Result<Vec<String>, String> {
    if path.exists() {
        read_tokens(path)
    } else {
        Ok(Vec::new())
    }
}

fn read_sections(path: &Path) -> Result<Vec<(String, String)>, String> {
    let mut sections = Vec::new();
    for line in read_tokens(path)? {
        let mut parts = line.split_whitespace();
        let segname = parts
            .next()
            .ok_or_else(|| format!("missing segment name in {}", path.display()))?;
        let sectname = parts
            .next()
            .ok_or_else(|| format!("missing section name in {}", path.display()))?;
        if parts.next().is_some() {
            return Err(format!(
                "too many fields in section spec `{line}` from {}",
                path.display()
            ));
        }
        sections.push((segname.to_string(), sectname.to_string()));
    }
    Ok(sections)
}

fn read_load_command_names(path: &Path) -> Result<Vec<u32>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut commands = Vec::new();
    for line in read_tokens(path)? {
        commands.push(parse_load_command_name(&line)?);
    }
    Ok(commands)
}

fn read_command_checks(path: &Path) -> Result<Vec<CommandCheck>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut checks = Vec::new();
    for line in read_tokens(path)? {
        checks.push(parse_command_check(&line)?);
    }
    Ok(checks)
}

fn read_page_refs(path: &Path) -> Result<Vec<PageRefCheck>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut checks = Vec::new();
    for line in read_tokens(path)? {
        let mut parts = line.split_whitespace();
        let segname = parts
            .next()
            .ok_or_else(|| format!("missing segment name in {}", path.display()))?;
        let sectname = parts
            .next()
            .ok_or_else(|| format!("missing section name in {}", path.display()))?;
        let site_offset = parts
            .next()
            .ok_or_else(|| format!("missing site offset in {}", path.display()))?;
        let kind = parts
            .next()
            .ok_or_else(|| format!("missing page-ref kind in {}", path.display()))?;
        let symbol = parts
            .next()
            .ok_or_else(|| format!("missing symbol name in {}", path.display()))?;
        if parts.next().is_some() {
            return Err(format!(
                "too many fields in page-ref spec `{line}` from {}",
                path.display()
            ));
        }
        checks.push(PageRefCheck {
            segname: segname.to_string(),
            sectname: sectname.to_string(),
            site_offset: parse_u64(site_offset)?,
            kind: parse_page_ref_kind(kind)?,
            symbol: symbol.to_string(),
        });
    }
    Ok(checks)
}

fn read_artifacts(path: &Path) -> Result<Vec<ArtifactSpec>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut specs = Vec::new();
    for line in read_tokens(path)? {
        let mut parts = line.split_whitespace();
        let kind = parts
            .next()
            .ok_or_else(|| format!("missing artifact kind in {}", path.display()))?;
        let src_name = parts
            .next()
            .ok_or_else(|| format!("missing artifact src in {}", path.display()))?;
        let out_name = parts
            .next()
            .ok_or_else(|| format!("missing artifact output in {}", path.display()))?;
        if parts.next().is_some() {
            return Err(format!(
                "too many fields in artifact spec `{line}` from {}",
                path.display()
            ));
        }
        let kind = match kind {
            "clang_dylib" => ArtifactKind::ClangDylib,
            other => return Err(format!("unknown artifact kind `{other}`")),
        };
        specs.push(ArtifactSpec {
            src_name: src_name.to_string(),
            out_name: out_name.to_string(),
            kind,
        });
    }
    Ok(specs)
}

fn parse_command_check(name: &str) -> Result<CommandCheck, String> {
    match name {
        "build_version" => Ok(CommandCheck::BuildVersion),
        "load_dylib_names" => Ok(CommandCheck::LoadDylibNames),
        "export_records" => Ok(CommandCheck::ExportRecords),
        "symbol_record_map" => Ok(CommandCheck::SymbolRecordMap),
        "dyld_info_rebase" => Ok(CommandCheck::DyldInfoRebase),
        "dyld_info_bind" => Ok(CommandCheck::DyldInfoBind),
        "dyld_info_weak_bind" => Ok(CommandCheck::DyldInfoWeakBind),
        "dyld_info_lazy_bind" => Ok(CommandCheck::DyldInfoLazyBind),
        other => Err(format!("unknown command check `{other}`")),
    }
}

fn parse_page_ref_kind(kind: &str) -> Result<PageRefKind, String> {
    match kind {
        "add" => Ok(PageRefKind::Add),
        "load" => Ok(PageRefKind::Load),
        other => Err(format!("unknown page-ref kind `{other}`")),
    }
}

fn parse_load_command_name(name: &str) -> Result<u32, String> {
    match name {
        "LC_LOAD_DYLIB" => Ok(LC_LOAD_DYLIB),
        "LC_UUID" => Ok(LC_UUID),
        "LC_CODE_SIGNATURE" => Ok(LC_CODE_SIGNATURE),
        "LC_LINKER_OPTIMIZATION_HINT" => Ok(afs_ld::macho::constants::LC_LINKER_OPTIMIZATION_HINT),
        other => Err(format!("unknown load command name `{other}`")),
    }
}

fn load_command_name(cmd: u32) -> &'static str {
    match cmd {
        LC_LOAD_DYLIB => "LC_LOAD_DYLIB",
        LC_UUID => "LC_UUID",
        LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE",
        afs_ld::macho::constants::LC_LINKER_OPTIMIZATION_HINT => "LC_LINKER_OPTIMIZATION_HINT",
        _ => "unknown load command",
    }
}

fn parse_u64(value: &str) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|e| format!("parse hex `{value}`: {e}"))
    } else {
        value
            .parse::<u64>()
            .map_err(|e| format!("parse integer `{value}`: {e}"))
    }
}

fn expand_args(
    args: &[String],
    compiled: &BTreeMap<String, PathBuf>,
    sidecars: &BTreeMap<String, PathBuf>,
    artifacts: &BTreeMap<String, PathBuf>,
    out: &Path,
    sdk: &str,
    sdk_ver: &str,
) -> Result<Vec<String>, String> {
    let mut expanded = Vec::with_capacity(args.len());
    for arg in args {
        if arg == "@OUT@" {
            expanded.push(out.to_string_lossy().to_string());
            continue;
        }
        if arg == "@SDK_PATH@" {
            expanded.push(sdk.to_string());
            continue;
        }
        if arg == "@SDK_VERSION@" {
            expanded.push(sdk_ver.to_string());
            continue;
        }
        if let Some(rel) = arg
            .strip_prefix("@SDK_TBD:")
            .and_then(|rest| rest.strip_suffix('@'))
        {
            expanded.push(Path::new(sdk).join(rel).to_string_lossy().to_string());
            continue;
        }
        if let Some(name) = arg
            .strip_prefix("@INPUT:")
            .and_then(|rest| rest.strip_suffix('@'))
        {
            let input = compiled
                .get(name)
                .ok_or_else(|| format!("unknown parity input placeholder `{name}`"))?;
            expanded.push(input.to_string_lossy().to_string());
            continue;
        }
        if let Some(name) = arg
            .strip_prefix("@FILE:")
            .and_then(|rest| rest.strip_suffix('@'))
        {
            let file = sidecars
                .get(name)
                .ok_or_else(|| format!("unknown parity sidecar placeholder `{name}`"))?;
            expanded.push(file.to_string_lossy().to_string());
            continue;
        }
        if let Some(name) = arg
            .strip_prefix("@ARTIFACT:")
            .and_then(|rest| rest.strip_suffix('@'))
        {
            let artifact = artifacts
                .get(name)
                .ok_or_else(|| format!("unknown parity artifact placeholder `{name}`"))?;
            expanded.push(artifact.to_string_lossy().to_string());
            continue;
        }
        expanded.push(arg.clone());
    }
    Ok(expanded)
}

fn tolerated_mask(bytes: &[u8]) -> Vec<Option<&'static str>> {
    let mut mask = vec![None; bytes.len()];
    let Ok(header) = parse_header(bytes) else {
        return mask;
    };
    let cmd_base = 32usize;
    let Ok(cmd_limit) = cmd_base.checked_add(header.sizeofcmds as usize).ok_or(()) else {
        return mask;
    };
    if cmd_limit > bytes.len() {
        return mask;
    }

    let mut cursor = cmd_base;
    for _ in 0..header.ncmds {
        if cursor + 8 > cmd_limit {
            break;
        }
        let cmd = u32_le(&bytes[cursor..cursor + 4]);
        let cmdsize = u32_le(&bytes[cursor + 4..cursor + 8]) as usize;
        if cmdsize < 8 || cursor + cmdsize > cmd_limit {
            break;
        }
        match cmd {
            LC_UUID => mark_range(&mut mask, cursor, cursor + cmdsize, "UUID bytes"),
            LC_CODE_SIGNATURE => {
                mark_range(
                    &mut mask,
                    cursor,
                    cursor + cmdsize,
                    "code-signature load command",
                );
                if cmdsize >= 16 {
                    let dataoff = u32_le(&bytes[cursor + 8..cursor + 12]) as usize;
                    let datasize = u32_le(&bytes[cursor + 12..cursor + 16]) as usize;
                    if let Some(end) = dataoff.checked_add(datasize) {
                        if end <= bytes.len() {
                            mark_range(&mut mask, dataoff, end, "code-signature hashes");
                        }
                    }
                }
            }
            _ => {}
        }
        cursor += cmdsize;
    }

    mask
}

fn mark_range(mask: &mut [Option<&'static str>], start: usize, end: usize, reason: &'static str) {
    let start = start.min(mask.len());
    let end = end.min(mask.len());
    for slot in &mut mask[start..end] {
        *slot = Some(reason);
    }
}

fn build_version_command(bytes: &[u8]) -> Result<Option<BuildVersionCmd>, String> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    Ok(commands.into_iter().find_map(|cmd| match cmd {
        LoadCommand::BuildVersion(cmd) => Some(cmd),
        _ => None,
    }))
}

fn normalized_build_version(bytes: &[u8]) -> Result<Option<NormalizedBuildVersion>, String> {
    Ok(build_version_command(bytes)?.map(|cmd| {
        (
            cmd.platform,
            cmd.minos,
            cmd.sdk,
            cmd.tools.into_iter().map(|tool| tool.tool).collect(),
        )
    }))
}

fn load_dylib_names(bytes: &[u8]) -> Result<Vec<String>, String> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    Ok(commands
        .into_iter()
        .filter_map(|cmd| match cmd {
            LoadCommand::Dylib(cmd) if cmd.cmd == LC_LOAD_DYLIB => Some(cmd.name),
            _ => None,
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalSymbolRecord {
    name: String,
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CanonicalExportKind {
    Regular(u64),
    ThreadLocal(u64),
    Absolute(u64),
    Reexport { ordinal: u32, imported_name: String },
    StubAndResolver { stub: u64, resolver: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalExportRecord {
    name: String,
    flags: u64,
    kind: CanonicalExportKind,
}

fn canonical_symbol_record_map(
    bytes: &[u8],
) -> Result<BTreeMap<String, CanonicalSymbolRecord>, String> {
    Ok(canonical_symbol_records(bytes)?
        .into_iter()
        .map(|record| (record.name.clone(), record))
        .collect())
}

fn canonical_symbol_records(bytes: &[u8]) -> Result<Vec<CanonicalSymbolRecord>, String> {
    let (symtab, _) = symtab_and_dysymtab(bytes)?;
    let symbols =
        parse_nlist_table(bytes, symtab.symoff, symtab.nsyms).map_err(|e| e.to_string())?;
    let strings =
        StringTable::from_file(bytes, symtab.stroff, symtab.strsize).map_err(|e| e.to_string())?;
    let section_addrs = section_addrs(bytes)?;
    Ok(symbols
        .iter()
        .map(|symbol| {
            let value = if symbol.kind() == SymKind::Sect && symbol.sect_idx() != 0 {
                let section_addr = section_addrs[symbol.sect_idx() as usize - 1];
                if symbol.value() >= section_addr {
                    symbol.value() - section_addr
                } else {
                    symbol.value()
                }
            } else {
                symbol.value()
            };
            CanonicalSymbolRecord {
                name: strings.get(symbol.strx()).unwrap().to_string(),
                n_type: symbol.raw.n_type,
                n_sect: symbol.raw.n_sect,
                n_desc: symbol.raw.n_desc,
                value,
            }
        })
        .collect())
}

fn canonical_export_records(bytes: &[u8]) -> Result<Vec<CanonicalExportRecord>, String> {
    let dylib = DylibFile::parse("/tmp/canonical.dylib", bytes).map_err(|e| e.to_string())?;
    let symbol_values: BTreeMap<String, u64> = canonical_symbol_records(bytes)?
        .into_iter()
        .map(|record| (record.name, record.value))
        .collect();
    let mut out = dylib
        .exports
        .entries()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|entry| {
            let kind = match entry.kind {
                ExportKind::Regular { .. } => {
                    CanonicalExportKind::Regular(*symbol_values.get(&entry.name).unwrap())
                }
                ExportKind::ThreadLocal { .. } => {
                    CanonicalExportKind::ThreadLocal(*symbol_values.get(&entry.name).unwrap())
                }
                ExportKind::Absolute { .. } => {
                    CanonicalExportKind::Absolute(*symbol_values.get(&entry.name).unwrap())
                }
                ExportKind::Reexport {
                    ordinal,
                    imported_name,
                } => CanonicalExportKind::Reexport {
                    ordinal,
                    imported_name,
                },
                ExportKind::StubAndResolver { stub, resolver } => {
                    CanonicalExportKind::StubAndResolver { stub, resolver }
                }
            };
            CanonicalExportRecord {
                name: entry.name,
                flags: entry.flags,
                kind,
            }
        })
        .collect::<Vec<_>>();
    out.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
    Ok(out)
}

fn symtab_and_dysymtab(
    bytes: &[u8],
) -> Result<
    (
        afs_ld::macho::reader::SymtabCmd,
        afs_ld::macho::reader::DysymtabCmd,
    ),
    String,
> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    let mut symtab = None;
    let mut dysymtab = None;
    for cmd in commands {
        match cmd {
            LoadCommand::Symtab(cmd) => symtab = Some(cmd),
            LoadCommand::Dysymtab(cmd) => dysymtab = Some(cmd),
            _ => {}
        }
    }
    Ok((
        symtab.ok_or_else(|| "missing LC_SYMTAB".to_string())?,
        dysymtab.ok_or_else(|| "missing LC_DYSYMTAB".to_string())?,
    ))
}

fn section_addrs(bytes: &[u8]) -> Result<Vec<u64>, String> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            for section in seg.sections {
                out.push(section.addr);
            }
        }
    }
    Ok(out)
}

#[derive(Clone, Copy)]
enum DyldInfoStreamKind {
    Rebase,
    Bind,
    WeakBind,
    LazyBind,
}

fn dyld_info_command(bytes: &[u8]) -> Result<DyldInfoCmd, String> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    commands
        .into_iter()
        .find_map(|cmd| match cmd {
            LoadCommand::DyldInfoOnly(cmd) => Some(cmd),
            _ => None,
        })
        .ok_or_else(|| "missing LC_DYLD_INFO_ONLY".to_string())
}

fn dyld_info_stream(bytes: &[u8], kind: DyldInfoStreamKind) -> Result<Vec<u8>, String> {
    let dyld_info = dyld_info_command(bytes)?;
    let (off, size) = match kind {
        DyldInfoStreamKind::Rebase => (dyld_info.rebase_off, dyld_info.rebase_size),
        DyldInfoStreamKind::Bind => (dyld_info.bind_off, dyld_info.bind_size),
        DyldInfoStreamKind::WeakBind => (dyld_info.weak_bind_off, dyld_info.weak_bind_size),
        DyldInfoStreamKind::LazyBind => (dyld_info.lazy_bind_off, dyld_info.lazy_bind_size),
    };
    if size == 0 {
        return Ok(Vec::new());
    }
    let start = off as usize;
    let end = start + size as usize;
    bytes
        .get(start..end)
        .map(|slice| slice.to_vec())
        .ok_or_else(|| "dyld-info stream out of bounds".to_string())
}

fn symbol_values(bytes: &[u8]) -> Result<BTreeMap<String, u64>, String> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    let symtab = commands
        .iter()
        .find_map(|cmd| match cmd {
            LoadCommand::Symtab(cmd) => Some(*cmd),
            _ => None,
        })
        .ok_or_else(|| "missing LC_SYMTAB".to_string())?;
    let symbols =
        parse_nlist_table(bytes, symtab.symoff, symtab.nsyms).map_err(|e| e.to_string())?;
    let strings =
        StringTable::from_file(bytes, symtab.stroff, symtab.strsize).map_err(|e| e.to_string())?;
    let mut out = BTreeMap::new();
    for symbol in symbols {
        let Ok(name) = strings.get(symbol.strx()) else {
            continue;
        };
        out.insert(name.to_string(), symbol.value());
    }
    Ok(out)
}

fn decode_page_reference(
    bytes: &[u8],
    section_addr: u64,
    site_offset: u64,
    kind: PageRefKind,
) -> Result<u64, String> {
    let start = site_offset as usize;
    let adrp = read_insn(bytes, start)?;
    let second = read_insn(bytes, start + 4)?;
    let place = section_addr + site_offset;
    let adrp_immlo = ((adrp >> 29) & 0x3) as i64;
    let adrp_immhi = ((adrp >> 5) & 0x7ffff) as i64;
    let adrp_pages = sign_extend_21((adrp_immhi << 2) | adrp_immlo);
    let adrp_base = ((place as i64) & !0xfff) + (adrp_pages << 12);
    let low = match kind {
        PageRefKind::Add => ((second >> 10) & 0xfff) as u64,
        PageRefKind::Load => {
            let shift = ((second >> 30) & 0b11) as u64;
            (((second >> 10) & 0xfff) as u64) << shift
        }
    };
    Ok((adrp_base as u64) + low)
}

fn read_insn(bytes: &[u8], start: usize) -> Result<u32, String> {
    let end = start + 4;
    let slice = bytes
        .get(start..end)
        .ok_or_else(|| format!("instruction read OOB at 0x{start:x}"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn sign_extend_21(value: i64) -> i64 {
    if value & (1 << 20) != 0 {
        value | !0x1f_ffff
    } else {
        value
    }
}
