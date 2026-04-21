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
    LC_BUILD_VERSION, LC_CODE_SIGNATURE, LC_DYSYMTAB, LC_DYLD_INFO_ONLY, LC_LOAD_DYLIB,
    LC_SEGMENT_64, LC_SYMTAB, LC_UUID,
};
use afs_ld::macho::reader::{parse_commands, parse_header, u32_le, LoadCommand};

#[derive(Debug, Clone)]
pub struct LinkCase {
    pub name: String,
    pub dir: PathBuf,
    pub inputs: Vec<PathBuf>,
    pub args: Vec<String>,
    pub section_checks: Vec<(String, String)>,
    pub ignored_load_commands: Vec<u32>,
    pub runtime_args: Vec<String>,
    pub notes: Option<String>,
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
            if input_path.extension().and_then(|s| s.to_str()) == Some("s") {
                inputs.push(input_path);
            }
        }
        inputs.sort();
        if inputs.is_empty() {
            return Err(format!(
                "parity corpus case {} has no .s inputs",
                path.display()
            ));
        }

        let args = read_tokens(&path.join("args.txt"))?;
        let section_checks = read_sections(&path.join("sections.txt"))?;
        let ignored_load_commands = read_load_command_names(&path.join("ignored_load_commands.txt"))?;
        let runtime_args = read_tokens_if_present(&path.join("runtime.txt"))?;
        let notes = fs::read_to_string(path.join("notes.md")).ok();

        cases.push(LinkCase {
            name,
            dir: path,
            inputs,
            args,
            section_checks,
            ignored_load_commands,
            runtime_args,
            notes,
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
    for input in &case.inputs {
        let stem = input
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("invalid input stem {}", input.display()))?;
        let src = fs::read_to_string(input)
            .map_err(|e| format!("read parity input {}: {e}", input.display()))?;
        let obj = work_dir.join(format!("{stem}.o"));
        assemble(&src, &obj)?;
        compiled.insert(format!("{stem}.o"), obj);
    }

    let suffix = if case.args.iter().any(|arg| arg == "-dylib") {
        "dylib"
    } else {
        "out"
    };
    let our_path = work_dir.join(format!("ours.{suffix}"));
    let their_path = work_dir.join(format!("apple.{suffix}"));

    let our_args = expand_args(&case.args, &compiled, &our_path, &sdk, &sdk_ver)?;
    let their_args = expand_args(&case.args, &compiled, &their_path, &sdk, &sdk_ver)?;

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
) -> Result<(), String> {
    for (segname, sectname) in sections {
        let (_, our_bytes) = output_section(ours, segname, sectname)
            .ok_or_else(|| format!("missing section {segname},{sectname} in afs-ld output"))?;
        let (_, their_bytes) = output_section(theirs, segname, sectname)
            .ok_or_else(|| format!("missing section {segname},{sectname} in Apple output"))?;
        let diff = diff_macho(&our_bytes, &their_bytes);
        if !diff.is_clean() {
            return Err(format!(
                "section bytes differ for {segname},{sectname}: {:#?}",
                diff.critical
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

fn read_tokens(path: &Path) -> Result<Vec<String>, String> {
    let contents =
        fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
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
    let mut commands = Vec::new();
    for line in read_tokens(path)? {
        commands.push(parse_load_command_name(&line)?);
    }
    Ok(commands)
}

fn parse_load_command_name(name: &str) -> Result<u32, String> {
    match name {
        "LC_LOAD_DYLIB" => Ok(LC_LOAD_DYLIB),
        "LC_UUID" => Ok(LC_UUID),
        "LC_CODE_SIGNATURE" => Ok(LC_CODE_SIGNATURE),
        other => Err(format!("unknown load command name `{other}`")),
    }
}

fn expand_args(
    args: &[String],
    compiled: &BTreeMap<String, PathBuf>,
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
    let Ok(cmd_limit) = cmd_base
        .checked_add(header.sizeofcmds as usize)
        .ok_or(())
    else {
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
