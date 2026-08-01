//! Differential harness shared by parity-oriented integration tests.
//!
//! The early scaffold only diffed arbitrary byte slices. Sprint 27 starts
//! turning it into a real Apple-`ld` matrix harness with a tiny corpus, basic
//! tolerated-diff rules, and reusable link/runtime helpers.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use afs_ld::leb::{read_sleb, read_uleb};
use afs_ld::macho::constants::{
    BIND_IMMEDIATE_MASK, BIND_OPCODE_ADD_ADDR_ULEB, BIND_OPCODE_DONE, BIND_OPCODE_DO_BIND,
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED, BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, BIND_OPCODE_MASK, BIND_OPCODE_SET_ADDEND_SLEB,
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM, BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM, BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, BIND_OPCODE_SET_TYPE_IMM,
    BIND_SYMBOL_FLAGS_WEAK_IMPORT, BIND_TYPE_POINTER, INDIRECT_SYMBOL_ABS, INDIRECT_SYMBOL_LOCAL,
    LC_BUILD_VERSION, LC_CODE_SIGNATURE, LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS,
    LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO_ONLY, LC_DYSYMTAB, LC_FUNCTION_STARTS, LC_ID_DYLIB,
    LC_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_SEGMENT_64,
    LC_SYMTAB, LC_UUID, N_ABS, N_SECT, N_TYPE, N_UNDF,
};
use afs_ld::macho::exports::{ExportKind, Exports};
use afs_ld::macho::reader::{
    parse_commands, parse_header, u32_le, BuildVersionCmd, DyldInfoCmd, LoadCommand,
    Section64Header,
};
use afs_ld::string_table::StringTable;
use afs_ld::symbol::{parse_nlist_table, SymKind};
use afs_ld::synth::stubs::{STUB_HELPER_ENTRY_SIZE, STUB_HELPER_HEADER_SIZE};
use afs_ld::synth::unwind::decode_unwind_info;

#[derive(Debug, Clone)]
pub struct LinkCase {
    pub name: String,
    pub dir: PathBuf,
    pub inputs: Vec<PathBuf>,
    pub args: Vec<String>,
    pub section_checks: Vec<(String, String)>,
    pub absent_sections: Vec<(String, String)>,
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
    IndirectSymbolIdentities,
    SymbolPartitionNames,
    StringTableNearParity,
    FunctionStarts,
    NormalizedFunctionStarts,
    DataInCode,
    DataInCodeIfPresent,
    RebasedUnwindBytes,
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
    dep_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactKind {
    Dylib,
    Archive,
    ReexportDylib,
}

type SymbolPartitions = (Vec<String>, Vec<String>, Vec<String>);

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
    let tmp = out.with_extension("s");
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
    let tmp = out.with_extension("c");
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
    let tmp = out.with_extension("c");
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

fn compile_archive_c(src: &str, out: &PathBuf) -> Result<(), String> {
    let obj = out.with_extension("o");
    compile_c(src, &obj)?;
    let output = Command::new("libtool")
        .args(["-static", "-o"])
        .arg(out)
        .arg(&obj)
        .output()
        .map_err(|e| format!("spawn libtool archive: {e}"))?;
    let _ = fs::remove_file(&obj);
    if !output.status.success() {
        return Err(format!(
            "libtool archive failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn compile_reexport_dylib_c(src: &str, out: &PathBuf, dep: &Path) -> Result<(), String> {
    let tmp = out.with_extension("c");
    fs::write(&tmp, src).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    let install_name = out.to_string_lossy().to_string();
    let output = Command::new("xcrun")
        .args(["--sdk", "macosx", "clang", "-arch", "arm64", "-dynamiclib"])
        .arg(&tmp)
        .arg(format!("-Wl,-install_name,{install_name}"))
        .arg(format!("-Wl,-reexport_library,{}", dep.display()))
        .arg("-o")
        .arg(out)
        .output()
        .map_err(|e| format!("spawn xcrun clang reexport dylib: {e}"))?;
    let _ = fs::remove_file(&tmp);
    if !output.status.success() {
        return Err(format!(
            "xcrun clang reexport dylib failed: {}",
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
                Some("s") | Some("c") | Some("o") | Some("a") | Some("tbd") => {
                    inputs.push(input_path)
                }
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
        let absent_sections = read_sections_if_present(&path.join("absent_sections.txt"))?;
        let page_ref_checks = read_page_refs(&path.join("page_refs.txt"))?;
        let command_checks = read_command_checks(&path.join("command_checks.txt"))?;
        let artifacts = read_artifacts(&path.join("artifacts.txt"))?;
        let artifact_srcs: HashSet<&str> = artifacts
            .iter()
            .map(|artifact| artifact.src_name.as_str())
            .collect();
        inputs.retain(|input| {
            input
                .file_name()
                .and_then(|s| s.to_str())
                .map(|name| !artifact_srcs.contains(name))
                .unwrap_or(true)
        });
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
            absent_sections,
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
    let mut compiled: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut sidecars: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut artifacts: BTreeMap<String, PathBuf> = BTreeMap::new();
    for input in &case.inputs {
        let stem = input
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("invalid input stem {}", input.display()))?;
        match input.extension().and_then(|s| s.to_str()) {
            Some("s") => {
                let src = fs::read_to_string(input)
                    .map_err(|e| format!("read parity input {}: {e}", input.display()))?;
                let obj = work_dir.join(format!("{stem}.o"));
                assemble(&src, &obj)?;
                compiled.insert(format!("{stem}.o"), obj);
            }
            Some("c") => {
                let src = fs::read_to_string(input)
                    .map_err(|e| format!("read parity input {}: {e}", input.display()))?;
                let obj = work_dir.join(format!("{stem}.o"));
                compile_c(&src, &obj)?;
                compiled.insert(format!("{stem}.o"), obj);
            }
            Some("o") | Some("a") | Some("tbd") => {
                let copied = work_dir.join(
                    input
                        .file_name()
                        .ok_or_else(|| format!("invalid input file name {}", input.display()))?,
                );
                fs::copy(input, &copied).map_err(|e| {
                    format!(
                        "copy parity input {} -> {}: {e}",
                        input.display(),
                        copied.display()
                    )
                })?;
                compiled.insert(
                    input
                        .file_name()
                        .and_then(|s| s.to_str())
                        .ok_or_else(|| format!("invalid UTF-8 input file {}", input.display()))?
                        .to_string(),
                    copied,
                );
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
            ArtifactKind::Dylib => compile_dylib_c(&src_contents, &out)?,
            ArtifactKind::Archive => compile_archive_c(&src_contents, &out)?,
            ArtifactKind::ReexportDylib => {
                let dep_name = artifact.dep_name.as_ref().ok_or_else(|| {
                    format!(
                        "missing reexport dependency for artifact {}",
                        artifact.out_name
                    )
                })?;
                let dep = artifacts
                    .get(dep_name)
                    .ok_or_else(|| format!("unknown reexport dependency `{dep_name}`"))?;
                compile_reexport_dylib_c(&src_contents, &out, dep)?;
            }
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
            LoadCommand::DyldChainedFixups(_) => LC_DYLD_CHAINED_FIXUPS,
            LoadCommand::DyldExportsTrie(_) => LC_DYLD_EXPORTS_TRIE,
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
            CommandCheck::IndirectSymbolIdentities => {
                let ours = indirect_symbol_identities(ours)?;
                let theirs = indirect_symbol_identities(theirs)?;
                if ours != theirs {
                    return Err(format!(
                        "indirect symbol identities diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
                }
            }
            CommandCheck::SymbolPartitionNames => {
                let ours = symbol_partition_names(ours)?;
                let theirs = symbol_partition_names(theirs)?;
                if ours != theirs {
                    return Err(format!(
                        "symbol partition names diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
                }
            }
            CommandCheck::StringTableNearParity => {
                let our_len = effective_string_table_len(ours)?;
                let their_len = effective_string_table_len(theirs)?;
                if !string_table_within_five_percent(our_len, their_len) {
                    return Err(format!(
                        "string table length drifted too far from Apple ld: ours={} theirs={}",
                        our_len, their_len
                    ));
                }
            }
            CommandCheck::FunctionStarts => {
                let ours = decode_function_starts(ours)?;
                let theirs = decode_function_starts(theirs)?;
                if ours != theirs {
                    return Err(format!(
                        "function starts diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
                }
            }
            CommandCheck::NormalizedFunctionStarts => {
                let ours = normalize_function_start_offsets(&decode_function_starts(ours)?);
                let theirs = normalize_function_start_offsets(&decode_function_starts(theirs)?);
                if ours != theirs {
                    return Err(format!(
                        "normalized function starts diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
                }
            }
            CommandCheck::DataInCode => {
                let ours = canonical_data_in_code(ours)?;
                let theirs = canonical_data_in_code(theirs)?;
                if ours != theirs {
                    return Err(format!(
                        "canonical data-in-code records diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
                }
            }
            CommandCheck::DataInCodeIfPresent => {
                let ours = canonical_data_in_code(ours)?;
                let theirs = canonical_data_in_code(theirs)?;
                if !ours.is_empty() && !theirs.is_empty() && ours != theirs {
                    return Err(format!(
                        "canonical data-in-code records diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
                }
            }
            CommandCheck::RebasedUnwindBytes => {
                let ours = rebased_unwind_bytes(ours)?;
                let theirs = rebased_unwind_bytes(theirs)?;
                if ours != theirs {
                    return Err("rebased unwind bytes diverged".to_string());
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
                let ours = canonical_bind_records(ours, DyldInfoStreamKind::Bind)?;
                let theirs = canonical_bind_records(theirs, DyldInfoStreamKind::Bind)?;
                if ours != theirs {
                    return Err(format!(
                        "bind stream diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
                }
            }
            CommandCheck::DyldInfoWeakBind => {
                let ours = canonical_bind_records(ours, DyldInfoStreamKind::WeakBind)?;
                let theirs = canonical_bind_records(theirs, DyldInfoStreamKind::WeakBind)?;
                if ours != theirs {
                    return Err(format!(
                        "weak-bind stream diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
                }
            }
            CommandCheck::DyldInfoLazyBind => {
                let ours = canonical_bind_records(ours, DyldInfoStreamKind::LazyBind)?;
                let theirs = canonical_bind_records(theirs, DyldInfoStreamKind::LazyBind)?;
                if ours != theirs {
                    return Err(format!(
                        "lazy-bind stream diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                    ));
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

pub fn ensure_absent_sections(
    bytes: &[u8],
    sections: &[(String, String)],
    side: &str,
) -> Result<(), String> {
    for (segname, sectname) in sections {
        if output_section(bytes, segname, sectname).is_some() {
            return Err(format!(
                "{side} unexpectedly emitted section {segname},{sectname}"
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

fn output_section_header(bytes: &[u8], segname: &str, sectname: &str) -> Option<Section64Header> {
    let header = parse_header(bytes).ok()?;
    let commands = parse_commands(&header, bytes).ok()?;
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            for section in seg.sections {
                if section.segname_str() == segname && section.sectname_str() == sectname {
                    return Some(section);
                }
            }
        }
    }
    None
}

fn segment_vmaddr(bytes: &[u8], segname: &str) -> Option<u64> {
    let header = parse_header(bytes).ok()?;
    let commands = parse_commands(&header, bytes).ok()?;
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            if seg.segname_str() == segname {
                return Some(seg.vmaddr);
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
        if segname == "__TEXT" && sectname == "__stubs" {
            let ours = canonical_stub_targets(ours)?;
            let theirs = canonical_stub_targets(theirs)?;
            if ours != theirs {
                return Err(format!(
                    "canonical stub targets diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                ));
            }
            continue;
        }
        if segname == "__TEXT" && sectname == "__stub_helper" {
            let ours = canonical_stub_helper(ours)?;
            let theirs = canonical_stub_helper(theirs)?;
            if ours != theirs {
                return Err(format!(
                    "canonical stub helper surface diverged:\nours:   {ours:#?}\ntheirs: {theirs:#?}"
                ));
            }
            continue;
        }
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
        let expected_ours = resolve_page_ref_expectation(ours, &our_symbols, &check.symbol)?;
        let expected_theirs = resolve_page_ref_expectation(theirs, &their_symbols, &check.symbol)?;
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

fn resolve_page_ref_expectation(
    bytes: &[u8],
    symbols: &BTreeMap<String, u64>,
    reference: &str,
) -> Result<u64, String> {
    if let Some(spec) = reference.strip_prefix("@SECTION:") {
        let (section_spec, addend) = if let Some((section_spec, addend)) = spec.rsplit_once('+') {
            (section_spec, parse_u64(addend)?)
        } else {
            (spec, 0)
        };
        let (segname, sectname) = section_spec
            .split_once(',')
            .ok_or_else(|| format!("invalid @SECTION page-ref target `{reference}`"))?;
        let (addr, data) = output_section(bytes, segname, sectname)
            .ok_or_else(|| format!("missing section {segname},{sectname} in output"))?;
        if addend > data.len() as u64 {
            return Err(format!(
                "@SECTION target `{reference}` exceeds section size {}",
                data.len()
            ));
        }
        return Ok(addr + addend);
    }
    symbols
        .get(reference)
        .copied()
        .ok_or_else(|| format!("missing symbol {reference} in output"))
}

pub fn run_program(path: &Path, args: &[String]) -> Result<ProgramOutput, String> {
    run_program_with_timeout(path, args, runtime_timeout())
}

pub(crate) fn run_program_with_timeout(
    path: &Path,
    args: &[String],
    runtime_timeout: Duration,
) -> Result<ProgramOutput, String> {
    let mut child = Command::new(path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("run {}: {e}", path.display()))?;
    let stdout = child
        .stdout
        .take()
        .expect("stdout is available after configuring a piped child stream");
    let stderr = child
        .stderr
        .take()
        .expect("stderr is available after configuring a piped child stream");
    let stdout_reader = thread::spawn(move || read_to_end(stdout));
    let stderr_reader = thread::spawn(move || read_to_end(stderr));

    let started = Instant::now();
    let wait_result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok((status, false)),
            Ok(None) if started.elapsed() >= runtime_timeout => {
                let _ = child.kill();
                break child
                    .wait()
                    .map(|status| (status, true))
                    .map_err(|e| format!("wait for timed-out {}: {e}", path.display()));
            }
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(format!("wait for {}: {error}", path.display()));
            }
        }
    };

    let stdout = join_output_reader(stdout_reader, "stdout", path);
    let stderr = join_output_reader(stderr_reader, "stderr", path);
    let (status, timed_out) = wait_result?;
    let stdout = stdout?;
    let stderr = stderr?;

    if timed_out {
        return Err(format!(
            "run {} timed out after {:?}: exit={:?} stdout={:?} stderr={:?}",
            path.display(),
            runtime_timeout,
            status.code(),
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        ));
    }

    Ok(ProgramOutput {
        exit_code: status.code(),
        stdout,
        stderr,
    })
}

fn read_to_end(mut stream: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn join_output_reader(
    reader: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream_name: &str,
    path: &Path,
) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| {
            format!(
                "collect {stream_name} from {}: reader panicked",
                path.display()
            )
        })?
        .map_err(|error| format!("collect {stream_name} from {}: {error}", path.display()))
}

pub fn compare_runtime(our_path: &Path, their_path: &Path, args: &[String]) -> Result<(), String> {
    let our_path = our_path.to_path_buf();
    let their_path = their_path.to_path_buf();
    let their_args = args.to_vec();
    let ours = thread::scope(|scope| {
        let theirs = scope.spawn(|| run_program(&their_path, &their_args));
        let ours = run_program(&our_path, args);
        let theirs = theirs
            .join()
            .map_err(|_| "Apple runtime worker panicked".to_string())?;
        Ok::<_, String>((ours, theirs))
    })?;
    let (ours, theirs) = ours;
    let ours = ours?;
    let theirs = theirs?;
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

fn runtime_timeout() -> Duration {
    const DEFAULT_RUNTIME_TIMEOUT_SECS: u64 = 120;

    std::env::var("PARITY_RUNTIME_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_RUNTIME_TIMEOUT_SECS))
}

/// Byte-level diff between two Mach-O images or section byte slices.
///
/// Sprint 27 starts tolerating a very small allowlist: UUID bytes, dylib
/// timestamp fields, and code-signature command/blob bytes at matching
/// offsets. Unknown diffs remain critical.
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
        let tolerated = case_tolerances
            .iter()
            .find(|tol| tolerance_covers_chunk(tol, segname, sectname, chunk.offset, chunk.len));
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
        Some((segname, sectname)) => (
            segname.trim().to_string(),
            Some(sectname.trim().to_string()),
        ),
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

fn read_sections_if_present(path: &Path) -> Result<Vec<(String, String)>, String> {
    if path.exists() {
        read_sections(path)
    } else {
        Ok(Vec::new())
    }
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
        let dep_name = parts.next().map(str::to_string);
        if parts.next().is_some() {
            return Err(format!(
                "too many fields in artifact spec `{line}` from {}",
                path.display()
            ));
        }
        let (kind, dep_name) = match kind {
            "clang_dylib" => {
                if dep_name.is_some() {
                    return Err(format!(
                        "clang_dylib takes exactly 3 fields in {}",
                        path.display()
                    ));
                }
                (ArtifactKind::Dylib, None)
            }
            "clang_archive" => {
                if dep_name.is_some() {
                    return Err(format!(
                        "clang_archive takes exactly 3 fields in {}",
                        path.display()
                    ));
                }
                (ArtifactKind::Archive, None)
            }
            "clang_reexport_dylib" => {
                let dep_name = dep_name.ok_or_else(|| {
                    format!(
                        "clang_reexport_dylib needs a dependency artifact in {}",
                        path.display()
                    )
                })?;
                (ArtifactKind::ReexportDylib, Some(dep_name))
            }
            other => return Err(format!("unknown artifact kind `{other}`")),
        };
        specs.push(ArtifactSpec {
            src_name: src_name.to_string(),
            out_name: out_name.to_string(),
            kind,
            dep_name,
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
        "indirect_symbol_identities" => Ok(CommandCheck::IndirectSymbolIdentities),
        "symbol_partition_names" => Ok(CommandCheck::SymbolPartitionNames),
        "string_table_near_parity" => Ok(CommandCheck::StringTableNearParity),
        "function_starts" => Ok(CommandCheck::FunctionStarts),
        "normalized_function_starts" => Ok(CommandCheck::NormalizedFunctionStarts),
        "data_in_code" => Ok(CommandCheck::DataInCode),
        "data_in_code_if_present" => Ok(CommandCheck::DataInCodeIfPresent),
        "rebased_unwind_bytes" => Ok(CommandCheck::RebasedUnwindBytes),
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
        "LC_SEGMENT_64" => Ok(LC_SEGMENT_64),
        "LC_LOAD_DYLIB" => Ok(LC_LOAD_DYLIB),
        "LC_UUID" => Ok(LC_UUID),
        "LC_CODE_SIGNATURE" => Ok(LC_CODE_SIGNATURE),
        "LC_LINKER_OPTIMIZATION_HINT" => Ok(afs_ld::macho::constants::LC_LINKER_OPTIMIZATION_HINT),
        other => Err(format!("unknown load command name `{other}`")),
    }
}

fn load_command_name(cmd: u32) -> &'static str {
    match cmd {
        LC_SEGMENT_64 => "LC_SEGMENT_64",
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
            LC_ID_DYLIB | LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB
            | LC_LOAD_UPWARD_DYLIB
                if cmdsize >= 16 =>
            {
                mark_range(&mut mask, cursor + 12, cursor + 16, "dylib timestamp");
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
    section: Option<(String, String)>,
    n_desc: u16,
    value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CanonicalExportKind {
    Regular(CanonicalSectionLocation),
    ThreadLocal(CanonicalSectionLocation),
    Absolute(u64),
    Reexport { ordinal: u32, imported_name: String },
    StubAndResolver { stub: u64, resolver: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalExportRecord {
    pub(crate) name: String,
    pub(crate) flags: u64,
    pub(crate) kind: CanonicalExportKind,
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
    let sections = section_regions(bytes)?;
    Ok(symbols
        .iter()
        .map(|symbol| {
            let (section, value) = if symbol.kind() == SymKind::Sect && symbol.sect_idx() != 0 {
                let section = &sections[symbol.sect_idx() as usize - 1];
                let value = if symbol.value() >= section.addr {
                    symbol.value() - section.addr
                } else {
                    symbol.value()
                };
                (
                    Some((section.segname.clone(), section.sectname.clone())),
                    value,
                )
            } else {
                (None, symbol.value())
            };
            CanonicalSymbolRecord {
                name: strings.get(symbol.strx()).unwrap().to_string(),
                n_type: symbol.raw.n_type,
                section,
                n_desc: symbol.raw.n_desc,
                value,
            }
        })
        .filter(|record| !is_optional_dyld_stub_binder_record(record))
        .collect())
}

fn is_optional_dyld_stub_binder_record(record: &CanonicalSymbolRecord) -> bool {
    record.name == "dyld_stub_binder"
        && (record.n_type & N_TYPE) == N_UNDF
        && record.section.is_none()
}

pub(crate) fn canonical_export_records(bytes: &[u8]) -> Result<Vec<CanonicalExportRecord>, String> {
    let exports = macho_exports(bytes)?;
    let symbol_records: BTreeMap<String, CanonicalSymbolRecord> = canonical_symbol_records(bytes)?
        .into_iter()
        .map(|record| (record.name.clone(), record))
        .collect();
    let mut out = exports
        .entries()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|entry| -> Result<CanonicalExportRecord, String> {
            let kind = match entry.kind {
                ExportKind::Regular { address } => CanonicalExportKind::Regular(
                    canonical_export_location(bytes, &entry.name, "regular", address)?,
                ),
                ExportKind::ThreadLocal { address } => CanonicalExportKind::ThreadLocal(
                    canonical_export_location(bytes, &entry.name, "thread-local", address)?,
                ),
                ExportKind::Absolute { address } => CanonicalExportKind::Absolute(address),
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
            validate_export_symbol(&entry.name, &kind, &symbol_records)?;
            Ok(CanonicalExportRecord {
                name: entry.name,
                flags: entry.flags,
                kind,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    out.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
    Ok(out)
}

fn canonical_export_location(
    bytes: &[u8],
    name: &str,
    kind: &str,
    image_offset: u64,
) -> Result<CanonicalSectionLocation, String> {
    let text_base = segment_regions(bytes)?
        .into_iter()
        .find(|segment| segment.segname == "__TEXT")
        .map(|segment| segment.vmaddr)
        .ok_or_else(|| format!("{kind} export `{name}` has no __TEXT image base"))?;
    let address = text_base.checked_add(image_offset).ok_or_else(|| {
        format!("{kind} export `{name}` address overflows the Mach-O image address space")
    })?;
    canonical_section_location(bytes, address).map_err(|error| {
        format!("{kind} export `{name}` trie address 0x{image_offset:x} is invalid: {error}")
    })
}

fn validate_export_symbol(
    name: &str,
    export_kind: &CanonicalExportKind,
    symbol_records: &BTreeMap<String, CanonicalSymbolRecord>,
) -> Result<(), String> {
    let Some(symbol) = symbol_records.get(name) else {
        return Err(format!("export `{name}` has no LC_SYMTAB record"));
    };
    let agrees = match export_kind {
        CanonicalExportKind::Regular(location) | CanonicalExportKind::ThreadLocal(location) => {
            (symbol.n_type & N_TYPE) == N_SECT
                && symbol.section.as_ref()
                    == Some(&(location.segname.clone(), location.sectname.clone()))
                && symbol.value == location.offset
        }
        CanonicalExportKind::Absolute(address) => {
            (symbol.n_type & N_TYPE) == N_ABS
                && symbol.section.is_none()
                && symbol.value == *address
        }
        CanonicalExportKind::Reexport { .. } | CanonicalExportKind::StubAndResolver { .. } => true,
    };
    if !agrees {
        return Err(format!(
            "export `{name}` trie record {export_kind:?} disagrees with LC_SYMTAB record {symbol:?}"
        ));
    }
    Ok(())
}

pub(crate) fn macho_exports(bytes: &[u8]) -> Result<Exports, String> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    for command in commands {
        let range = match command {
            LoadCommand::DyldInfoOnly(info) if info.export_size != 0 => {
                Some((info.export_off, info.export_size))
            }
            LoadCommand::DyldExportsTrie(linkedit) if linkedit.datasize != 0 => {
                Some((linkedit.dataoff, linkedit.datasize))
            }
            _ => None,
        };
        let Some((offset, size)) = range else {
            continue;
        };
        let start = offset as usize;
        let end = start
            .checked_add(size as usize)
            .ok_or_else(|| "export trie offset and size overflow".to_string())?;
        let trie = bytes.get(start..end).ok_or_else(|| {
            format!(
                "export trie range 0x{start:x}..0x{end:x} exceeds file size 0x{:x}",
                bytes.len()
            )
        })?;
        return Ok(Exports::from_trie_bytes(trie));
    }
    Ok(Exports::empty())
}

fn symbol_partition_names(bytes: &[u8]) -> Result<SymbolPartitions, String> {
    let (symtab, dysymtab) = symtab_and_dysymtab(bytes)?;
    let symbols =
        parse_nlist_table(bytes, symtab.symoff, symtab.nsyms).map_err(|e| e.to_string())?;
    let strings =
        StringTable::from_file(bytes, symtab.stroff, symtab.strsize).map_err(|e| e.to_string())?;
    let names_for = |start: u32, count: u32| -> Vec<String> {
        symbols[start as usize..(start + count) as usize]
            .iter()
            .map(|symbol| strings.get(symbol.strx()).unwrap().to_string())
            .collect()
    };
    Ok((
        names_for(dysymtab.ilocalsym, dysymtab.nlocalsym),
        names_for(dysymtab.iextdefsym, dysymtab.nextdefsym),
        names_for(dysymtab.iundefsym, dysymtab.nundefsym)
            .into_iter()
            .filter(|name| name != "dyld_stub_binder")
            .collect(),
    ))
}

fn has_optional_dyld_stub_binder(bytes: &[u8]) -> Result<bool, String> {
    let (symtab, _) = symtab_and_dysymtab(bytes)?;
    let symbols =
        parse_nlist_table(bytes, symtab.symoff, symtab.nsyms).map_err(|e| e.to_string())?;
    let strings =
        StringTable::from_file(bytes, symtab.stroff, symtab.strsize).map_err(|e| e.to_string())?;
    Ok(symbols.iter().any(|symbol| {
        strings
            .get(symbol.strx())
            .map(|name| {
                name == "dyld_stub_binder"
                    && (symbol.raw.n_type & N_TYPE) == N_UNDF
                    && symbol.raw.n_sect == 0
            })
            .unwrap_or(false)
    }))
}

fn raw_string_table(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let (symtab, _) = symtab_and_dysymtab(bytes)?;
    let start = symtab.stroff as usize;
    let end = start + symtab.strsize as usize;
    Ok(bytes[start..end].to_vec())
}

fn effective_string_table_len(bytes: &[u8]) -> Result<usize, String> {
    let mut len = raw_string_table(bytes)?.len();
    if has_optional_dyld_stub_binder(bytes)? {
        len = len.saturating_sub("dyld_stub_binder".len() + 1);
    }
    Ok(len)
}

pub fn string_table_within_five_percent(ours: usize, theirs: usize) -> bool {
    let delta = ours.abs_diff(theirs);
    delta * 20 <= theirs
}

fn indirect_symbol_table(bytes: &[u8]) -> Result<Vec<u32>, String> {
    let (_, dysymtab) = symtab_and_dysymtab(bytes)?;
    if dysymtab.nindirectsyms == 0 {
        return Ok(Vec::new());
    }
    let start = dysymtab.indirectsymoff as usize;
    let end = start + dysymtab.nindirectsyms as usize * 4;
    Ok(bytes[start..end]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect())
}

fn indirect_symbol_identities(bytes: &[u8]) -> Result<Vec<String>, String> {
    let (symtab, _) = symtab_and_dysymtab(bytes)?;
    let symbols =
        parse_nlist_table(bytes, symtab.symoff, symtab.nsyms).map_err(|e| e.to_string())?;
    let strings =
        StringTable::from_file(bytes, symtab.stroff, symtab.strsize).map_err(|e| e.to_string())?;
    Ok(indirect_symbol_table(bytes)?
        .into_iter()
        .map(|index| {
            if index & INDIRECT_SYMBOL_LOCAL != 0 {
                if index & INDIRECT_SYMBOL_ABS != 0 {
                    "<LOCAL|ABS>".to_string()
                } else {
                    "<LOCAL>".to_string()
                }
            } else if index & INDIRECT_SYMBOL_ABS != 0 {
                "<ABS>".to_string()
            } else {
                let symbol = &symbols[index as usize];
                strings.get(symbol.strx()).unwrap().to_string()
            }
        })
        .collect())
}

fn raw_linkedit_data_cmd(bytes: &[u8], expected_cmd: u32) -> Result<(u32, u32), String> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    for cmd in commands {
        match cmd {
            LoadCommand::Raw { cmd, data, .. } if cmd == expected_cmd => {
                return Ok((u32_le(&data[0..4]), u32_le(&data[4..8])));
            }
            LoadCommand::LinkerOptimizationHint(linkedit)
                if expected_cmd == afs_ld::macho::constants::LC_LINKER_OPTIMIZATION_HINT =>
            {
                return Ok((linkedit.dataoff, linkedit.datasize));
            }
            _ => {}
        }
    }
    Err(format!("missing raw linkedit command 0x{expected_cmd:x}"))
}

fn linkedit_payload(bytes: &[u8], cmd: u32) -> Result<Vec<u8>, String> {
    let (dataoff, datasize) = raw_linkedit_data_cmd(bytes, cmd)?;
    if datasize == 0 {
        return Ok(Vec::new());
    }
    Ok(bytes[dataoff as usize..(dataoff + datasize) as usize].to_vec())
}

fn decode_function_starts(bytes: &[u8]) -> Result<Vec<u64>, String> {
    let payload = linkedit_payload(bytes, LC_FUNCTION_STARTS)?;
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    let mut offsets = Vec::new();
    let mut cursor = 0usize;
    let mut current = 0u64;
    while cursor < payload.len() {
        let (delta, used) = read_uleb(&payload[cursor..]).map_err(|e| e.to_string())?;
        cursor += used;
        if delta == 0 {
            if payload[cursor..].iter().any(|byte| *byte != 0) {
                return Err(
                    "LC_FUNCTION_STARTS contains non-zero padding after its terminator".into(),
                );
            }
            return Ok(offsets);
        }
        current += delta;
        offsets.push(current);
    }
    Err("LC_FUNCTION_STARTS is missing its zero ULEB terminator".into())
}

fn normalize_function_start_offsets(starts: &[u64]) -> Vec<u64> {
    let Some(&base) = starts.first() else {
        return Vec::new();
    };
    starts.iter().map(|offset| offset - base).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DataInCodeRecord {
    offset: u32,
    length: u16,
    kind: u16,
}

fn decode_data_in_code(bytes: &[u8]) -> Result<Vec<DataInCodeRecord>, String> {
    let payload = linkedit_payload(bytes, LC_DATA_IN_CODE)?;
    Ok(payload
        .chunks_exact(8)
        .map(|chunk| DataInCodeRecord {
            offset: u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
            length: u16::from_le_bytes(chunk[4..6].try_into().unwrap()),
            kind: u16::from_le_bytes(chunk[6..8].try_into().unwrap()),
        })
        .collect())
}

fn canonical_data_in_code(bytes: &[u8]) -> Result<Vec<DataInCodeRecord>, String> {
    let text = output_section_header(bytes, "__TEXT", "__text")
        .ok_or_else(|| "missing __TEXT,__text section".to_string())?;
    Ok(decode_data_in_code(bytes)?
        .into_iter()
        .map(|record| DataInCodeRecord {
            offset: record.offset - text.offset,
            length: record.length,
            kind: record.kind,
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CanonicalBindLocation {
    Section {
        segname: String,
        sectname: String,
        offset: u64,
    },
    Segment {
        segment_index: u8,
        segment_offset: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalBindRecord {
    location: CanonicalBindLocation,
    ordinal: i32,
    symbol: String,
    weak_import: bool,
    bind_type: u8,
    addend: i64,
}

fn canonical_bind_records(
    bytes: &[u8],
    kind: DyldInfoStreamKind,
) -> Result<Vec<CanonicalBindRecord>, String> {
    let stream = dyld_info_stream(bytes, kind)?;
    let mut cursor = 0usize;
    let mut segment_index = 0u8;
    let mut segment_offset = 0u64;
    let mut ordinal = 0i32;
    let mut symbol = String::new();
    let mut weak_import = false;
    let mut bind_type = BIND_TYPE_POINTER;
    let mut addend = 0i64;
    let mut out = Vec::new();

    while cursor < stream.len() {
        let byte = stream[cursor];
        cursor += 1;
        let opcode = byte & BIND_OPCODE_MASK;
        let imm = byte & BIND_IMMEDIATE_MASK;
        match opcode {
            BIND_OPCODE_DONE => break,
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => ordinal = imm as i32,
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                let (value, used) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("bind uleb: {e}"))?;
                cursor += used;
                ordinal = value as i32;
            }
            BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                ordinal = if imm == 0 {
                    0
                } else {
                    (((imm as i8) << 4) >> 4) as i32
                };
            }
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                let (value, used) = read_c_string(&stream[cursor..])?;
                cursor += used;
                symbol = value;
                weak_import = (imm & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0;
            }
            BIND_OPCODE_SET_TYPE_IMM => bind_type = imm,
            BIND_OPCODE_SET_ADDEND_SLEB => {
                let (value, used) =
                    read_sleb(&stream[cursor..]).map_err(|e| format!("bind sleb: {e}"))?;
                cursor += used;
                addend = value;
            }
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                let (value, used) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("bind uleb: {e}"))?;
                cursor += used;
                segment_index = imm;
                segment_offset = value;
            }
            BIND_OPCODE_ADD_ADDR_ULEB => {
                let (value, used) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("bind uleb: {e}"))?;
                cursor += used;
                segment_offset += value;
            }
            BIND_OPCODE_DO_BIND => {
                out.push(CanonicalBindRecord {
                    location: canonical_bind_location(bytes, segment_index, segment_offset)?,
                    ordinal,
                    symbol: symbol.clone(),
                    weak_import,
                    bind_type,
                    addend,
                });
                segment_offset += 8;
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                let (value, used) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("bind uleb: {e}"))?;
                cursor += used;
                out.push(CanonicalBindRecord {
                    location: canonical_bind_location(bytes, segment_index, segment_offset)?,
                    ordinal,
                    symbol: symbol.clone(),
                    weak_import,
                    bind_type,
                    addend,
                });
                segment_offset += 8 + value;
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                out.push(CanonicalBindRecord {
                    location: canonical_bind_location(bytes, segment_index, segment_offset)?,
                    ordinal,
                    symbol: symbol.clone(),
                    weak_import,
                    bind_type,
                    addend,
                });
                segment_offset += 8 + (imm as u64) * 8;
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let (count, count_used) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("bind uleb: {e}"))?;
                cursor += count_used;
                let (skip, skip_used) =
                    read_uleb(&stream[cursor..]).map_err(|e| format!("bind uleb: {e}"))?;
                cursor += skip_used;
                for _ in 0..count {
                    out.push(CanonicalBindRecord {
                        location: canonical_bind_location(bytes, segment_index, segment_offset)?,
                        ordinal,
                        symbol: symbol.clone(),
                        weak_import,
                        bind_type,
                        addend,
                    });
                    segment_offset += 8 + skip;
                }
            }
            other => return Err(format!("unsupported bind opcode 0x{other:02x}")),
        }
    }

    normalize_bind_section_offsets(&mut out);
    out.sort();
    Ok(out)
}

fn normalize_bind_section_offsets(records: &mut [CanonicalBindRecord]) {
    let mut next_offsets: BTreeMap<(String, String), u64> = BTreeMap::new();
    records.sort();
    for record in records.iter_mut() {
        let CanonicalBindLocation::Section {
            segname,
            sectname,
            offset,
        } = &mut record.location
        else {
            continue;
        };
        let next = next_offsets
            .entry((segname.clone(), sectname.clone()))
            .or_insert(0);
        *offset = *next;
        *next += 8;
    }
}

fn rebased_unwind_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let header_base = segment_vmaddr(bytes, "__TEXT").unwrap_or(0);
    let text_base = output_section(bytes, "__TEXT", "__text")
        .ok_or_else(|| "missing __TEXT,__text section".to_string())?
        .0
        - header_base;
    let got_range = output_section(bytes, "__DATA_CONST", "__got")
        .map(|(addr, data)| (addr - header_base, addr - header_base + data.len() as u64));
    let lsda_base =
        output_section(bytes, "__TEXT", "__gcc_except_tab").map(|(addr, _)| addr - header_base);
    let (_, unwind) = output_section(bytes, "__TEXT", "__unwind_info")
        .ok_or_else(|| "missing __TEXT,__unwind_info section".to_string())?;
    let mut out = unwind;
    if out.len() < 28 {
        return Ok(out);
    }

    let personalities_offset = u32_le(&out[12..16]) as usize;
    let personalities_count = u32_le(&out[16..20]) as usize;
    let indices_offset = u32_le(&out[20..24]) as usize;
    let indices_count = u32_le(&out[24..28]) as usize;

    for idx in 0..personalities_count {
        let off = personalities_offset + idx * 4;
        let value = u32_le(&out[off..off + 4]) as u64;
        let rebased = if let Some((got_start, got_end)) = got_range {
            if got_start <= value && value < got_end {
                value - got_start
            } else if value >= text_base {
                value - text_base
            } else {
                value
            }
        } else if value >= text_base {
            value - text_base
        } else {
            value
        };
        out[off..off + 4].copy_from_slice(&(rebased as u32).to_le_bytes());
    }

    let mut lsda_offsets = Vec::with_capacity(indices_count);
    for idx in 0..indices_count {
        let entry_off = indices_offset + idx * 12;
        let function_offset = u32_le(&out[entry_off..entry_off + 4]) as u64;
        let rebased = function_offset.saturating_sub(text_base);
        out[entry_off..entry_off + 4].copy_from_slice(&(rebased as u32).to_le_bytes());
        lsda_offsets.push(u32_le(&out[entry_off + 8..entry_off + 12]) as usize);
    }

    if let (Some(lsda_base), Some(&start), Some(&end)) =
        (lsda_base, lsda_offsets.first(), lsda_offsets.last())
    {
        let mut entry_off = start;
        while entry_off < end {
            let function_offset = u32_le(&out[entry_off..entry_off + 4]) as u64;
            let lsda_offset = u32_le(&out[entry_off + 4..entry_off + 8]) as u64;
            out[entry_off..entry_off + 4]
                .copy_from_slice(&(function_offset.saturating_sub(text_base) as u32).to_le_bytes());
            out[entry_off + 4..entry_off + 8]
                .copy_from_slice(&(lsda_offset.saturating_sub(lsda_base) as u32).to_le_bytes());
            entry_off += 8;
        }
    }

    let _ = decode_unwind_info(&out).map_err(|e| format!("decode unwind info: {e}"))?;
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
    Ok(section_regions(bytes)?
        .into_iter()
        .map(|section| section.addr)
        .collect())
}

#[derive(Debug, Clone)]
struct SegmentRegion {
    index: u8,
    segname: String,
    vmaddr: u64,
    vmsize: u64,
}

#[derive(Debug, Clone)]
struct SectionRegion {
    segment_index: u8,
    segname: String,
    sectname: String,
    addr: u64,
    size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CanonicalSectionLocation {
    segname: String,
    sectname: String,
    offset: u64,
}

fn segment_regions(bytes: &[u8]) -> Result<Vec<SegmentRegion>, String> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut index = 0u8;
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            out.push(SegmentRegion {
                index,
                segname: seg.segname_str().to_string(),
                vmaddr: seg.vmaddr,
                vmsize: seg.vmsize,
            });
            index = index.saturating_add(1);
        }
    }
    Ok(out)
}

fn section_regions(bytes: &[u8]) -> Result<Vec<SectionRegion>, String> {
    let header = parse_header(bytes).map_err(|e| e.to_string())?;
    let commands = parse_commands(&header, bytes).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut segment_index = 0u8;
    for cmd in commands {
        if let LoadCommand::Segment64(seg) = cmd {
            for section in seg.sections {
                out.push(SectionRegion {
                    segment_index,
                    segname: section.segname_str().to_string(),
                    sectname: section.sectname_str().to_string(),
                    addr: section.addr,
                    size: section.size,
                });
            }
            segment_index = segment_index.saturating_add(1);
        }
    }
    Ok(out)
}

fn canonical_bind_location(
    bytes: &[u8],
    segment_index: u8,
    segment_offset: u64,
) -> Result<CanonicalBindLocation, String> {
    let segments = segment_regions(bytes)?;
    let sections = section_regions(bytes)?;
    let Some(segment) = segments
        .iter()
        .find(|segment| segment.index == segment_index)
    else {
        return Ok(CanonicalBindLocation::Segment {
            segment_index,
            segment_offset,
        });
    };
    if segment_offset >= segment.vmsize {
        return Ok(CanonicalBindLocation::Segment {
            segment_index,
            segment_offset,
        });
    }
    let addr = segment.vmaddr + segment_offset;
    if let Some(section) = sections.iter().find(|section| {
        section.segment_index == segment_index
            && section.addr <= addr
            && addr < section.addr + section.size
    }) {
        return Ok(CanonicalBindLocation::Section {
            segname: section.segname.clone(),
            sectname: section.sectname.clone(),
            offset: addr - section.addr,
        });
    }
    Ok(CanonicalBindLocation::Segment {
        segment_index,
        segment_offset,
    })
}

fn canonical_section_location(bytes: &[u8], addr: u64) -> Result<CanonicalSectionLocation, String> {
    let sections = section_regions(bytes)?;
    let section = sections
        .into_iter()
        .find(|section| section.addr <= addr && addr < section.addr + section.size)
        .ok_or_else(|| format!("address 0x{addr:x} is not inside any output section"))?;
    Ok(CanonicalSectionLocation {
        segname: section.segname,
        sectname: section.sectname,
        offset: addr - section.addr,
    })
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

fn read_c_string(bytes: &[u8]) -> Result<(String, usize), String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "unterminated C string".to_string())?;
    let value = std::str::from_utf8(&bytes[..end])
        .map_err(|e| format!("utf-8 in C string: {e}"))?
        .to_string();
    Ok((value, end + 1))
}

fn canonical_stub_targets(bytes: &[u8]) -> Result<Vec<CanonicalSectionLocation>, String> {
    let header = output_section_header(bytes, "__TEXT", "__stubs")
        .ok_or_else(|| "missing __TEXT,__stubs section".to_string())?;
    let (section_addr, section_bytes) = output_section(bytes, "__TEXT", "__stubs")
        .ok_or_else(|| "missing __TEXT,__stubs section".to_string())?;
    if section_bytes.is_empty() {
        return Ok(Vec::new());
    }
    let stub_size = usize::try_from(header.reserved2)
        .ok()
        .filter(|size| *size > 0)
        .unwrap_or(12);
    if section_bytes.len() % stub_size != 0 {
        return Err(format!(
            "__TEXT,__stubs size {} is not a multiple of stub size {}",
            section_bytes.len(),
            stub_size
        ));
    }
    let mut out = Vec::new();
    for (idx, chunk) in section_bytes.chunks_exact(stub_size).enumerate() {
        let target = decode_stub_target(chunk, section_addr + (idx * stub_size) as u64)?;
        out.push(canonical_section_location(bytes, target)?);
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalStubHelper {
    dyld_private: CanonicalSectionLocation,
    binder_got: CanonicalSectionLocation,
    lazy_bind_offsets: Vec<u32>,
}

fn canonical_stub_helper(bytes: &[u8]) -> Result<CanonicalStubHelper, String> {
    let (section_addr, section_bytes) = output_section(bytes, "__TEXT", "__stub_helper")
        .ok_or_else(|| "missing __TEXT,__stub_helper section".to_string())?;
    if section_bytes.len() < STUB_HELPER_HEADER_SIZE as usize {
        return Err(format!(
            "__TEXT,__stub_helper is too small for header: {} < {}",
            section_bytes.len(),
            STUB_HELPER_HEADER_SIZE
        ));
    }
    let dyld_private_target =
        decode_page_reference(&section_bytes, section_addr, 0, PageRefKind::Add)?;
    let binder_got_target =
        decode_page_reference(&section_bytes, section_addr, 12, PageRefKind::Load)?;
    let dyld_private = canonical_section_location(bytes, dyld_private_target)?;
    let binder_got = canonical_section_location(bytes, binder_got_target)?;

    let entry_bytes = &section_bytes[STUB_HELPER_HEADER_SIZE as usize..];
    if entry_bytes.len() % STUB_HELPER_ENTRY_SIZE as usize != 0 {
        return Err(format!(
            "__TEXT,__stub_helper entries {} are not a multiple of {}",
            entry_bytes.len(),
            STUB_HELPER_ENTRY_SIZE
        ));
    }

    let mut lazy_bind_offsets = Vec::new();
    for (idx, chunk) in entry_bytes
        .chunks_exact(STUB_HELPER_ENTRY_SIZE as usize)
        .enumerate()
    {
        let entry_addr = section_addr
            + STUB_HELPER_HEADER_SIZE as u64
            + (idx as u64) * STUB_HELPER_ENTRY_SIZE as u64;
        let ldr = read_insn(chunk, 0)?;
        if ldr != 0x1800_0050 {
            return Err(format!(
                "stub helper entry at 0x{entry_addr:x} does not start with LDR literal"
            ));
        }
        let branch = read_insn(chunk, 4)?;
        let branch_target = decode_branch26_target(branch, entry_addr + 4)?;
        if branch_target != section_addr {
            return Err(format!(
                "stub helper entry at 0x{entry_addr:x} branches to 0x{branch_target:x}, expected header 0x{section_addr:x}"
            ));
        }
        lazy_bind_offsets.push(u32_le(&chunk[8..12]));
    }

    Ok(CanonicalStubHelper {
        dyld_private,
        binder_got,
        lazy_bind_offsets,
    })
}

fn decode_stub_target(bytes: &[u8], stub_addr: u64) -> Result<u64, String> {
    let adrp = read_insn(bytes, 0)?;
    let ldr = read_insn(bytes, 4)?;
    let br = read_insn(bytes, 8)?;
    if (adrp & 0x9f00_0000) != 0x9000_0000 {
        return Err(format!("stub at 0x{stub_addr:x} does not start with ADRP"));
    }
    if (ldr & 0xffc0_0000) != 0xf940_0000 {
        return Err(format!(
            "stub at 0x{stub_addr:x} does not use LDR (unsigned)"
        ));
    }
    if (br & 0xffff_fc1f) != 0xd61f_0000 {
        return Err(format!("stub at 0x{stub_addr:x} does not end with BR"));
    }
    let adrp_reg = (adrp & 0x1f) as u8;
    let ldr_base = ((ldr >> 5) & 0x1f) as u8;
    let ldr_reg = (ldr & 0x1f) as u8;
    let br_reg = ((br >> 5) & 0x1f) as u8;
    if adrp_reg != ldr_base || adrp_reg != ldr_reg || adrp_reg != br_reg {
        return Err(format!(
            "stub at 0x{stub_addr:x} uses inconsistent scratch regs: adrp=x{adrp_reg}, ldr base=x{ldr_base}, ldr rt=x{ldr_reg}, br=x{br_reg}"
        ));
    }
    let adrp_immlo = ((adrp >> 29) & 0x3) as i64;
    let adrp_immhi = ((adrp >> 5) & 0x7ffff) as i64;
    let adrp_pages = sign_extend_21((adrp_immhi << 2) | adrp_immlo);
    let adrp_base = ((stub_addr as i64) & !0xfff) + (adrp_pages << 12);
    let scaled = ((ldr >> 10) & 0xfff) as u64;
    Ok((adrp_base as u64) + scaled * 8)
}

fn decode_branch26_target(insn: u32, place: u64) -> Result<u64, String> {
    if (insn & 0xfc00_0000) != 0x1400_0000 {
        return Err(format!(
            "instruction 0x{insn:08x} at 0x{place:x} is not a B/BL branch26"
        ));
    }
    let imm26 = sign_extend_26((insn & 0x03ff_ffff) as i64);
    Ok(((place as i64) + (imm26 << 2)) as u64)
}

fn sign_extend_26(value: i64) -> i64 {
    let shift = 64 - 26;
    (value << shift) >> shift
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
