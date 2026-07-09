use std::process::ExitCode;

use afs_ld::{archive, args, diag, dump, elf, LinkError, Linker};

fn usage() -> &'static str {
    "\
Usage: afs-ld [options] <inputs...>

Options:
  -o <path>                       Write output to <path>
  -dylib                          Emit a dylib instead of an executable
  -e <symbol>                     Set the entry symbol
  -arch arm64                     Select the arm64 target
  -map <path>                     Emit text link map
  -why_live <symbol>              Print a reachability chain for <symbol>
  -l<name> / -l <name>            Search for library
  -L <dir>                        Add library search path
  -framework <name>               Link framework
  -weak_framework <name>          Link weak framework
  -ObjC                           Objective-C archive loading mode (currently a no-op warning)
  -syslibroot <path>              Prefix SDK search roots
  -platform_version macos <min> <sdk>
                                  Set LC_BUILD_VERSION payload
  -r                              Relocatable output (deferred; errors)
  -bundle                         Bundle output (deferred; errors)
  -undefined <error|warning|suppress|dynamic_lookup>
                                  Control unresolved-symbol treatment
  -rpath <path>                   Add LC_RPATH
  -install_name <path>            Override dylib install name
  -current_version <v>            Override dylib current version
  -compatibility_version <v>      Override dylib compatibility version
  -exported_symbols_list <file>   Export only symbols matching file patterns
  -unexported_symbols_list <file> Hide symbols matching file patterns
  -exported_symbol <sym>          Export one symbol/pattern
  -unexported_symbol <sym>        Hide one symbol/pattern
  -x                              Strip local symbols
  -S                              Strip debug symbols (currently a no-op warning)
  -no_uuid                        Omit LC_UUID
  -no_loh                         Accepted for compatibility (currently warns; no effect)
  -thunks=<none|safe|all>         Configure branch thunks
  -dead_strip                     Dead-strip unreferenced code/data
  -icf=safe | -icf=none | -icf=all
                                  Configure identical code folding (`all` currently errors)
  -fixup_chains | -no_fixup_chains
                                  Select chained fixups vs classic dyld info
  -all_load                       Force-load every archive member
  -force_load <archive>           Force-load one archive
  -j <jobs>                       Limit parallel worker jobs (`1` disables parallelism)
  -Wl,<arg,arg,...>               Normalize comma-separated driver flags
  --dump <path>                   Dump a Mach-O file summary
  --dump-archive <path>           Dump an archive summary
  --dump-dylib <path>             Dump a dylib summary
  --dump-tbd <path>               Dump a TBD summary
  -t, -trace                      Print input paths as they are loaded
  -h, --help                      Show this help
  -v, --version                   Show afs-ld version
"
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();

    // x16: ELF mode. If any input file carries ELF magic, route to
    // the ELF linker before the Mach-O argument surface sees it.
    // Rung-1 flag set: `-o <out> <objects...>`; anything else is a
    // loud not-yet, never a silent ignore.
    if let Some(code) = elf_mode(&argv[1..]) {
        return code;
    }

    let opts = match args::parse(&argv[1..]) {
        Ok(opts) => opts,
        Err(e) => {
            diag::error(&e.to_string());
            return ExitCode::from(2);
        }
    };

    if opts.show_help {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }

    if opts.show_version {
        println!("afs-ld {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    if let Some(path) = &opts.dump {
        return match dump::dump_file(path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                diag::error(&format!("{}: {}", path.display(), e));
                ExitCode::from(1)
            }
        };
    }

    if let Some(path) = &opts.dump_archive {
        return match dump::dump_archive_file(path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                diag::error(&format!("{}: {}", path.display(), e));
                ExitCode::from(1)
            }
        };
    }

    if let Some(path) = &opts.dump_dylib {
        return match dump::dump_dylib_file(path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                diag::error(&format!("{}: {}", path.display(), e));
                ExitCode::from(1)
            }
        };
    }

    if let Some(path) = &opts.dump_tbd {
        return match dump::dump_tbd_file(path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                diag::error(&format!("{}: {}", path.display(), e));
                ExitCode::from(1)
            }
        };
    }

    match Linker::run(&opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(LinkError::NoInputs) => {
            diag::error("no input files");
            ExitCode::from(2)
        }
        Err(LinkError::DuplicateSymbols(msg)) | Err(LinkError::UndefinedSymbols(msg)) => {
            diag::error_verbatim(&msg);
            ExitCode::from(1)
        }
        Err(e) => {
            diag::error(&e.to_string());
            ExitCode::from(1)
        }
    }
}

/// A command-line link input, tagged so its position relative to other
/// inputs is preserved. GNU ld resolves archives left-to-right, so
/// `pmain.o -lb ./liba.a` searches `libb` before `liba`; keeping a single
/// ordered list (rather than draining all positional files before all
/// `-l` requests) is what makes that ordering hold.
enum LinkInput {
    /// A positional path: an object, an archive, or a shared object.
    File(std::path::PathBuf),
    /// A `-lfoo` request, resolved against the search dirs in link order.
    Lib(String),
    /// Start a repeated archive search group.
    GroupStart,
    /// End a repeated archive search group.
    GroupEnd,
}

/// Detect and run the ELF link path. Returns None when no input is
/// an ELF object (Mach-O flow continues unchanged).
fn elf_mode(args: &[String]) -> Option<ExitCode> {
    let mut output: Option<std::path::PathBuf> = None;
    // Inputs in command-line order, positional files and `-l` requests
    // interleaved. `-L` search dirs accumulate separately and apply to
    // every `-l` regardless of relative position.
    let mut link_inputs: Vec<LinkInput> = Vec::new();
    let mut lib_dirs: Vec<std::path::PathBuf> = Vec::new();
    let mut unsupported: Vec<String> = Vec::new();
    let mut dynamic_linker: Option<String> = None;
    let mut eh_frame_hdr = false;
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-o" => output = it.next().map(std::path::PathBuf::from),
            "-L" => {
                if let Some(d) = it.next() {
                    lib_dirs.push(std::path::PathBuf::from(d));
                }
            }
            "-l" => {
                if let Some(n) = it.next() {
                    link_inputs.push(LinkInput::Lib(n.clone()));
                }
            }
            "--dynamic-linker" | "-dynamic-linker" => {
                dynamic_linker = it.next().cloned();
            }
            // `--eh-frame-hdr` requests the `.eh_frame_hdr` unwind index +
            // PT_GNU_EH_FRAME (GNU semantics: emitted only when asked).
            "--eh-frame-hdr" => eh_frame_hdr = true,
            "--no-eh-frame-hdr" => eh_frame_hdr = false,
            "--start-group" | "-(" => link_inputs.push(LinkInput::GroupStart),
            "--end-group" | "-)" => link_inputs.push(LinkInput::GroupEnd),
            // Flags we honor or safely ignore. -static and a target
            // emulation are the expected mode.
            "-static" | "-Bstatic" | "-Bdynamic" | "-melf_x86_64" | "-znow" | "--no-as-needed"
            | "--as-needed" | "--gc-sections" => {}
            "-m" => {
                it.next();
            }
            "-z" => {
                it.next();
            }
            // PIE and shared-object output are later rungs.
            "-pie" | "--pie" | "-shared" | "-Bshareable" => unsupported.push(a.to_string()),
            s if s.starts_with("-L") => lib_dirs.push(std::path::PathBuf::from(&s[2..])),
            s if s.starts_with("-l") => link_inputs.push(LinkInput::Lib(s[2..].to_string())),
            s if s.starts_with('-') => unsupported.push(s.to_string()),
            _ => link_inputs.push(LinkInput::File(std::path::PathBuf::from(a))),
        }
    }
    let is_elf = |p: &std::path::Path| {
        std::fs::read(p)
            .map(|b| b.len() >= 4 && &b[0..4] == b"\x7fELF")
            .unwrap_or(false)
    };
    if !link_inputs
        .iter()
        .any(|li| matches!(li, LinkInput::File(p) if is_elf(p)))
    {
        return None;
    }
    if !unsupported.is_empty() {
        diag::error(&format!(
            "ELF mode does not support: {} — PIE and shared-object output land in a later rung",
            unsupported.join(" ")
        ));
        return Some(ExitCode::from(2));
    }
    let Some(output) = output else {
        diag::error("ELF mode requires -o <output>");
        return Some(ExitCode::from(2));
    };

    let read_bytes = |p: &std::path::Path| -> Result<Vec<u8>, ExitCode> {
        std::fs::read(p).map_err(|e| {
            diag::error(&format!("{}: {}", p.display(), e));
            ExitCode::from(1)
        })
    };

    let image = if let Some(interp) = dynamic_linker {
        match link_dynamic(&link_inputs, &lib_dirs, &interp, eh_frame_hdr, read_bytes) {
            Ok(img) => img,
            Err(code) => return Some(code),
        }
    } else {
        match link_static(&link_inputs, &lib_dirs, eh_frame_hdr, read_bytes) {
            Ok(img) => img,
            Err(code) => return Some(code),
        }
    };

    if let Err(e) = std::fs::write(&output, &image) {
        diag::error(&format!("{}: {}", output.display(), e));
        return Some(ExitCode::from(1));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o755));
    }
    Some(ExitCode::SUCCESS)
}

/// Resolve a `-lfoo` request to `lib<name>.<ext>` against the search
/// dirs, in `-L` order. Returns None when nothing matches; the caller
/// emits the mode-appropriate diagnostic.
fn resolve_lib(
    name: &str,
    ext: &str,
    lib_dirs: &[std::path::PathBuf],
) -> Option<std::path::PathBuf> {
    lib_dirs.iter().find_map(|d| {
        let cand = d.join(format!("lib{name}.{ext}"));
        cand.exists().then_some(cand)
    })
}

fn resolve_script_path(
    script: &std::path::Path,
    token: &str,
    lib_dirs: &[std::path::PathBuf],
) -> std::path::PathBuf {
    let raw = std::path::PathBuf::from(token);
    if raw.is_absolute() {
        return raw;
    }
    if let Some(parent) = script.parent() {
        let from_script = parent.join(&raw);
        if from_script.exists() {
            return from_script;
        }
    }
    lib_dirs
        .iter()
        .map(|dir| dir.join(&raw))
        .find(|p| p.exists())
        .unwrap_or(raw)
}

fn strip_c_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn script_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        match ch {
            '(' | ')' | ',' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                tokens.push(ch.to_string());
            }
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn parenthesized(tokens: &[String], open: usize) -> Option<(&[String], usize)> {
    if tokens.get(open).map(String::as_str) != Some("(") {
        return None;
    }
    let mut depth = 1usize;
    for i in open + 1..tokens.len() {
        match tokens[i].as_str() {
            "(" => depth += 1,
            ")" => {
                depth -= 1;
                if depth == 0 {
                    return Some((&tokens[open + 1..i], i + 1));
                }
            }
            _ => {}
        }
    }
    None
}

fn collect_script_inputs(
    tokens: &[String],
    script: &std::path::Path,
    lib_dirs: &[std::path::PathBuf],
    out: &mut Vec<LinkInput>,
) {
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "GROUP" => {
                if let Some((inner, next)) = parenthesized(tokens, i + 1) {
                    out.push(LinkInput::GroupStart);
                    collect_script_inputs(inner, script, lib_dirs, out);
                    out.push(LinkInput::GroupEnd);
                    i = next;
                } else {
                    i += 1;
                }
            }
            "INPUT" | "AS_NEEDED" => {
                if let Some((inner, next)) = parenthesized(tokens, i + 1) {
                    collect_script_inputs(inner, script, lib_dirs, out);
                    i = next;
                } else {
                    i += 1;
                }
            }
            "OUTPUT_FORMAT" | "SEARCH_DIR" => {
                if let Some((_, next)) = parenthesized(tokens, i + 1) {
                    i = next;
                } else {
                    i += 1;
                }
            }
            "(" | ")" | "," => i += 1,
            token if token.starts_with("-l") && token.len() > 2 => {
                out.push(LinkInput::Lib(token[2..].to_string()));
                i += 1;
            }
            token if token.starts_with('-') => i += 1,
            token => {
                out.push(LinkInput::File(resolve_script_path(
                    script, token, lib_dirs,
                )));
                i += 1;
            }
        }
    }
}

fn linker_script_inputs(
    script: &std::path::Path,
    bytes: &[u8],
    lib_dirs: &[std::path::PathBuf],
) -> Option<Vec<LinkInput>> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !(text.contains("GROUP") || text.contains("INPUT")) {
        return None;
    }
    let stripped = strip_c_comments(text);
    let tokens = script_tokens(&stripped);
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "GROUP" => {
                if let Some((inner, next)) = parenthesized(&tokens, i + 1) {
                    out.push(LinkInput::GroupStart);
                    collect_script_inputs(inner, script, lib_dirs, &mut out);
                    out.push(LinkInput::GroupEnd);
                    i = next;
                } else {
                    i += 1;
                }
            }
            "INPUT" => {
                if let Some((inner, next)) = parenthesized(&tokens, i + 1) {
                    collect_script_inputs(inner, script, lib_dirs, &mut out);
                    i = next;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Static link: objects load eagerly, `ar` archives feed lazy member
/// selection. `-lfoo` resolves to `libfoo.a`. Inputs are consumed in
/// command-line order so archive symbol resolution matches GNU ld
/// left-to-right: the first eligible archive that defines a symbol wins,
/// and interleaving `-l` with positional archives is honored.
fn link_static(
    link_inputs: &[LinkInput],
    lib_dirs: &[std::path::PathBuf],
    eh_frame_hdr: bool,
    read_bytes: impl Fn(&std::path::Path) -> Result<Vec<u8>, ExitCode>,
) -> Result<Vec<u8>, ExitCode> {
    let mut inputs = Vec::new();
    for input in link_inputs {
        let p = match input {
            LinkInput::File(p) => p.clone(),
            LinkInput::Lib(name) => match resolve_lib(name, "a", lib_dirs) {
                Some(p) => p,
                None => {
                    diag::error(&format!("unable to find library -l{name}"));
                    return Err(ExitCode::from(1));
                }
            },
            LinkInput::GroupStart => {
                inputs.push(elf::LinkInput::GroupStart);
                continue;
            }
            LinkInput::GroupEnd => {
                inputs.push(elf::LinkInput::GroupEnd);
                continue;
            }
        };
        let bytes = read_bytes(&p)?;
        if bytes.starts_with(archive::AR_MAGIC) || bytes.starts_with(archive::AR_MAGIC_THIN) {
            inputs.push(elf::LinkInput::Archive(elf::Library {
                name: p.display().to_string(),
                bytes,
            }));
        } else {
            inputs.push(elf::LinkInput::Object(parse_object(&p, &bytes)?));
        }
    }
    elf::link_static(inputs, "_start", eh_frame_hdr).map_err(|e| {
        diag::error(&e.to_string());
        ExitCode::from(1)
    })
}

/// Dynamic link: objects load eagerly; `.a` inputs feed lazy member
/// selection; `.so` inputs (positional, script-expanded, or from
/// `-lfoo`) provide imports resolved at runtime. Inputs are consumed in
/// command-line order.
fn link_dynamic(
    link_inputs: &[LinkInput],
    lib_dirs: &[std::path::PathBuf],
    interp: &str,
    eh_frame_hdr: bool,
    read_bytes: impl Fn(&std::path::Path) -> Result<Vec<u8>, ExitCode>,
) -> Result<Vec<u8>, ExitCode> {
    let mut inputs = Vec::new();
    for input in link_inputs {
        push_dynamic_input(input, lib_dirs, &read_bytes, &mut inputs)?;
    }
    elf::link_dynamic(inputs, "_start", interp, eh_frame_hdr).map_err(|e| {
        diag::error(&e.to_string());
        ExitCode::from(1)
    })
}

fn resolve_dynamic_lib(name: &str, lib_dirs: &[std::path::PathBuf]) -> Option<std::path::PathBuf> {
    resolve_lib(name, "so", lib_dirs).or_else(|| resolve_lib(name, "a", lib_dirs))
}

fn push_dynamic_input(
    input: &LinkInput,
    lib_dirs: &[std::path::PathBuf],
    read_bytes: &impl Fn(&std::path::Path) -> Result<Vec<u8>, ExitCode>,
    inputs: &mut Vec<elf::DynamicLinkInput>,
) -> Result<(), ExitCode> {
    let p = match input {
        LinkInput::File(p) => p.clone(),
        LinkInput::Lib(name) => match resolve_dynamic_lib(name, lib_dirs) {
            Some(p) => p,
            None => {
                diag::error(&format!("unable to find library -l{name}"));
                return Err(ExitCode::from(1));
            }
        },
        LinkInput::GroupStart => {
            inputs.push(elf::DynamicLinkInput::GroupStart);
            return Ok(());
        }
        LinkInput::GroupEnd => {
            inputs.push(elf::DynamicLinkInput::GroupEnd);
            return Ok(());
        }
    };
    push_dynamic_path(&p, lib_dirs, read_bytes, inputs)
}

fn push_dynamic_path(
    p: &std::path::Path,
    lib_dirs: &[std::path::PathBuf],
    read_bytes: &impl Fn(&std::path::Path) -> Result<Vec<u8>, ExitCode>,
    inputs: &mut Vec<elf::DynamicLinkInput>,
) -> Result<(), ExitCode> {
    let bytes = read_bytes(p)?;
    if bytes.starts_with(archive::AR_MAGIC) || bytes.starts_with(archive::AR_MAGIC_THIN) {
        inputs.push(elf::DynamicLinkInput::Archive(elf::Library {
            name: p.display().to_string(),
            bytes,
        }));
        return Ok(());
    }
    if bytes.len() >= 18 && &bytes[0..4] == b"\x7fELF" {
        // ET_DYN (e_type == 3) is a shared object; otherwise a relocatable.
        if bytes[16] == 3 && bytes[17] == 0 {
            inputs.push(elf::DynamicLinkInput::Shared(parse_shared_lib(p, &bytes)?));
        } else {
            inputs.push(elf::DynamicLinkInput::Object(parse_object(p, &bytes)?));
        }
        return Ok(());
    }
    if let Some(script_inputs) = linker_script_inputs(p, &bytes, lib_dirs) {
        for input in script_inputs {
            push_dynamic_input(&input, lib_dirs, read_bytes, inputs)?;
        }
        return Ok(());
    }
    inputs.push(elf::DynamicLinkInput::Object(parse_object(p, &bytes)?));
    Ok(())
}

fn parse_object(p: &std::path::Path, bytes: &[u8]) -> Result<elf::ElfObject, ExitCode> {
    elf::parse_rel(&p.display().to_string(), bytes).map_err(|e| {
        diag::error(&e.to_string());
        ExitCode::from(1)
    })
}

fn parse_shared_lib(p: &std::path::Path, bytes: &[u8]) -> Result<elf::SharedLib, ExitCode> {
    elf::parse_shared(&p.display().to_string(), bytes).map_err(|e| {
        diag::error(&e.to_string());
        ExitCode::from(1)
    })
}
