use std::collections::HashSet;
use std::process::ExitCode;

use afs_ld::{archive, args, diag, dump, elf, output, LinkError, Linker};

fn usage() -> &'static str {
    "\
Usage: afs-ld [options] <inputs...>

Options:
  -o <path>                       Write output to <path>
  -dylib                          Emit a dylib instead of an executable
  -e <symbol>                     Set the entry symbol
  -arch arm64                     Select the arm64 target
  -melf_x86_64 / -m elf_x86_64   Select the x86_64 ELF target
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
  --gc-sections                   Discard unreachable ELF input sections
  --no-gc-sections                Keep all ELF input sections
  -z execstack | -z noexecstack   Override ELF stack executability
  -z lazy | -z now                Select lazy or eager ELF symbol binding
  -icf=safe | -icf=none | -icf=all
                                  Configure identical code folding (`all` currently errors)
  -fixup_chains | -no_fixup_chains
                                  Select chained fixups vs classic dyld info
  -all_load                       Force-load every archive member
  -force_load <archive>           Force-load one archive
  -j <jobs>                       Limit parallel worker jobs (`1` disables parallelism)
  @<file>                         Read additional arguments from <file>
  @@<path>                        Treat @<path> as a literal input path
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
    let preprocessed = match args::preprocess_args(&argv[1..]) {
        Ok(preprocessed) => preprocessed,
        Err(e) => {
            diag::error(&e.to_string());
            return ExitCode::from(2);
        }
    };

    // Route explicit x86_64 ELF emulation and direct or indirect ELF
    // inputs before the Mach-O argument surface sees them.
    if let Some(code) = elf_mode(&preprocessed) {
        return code;
    }

    let (parsed, force_load_positions) =
        match args::parse_preprocessed_with_force_loads(&preprocessed) {
            Ok(parsed) => parsed,
            Err(e) => {
                diag::error(&e.to_string());
                return ExitCode::from(2);
            }
        };
    let opts = parsed.options;

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

    match Linker::run_ordered_with_force_loads(&opts, &parsed.input_specs, &force_load_positions) {
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
    File {
        path: std::path::PathBuf,
        as_needed: bool,
        library_search: LibrarySearchMode,
    },
    /// A `-lfoo` request, resolved against the search dirs in link order.
    Lib {
        name: String,
        as_needed: bool,
        library_search: LibrarySearchMode,
    },
    /// Start a repeated archive search group.
    GroupStart,
    /// End a repeated archive search group.
    GroupEnd,
}

/// Search policy captured at each input's command-line position. Dynamic
/// links normally prefer a shared object and fall back to an archive;
/// `-Bstatic` restricts following `-l` requests to archives until restored.
#[derive(Clone, Copy, Default)]
enum LibrarySearchMode {
    #[default]
    DynamicPreferred,
    StaticOnly,
}

#[derive(Clone, Copy, Default)]
struct ElfModeOptions {
    eh_frame_hdr: bool,
    gc_sections: bool,
    policy: elf::ElfLinkPolicy,
}

fn apply_elf_z_policy(
    keyword: &str,
    policy: &mut elf::ElfLinkPolicy,
) -> Result<(), args::ArgsError> {
    match keyword {
        "execstack" => policy.executable_stack = Some(true),
        "noexecstack" => policy.executable_stack = Some(false),
        "lazy" => policy.bind_now = false,
        "now" => policy.bind_now = true,
        _ => {
            return Err(args::ArgsError::InvalidValue {
                flag: "-z".to_string(),
                value: keyword.to_string(),
                expected: "`execstack`, `noexecstack`, `lazy`, or `now`".to_string(),
            });
        }
    }
    Ok(())
}

/// Detect and run the ELF link path. Returns None when neither an explicit
/// ELF emulation nor a direct or indirect ELF input selects it.
fn elf_mode(args: &[String]) -> Option<ExitCode> {
    let mut output: Option<std::path::PathBuf> = None;
    // Inputs in command-line order, positional files and `-l` requests
    // interleaved. `-L` search dirs accumulate separately and apply to
    // every `-l` regardless of relative position.
    let mut link_inputs: Vec<LinkInput> = Vec::new();
    let mut lib_dirs: Vec<std::path::PathBuf> = Vec::new();
    let mut unsupported: Vec<String> = Vec::new();
    let mut argument_error: Option<args::ArgsError> = None;
    let mut dynamic_linker: Option<String> = None;
    let mut options = ElfModeOptions::default();
    let mut as_needed = false;
    let mut library_search = LibrarySearchMode::default();
    let mut elf_emulation = false;
    let mut entry = "_start".to_string();
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
                    link_inputs.push(LinkInput::Lib {
                        name: n.clone(),
                        as_needed,
                        library_search,
                    });
                }
            }
            "--dynamic-linker" | "-dynamic-linker" => {
                if let Some(path) = it.next() {
                    dynamic_linker = Some(path.clone());
                } else {
                    argument_error = Some(args::ArgsError::MissingValue(a.clone()));
                }
            }
            "-e" => {
                if let Some(symbol) = it.next() {
                    entry = symbol.clone();
                } else {
                    unsupported.push("-e (missing symbol)".to_string());
                }
            }
            // `--eh-frame-hdr` requests the `.eh_frame_hdr` unwind index +
            // PT_GNU_EH_FRAME (GNU semantics: emitted only when asked).
            "--eh-frame-hdr" => options.eh_frame_hdr = true,
            "--no-eh-frame-hdr" => options.eh_frame_hdr = false,
            "--gc-sections" => options.gc_sections = true,
            "--no-gc-sections" => options.gc_sections = false,
            "--start-group" | "-(" => link_inputs.push(LinkInput::GroupStart),
            "--end-group" | "-)" => link_inputs.push(LinkInput::GroupEnd),
            // Flags we honor or safely ignore. -static and a target
            // emulation are the expected mode.
            "--as-needed" => as_needed = true,
            "--no-as-needed" => as_needed = false,
            "-melf_x86_64" => elf_emulation = true,
            "-static" | "-Bstatic" | "-dn" | "-non_shared" => {
                library_search = LibrarySearchMode::StaticOnly;
            }
            "-Bdynamic" | "-dy" | "-call_shared" => {
                library_search = LibrarySearchMode::DynamicPreferred;
            }
            "-m" => match it.next() {
                Some(emulation) if emulation == "elf_x86_64" => elf_emulation = true,
                Some(emulation) => unsupported.push(format!("-m {emulation}")),
                None => unsupported.push("-m (missing emulation)".to_string()),
            },
            "-z" => match it.next() {
                Some(keyword) => {
                    if let Err(error) = apply_elf_z_policy(keyword, &mut options.policy) {
                        argument_error.get_or_insert(error);
                    }
                }
                None => {
                    argument_error.get_or_insert_with(|| args::ArgsError::MissingValue(a.clone()));
                }
            },
            // PIE and shared-object output are later rungs.
            "-pie" | "--pie" | "-shared" | "-Bshareable" => unsupported.push(a.to_string()),
            s if s.starts_with("-L") => lib_dirs.push(std::path::PathBuf::from(&s[2..])),
            s if s.starts_with("-l") => link_inputs.push(LinkInput::Lib {
                name: s[2..].to_string(),
                as_needed,
                library_search,
            }),
            s if s.starts_with("-z") => {
                if let Err(error) = apply_elf_z_policy(&s[2..], &mut options.policy) {
                    argument_error.get_or_insert(error);
                }
            }
            s if s.starts_with('-') => unsupported.push(s.to_string()),
            _ => link_inputs.push(LinkInput::File {
                path: std::path::PathBuf::from(a),
                as_needed,
                library_search,
            }),
        }
    }
    let dynamic = dynamic_linker.is_some();
    if let Some(error) = argument_error {
        diag::error(&error.to_string());
        return Some(ExitCode::from(2));
    }
    if !elf_emulation && !link_inputs_select_elf(&link_inputs, &lib_dirs, dynamic) {
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
        match link_dynamic(
            &link_inputs,
            &lib_dirs,
            &entry,
            &interp,
            options,
            read_bytes,
        ) {
            Ok(img) => img,
            Err(code) => return Some(code),
        }
    } else {
        match link_static(&link_inputs, &lib_dirs, &entry, options, read_bytes) {
            Ok(img) => img,
            Err(code) => return Some(code),
        }
    };

    if let Err(e) = output::write_atomic(&output, &image, output::PermissionMode::Exact(0o755)) {
        diag::error(&format!("{}: {}", output.display(), e));
        return Some(ExitCode::from(1));
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
    as_needed: bool,
    library_search: LibrarySearchMode,
    out: &mut Vec<LinkInput>,
) {
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "GROUP" => {
                if let Some((inner, next)) = parenthesized(tokens, i + 1) {
                    out.push(LinkInput::GroupStart);
                    collect_script_inputs(inner, script, lib_dirs, as_needed, library_search, out);
                    out.push(LinkInput::GroupEnd);
                    i = next;
                } else {
                    i += 1;
                }
            }
            "INPUT" => {
                if let Some((inner, next)) = parenthesized(tokens, i + 1) {
                    collect_script_inputs(inner, script, lib_dirs, as_needed, library_search, out);
                    i = next;
                } else {
                    i += 1;
                }
            }
            "AS_NEEDED" => {
                if let Some((inner, next)) = parenthesized(tokens, i + 1) {
                    collect_script_inputs(inner, script, lib_dirs, true, library_search, out);
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
                out.push(LinkInput::Lib {
                    name: token[2..].to_string(),
                    as_needed,
                    library_search,
                });
                i += 1;
            }
            token if token.starts_with('-') => i += 1,
            token => {
                out.push(LinkInput::File {
                    path: resolve_script_path(script, token, lib_dirs),
                    as_needed,
                    library_search,
                });
                i += 1;
            }
        }
    }
}

fn linker_script_inputs(
    script: &std::path::Path,
    bytes: &[u8],
    lib_dirs: &[std::path::PathBuf],
    as_needed: bool,
    library_search: LibrarySearchMode,
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
                    collect_script_inputs(
                        inner,
                        script,
                        lib_dirs,
                        as_needed,
                        library_search,
                        &mut out,
                    );
                    out.push(LinkInput::GroupEnd);
                    i = next;
                } else {
                    i += 1;
                }
            }
            "INPUT" => {
                if let Some((inner, next)) = parenthesized(&tokens, i + 1) {
                    collect_script_inputs(
                        inner,
                        script,
                        lib_dirs,
                        as_needed,
                        library_search,
                        &mut out,
                    );
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

fn link_inputs_select_elf(
    link_inputs: &[LinkInput],
    lib_dirs: &[std::path::PathBuf],
    dynamic: bool,
) -> bool {
    let mut script_stack = HashSet::new();
    link_inputs
        .iter()
        .any(|input| link_input_selects_elf(input, lib_dirs, dynamic, &mut script_stack))
}

fn link_input_selects_elf(
    input: &LinkInput,
    lib_dirs: &[std::path::PathBuf],
    dynamic: bool,
    script_stack: &mut HashSet<std::path::PathBuf>,
) -> bool {
    let (path, library_search) = match input {
        LinkInput::File {
            path,
            library_search,
            ..
        } => (path.clone(), *library_search),
        LinkInput::Lib {
            name,
            library_search,
            ..
        } => {
            let resolved = if dynamic {
                resolve_dynamic_lib(name, lib_dirs, *library_search)
            } else {
                resolve_lib(name, "a", lib_dirs)
            };
            let Some(path) = resolved else {
                return false;
            };
            (path, *library_search)
        }
        LinkInput::GroupStart | LinkInput::GroupEnd => return false,
    };
    path_selects_elf(&path, lib_dirs, dynamic, library_search, script_stack)
}

fn path_selects_elf(
    path: &std::path::Path,
    lib_dirs: &[std::path::PathBuf],
    dynamic: bool,
    library_search: LibrarySearchMode,
    script_stack: &mut HashSet<std::path::PathBuf>,
) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    if bytes.starts_with(b"\x7fELF") {
        return true;
    }
    if bytes.starts_with(archive::AR_MAGIC) || bytes.starts_with(archive::AR_MAGIC_THIN) {
        let Ok(container) = archive::Archive::open(path, &bytes) else {
            return false;
        };
        return container.object_members().any(|member| {
            container
                .member_bytes(member)
                .is_ok_and(|member_bytes| member_bytes.starts_with(b"\x7fELF"))
        });
    }
    let Some(script_inputs) = linker_script_inputs(path, &bytes, lib_dirs, false, library_search)
    else {
        return false;
    };
    let identity = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !script_stack.insert(identity.clone()) {
        return false;
    }
    let selects_elf = script_inputs
        .iter()
        .any(|input| link_input_selects_elf(input, lib_dirs, dynamic, script_stack));
    script_stack.remove(&identity);
    selects_elf
}

/// Static link: objects load eagerly, `ar` archives feed lazy member
/// selection. `-lfoo` resolves to `libfoo.a`. Inputs are consumed in
/// command-line order so archive symbol resolution matches GNU ld
/// left-to-right: the first eligible archive that defines a symbol wins,
/// and interleaving `-l` with positional archives is honored.
fn link_static(
    link_inputs: &[LinkInput],
    lib_dirs: &[std::path::PathBuf],
    entry: &str,
    options: ElfModeOptions,
    read_bytes: impl Fn(&std::path::Path) -> Result<Vec<u8>, ExitCode>,
) -> Result<Vec<u8>, ExitCode> {
    let mut inputs = Vec::new();
    let mut script_stack = HashSet::new();
    for input in link_inputs {
        push_static_input(input, lib_dirs, &read_bytes, &mut script_stack, &mut inputs)?;
    }
    elf::link_static_with_gc_and_policy(
        inputs,
        entry,
        options.eh_frame_hdr,
        options.gc_sections,
        options.policy,
    )
    .map_err(|e| {
        diag::error(&e.to_string());
        ExitCode::from(1)
    })
}

fn push_static_input(
    input: &LinkInput,
    lib_dirs: &[std::path::PathBuf],
    read_bytes: &impl Fn(&std::path::Path) -> Result<Vec<u8>, ExitCode>,
    script_stack: &mut HashSet<std::path::PathBuf>,
    inputs: &mut Vec<elf::LinkInput>,
) -> Result<(), ExitCode> {
    let (path, library_search) = match input {
        LinkInput::File {
            path,
            library_search,
            ..
        } => (path.clone(), *library_search),
        LinkInput::Lib {
            name,
            library_search,
            ..
        } => match resolve_lib(name, "a", lib_dirs) {
            Some(path) => (path, *library_search),
            None => {
                diag::error(&format!("unable to find library -l{name}"));
                return Err(ExitCode::from(1));
            }
        },
        LinkInput::GroupStart => {
            inputs.push(elf::LinkInput::GroupStart);
            return Ok(());
        }
        LinkInput::GroupEnd => {
            inputs.push(elf::LinkInput::GroupEnd);
            return Ok(());
        }
    };
    push_static_path(
        &path,
        lib_dirs,
        library_search,
        read_bytes,
        script_stack,
        inputs,
    )
}

fn push_static_path(
    path: &std::path::Path,
    lib_dirs: &[std::path::PathBuf],
    library_search: LibrarySearchMode,
    read_bytes: &impl Fn(&std::path::Path) -> Result<Vec<u8>, ExitCode>,
    script_stack: &mut HashSet<std::path::PathBuf>,
    inputs: &mut Vec<elf::LinkInput>,
) -> Result<(), ExitCode> {
    let bytes = read_bytes(path)?;
    if bytes.starts_with(archive::AR_MAGIC) || bytes.starts_with(archive::AR_MAGIC_THIN) {
        inputs.push(elf::LinkInput::Archive(elf::Library {
            name: path.display().to_string(),
            path: path.to_path_buf(),
            bytes,
        }));
        return Ok(());
    }
    if bytes.starts_with(b"\x7fELF") {
        inputs.push(elf::LinkInput::Object(parse_object(path, &bytes)?));
        return Ok(());
    }
    if let Some(script_inputs) = linker_script_inputs(path, &bytes, lib_dirs, false, library_search)
    {
        let identity = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if !script_stack.insert(identity.clone()) {
            diag::error(&format!("linker script cycle involving {}", path.display()));
            return Err(ExitCode::from(1));
        }
        let result = script_inputs.iter().try_for_each(|input| {
            push_static_input(input, lib_dirs, read_bytes, script_stack, inputs)
        });
        script_stack.remove(&identity);
        return result;
    }
    inputs.push(elf::LinkInput::Object(parse_object(path, &bytes)?));
    Ok(())
}

/// Dynamic link: objects load eagerly; `.a` inputs feed lazy member
/// selection; `.so` inputs (positional, script-expanded, or from
/// `-lfoo`) provide imports resolved at runtime. Inputs are consumed in
/// command-line order.
fn link_dynamic(
    link_inputs: &[LinkInput],
    lib_dirs: &[std::path::PathBuf],
    entry: &str,
    interp: &str,
    options: ElfModeOptions,
    read_bytes: impl Fn(&std::path::Path) -> Result<Vec<u8>, ExitCode>,
) -> Result<Vec<u8>, ExitCode> {
    let mut inputs = Vec::new();
    let mut script_stack = HashSet::new();
    for input in link_inputs {
        push_dynamic_input(input, lib_dirs, &read_bytes, &mut script_stack, &mut inputs)?;
    }
    elf::link_dynamic_with_as_needed_gc_and_policy(
        inputs,
        entry,
        interp,
        options.eh_frame_hdr,
        options.gc_sections,
        options.policy,
    )
    .map_err(|e| {
        diag::error(&e.to_string());
        ExitCode::from(1)
    })
}

fn resolve_dynamic_lib(
    name: &str,
    lib_dirs: &[std::path::PathBuf],
    library_search: LibrarySearchMode,
) -> Option<std::path::PathBuf> {
    match library_search {
        LibrarySearchMode::DynamicPreferred => lib_dirs.iter().find_map(|dir| {
            ["so", "a"].iter().find_map(|extension| {
                let candidate = dir.join(format!("lib{name}.{extension}"));
                candidate.exists().then_some(candidate)
            })
        }),
        LibrarySearchMode::StaticOnly => resolve_lib(name, "a", lib_dirs),
    }
}

fn push_dynamic_input(
    input: &LinkInput,
    lib_dirs: &[std::path::PathBuf],
    read_bytes: &impl Fn(&std::path::Path) -> Result<Vec<u8>, ExitCode>,
    script_stack: &mut HashSet<std::path::PathBuf>,
    inputs: &mut Vec<(elf::DynamicLinkInput, bool, Option<elf::SharedLinkMetadata>)>,
) -> Result<(), ExitCode> {
    let (p, as_needed, library_search) = match input {
        LinkInput::File {
            path,
            as_needed,
            library_search,
        } => (path.clone(), *as_needed, *library_search),
        LinkInput::Lib {
            name,
            as_needed,
            library_search,
        } => match resolve_dynamic_lib(name, lib_dirs, *library_search) {
            Some(p) => (p, *as_needed, *library_search),
            None => {
                diag::error(&format!("unable to find library -l{name}"));
                return Err(ExitCode::from(1));
            }
        },
        LinkInput::GroupStart => {
            inputs.push((elf::DynamicLinkInput::GroupStart, false, None));
            return Ok(());
        }
        LinkInput::GroupEnd => {
            inputs.push((elf::DynamicLinkInput::GroupEnd, false, None));
            return Ok(());
        }
    };
    push_dynamic_path(
        &p,
        lib_dirs,
        as_needed,
        library_search,
        read_bytes,
        script_stack,
        inputs,
    )
}

fn push_dynamic_path(
    p: &std::path::Path,
    lib_dirs: &[std::path::PathBuf],
    as_needed: bool,
    library_search: LibrarySearchMode,
    read_bytes: &impl Fn(&std::path::Path) -> Result<Vec<u8>, ExitCode>,
    script_stack: &mut HashSet<std::path::PathBuf>,
    inputs: &mut Vec<(elf::DynamicLinkInput, bool, Option<elf::SharedLinkMetadata>)>,
) -> Result<(), ExitCode> {
    let bytes = read_bytes(p)?;
    if bytes.starts_with(archive::AR_MAGIC) || bytes.starts_with(archive::AR_MAGIC_THIN) {
        inputs.push((
            elf::DynamicLinkInput::Archive(elf::Library {
                name: p.display().to_string(),
                path: p.to_path_buf(),
                bytes,
            }),
            false,
            None,
        ));
        return Ok(());
    }
    if bytes.len() >= 18 && &bytes[0..4] == b"\x7fELF" {
        // ET_DYN (e_type == 3) is a shared object; otherwise a relocatable.
        if bytes[16] == 3 && bytes[17] == 0 {
            let (lib, metadata) = parse_shared_lib(p, &bytes)?;
            inputs.push((
                elf::DynamicLinkInput::Shared(lib),
                as_needed,
                Some(metadata),
            ));
        } else {
            inputs.push((
                elf::DynamicLinkInput::Object(parse_object(p, &bytes)?),
                false,
                None,
            ));
        }
        return Ok(());
    }
    if let Some(script_inputs) =
        linker_script_inputs(p, &bytes, lib_dirs, as_needed, library_search)
    {
        let identity = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        if !script_stack.insert(identity.clone()) {
            diag::error(&format!("linker script cycle involving {}", p.display()));
            return Err(ExitCode::from(1));
        }
        let result = script_inputs.iter().try_for_each(|input| {
            push_dynamic_input(input, lib_dirs, read_bytes, script_stack, inputs)
        });
        script_stack.remove(&identity);
        return result;
    }
    inputs.push((
        elf::DynamicLinkInput::Object(parse_object(p, &bytes)?),
        false,
        None,
    ));
    Ok(())
}

fn parse_object(p: &std::path::Path, bytes: &[u8]) -> Result<elf::ElfObject, ExitCode> {
    elf::parse_rel(&p.display().to_string(), bytes).map_err(|e| {
        diag::error(&e.to_string());
        ExitCode::from(1)
    })
}

fn parse_shared_lib(
    p: &std::path::Path,
    bytes: &[u8],
) -> Result<(elf::SharedLib, elf::SharedLinkMetadata), ExitCode> {
    elf::parse_shared_with_metadata(&p.display().to_string(), bytes).map_err(|e| {
        diag::error(&e.to_string());
        ExitCode::from(1)
    })
}
