use std::process::ExitCode;

use afs_ld::{args, diag, dump, elf, LinkError, Linker};

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

/// Detect and run the ELF link path. Returns None when no input is
/// an ELF object (Mach-O flow continues unchanged).
fn elf_mode(args: &[String]) -> Option<ExitCode> {
    let mut output: Option<std::path::PathBuf> = None;
    // Positional inputs, in command-line order: an object, an archive,
    // or a shared object.
    let mut inputs: Vec<std::path::PathBuf> = Vec::new();
    let mut lib_dirs: Vec<std::path::PathBuf> = Vec::new();
    // `-lfoo` requests, resolved against `lib_dirs` after arg parsing so
    // a `-L` that follows a `-l` on the command line still applies.
    let mut lib_names: Vec<String> = Vec::new();
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
                    lib_names.push(n.clone());
                }
            }
            "--dynamic-linker" | "-dynamic-linker" => {
                dynamic_linker = it.next().cloned();
            }
            // `--eh-frame-hdr` requests the `.eh_frame_hdr` unwind index +
            // PT_GNU_EH_FRAME (GNU semantics: emitted only when asked).
            "--eh-frame-hdr" => eh_frame_hdr = true,
            "--no-eh-frame-hdr" => eh_frame_hdr = false,
            // Flags we honor or safely ignore. Group markers are no-ops
            // (selection iterates to a global fixed point); -static and a
            // target emulation are the expected mode.
            "-static" | "-Bstatic" | "-Bdynamic" | "--start-group" | "--end-group" | "-("
            | "-)" | "-melf_x86_64" | "-znow" | "--no-as-needed" | "--as-needed" => {}
            "-m" => {
                it.next();
            }
            "-z" => {
                it.next();
            }
            // PIE and shared-object output are later rungs.
            "-pie" | "--pie" | "-shared" | "-Bshareable" => unsupported.push(a.to_string()),
            s if s.starts_with("-L") => lib_dirs.push(std::path::PathBuf::from(&s[2..])),
            s if s.starts_with("-l") => lib_names.push(s[2..].to_string()),
            s if s.starts_with('-') => unsupported.push(s.to_string()),
            _ => inputs.push(std::path::PathBuf::from(a)),
        }
    }
    let is_elf = |p: &std::path::Path| {
        std::fs::read(p)
            .map(|b| b.len() >= 4 && &b[0..4] == b"\x7fELF")
            .unwrap_or(false)
    };
    if !inputs.iter().any(|p| is_elf(p)) {
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
        match link_dynamic(&inputs, &lib_dirs, &lib_names, &interp, eh_frame_hdr, read_bytes) {
            Ok(img) => img,
            Err(code) => return Some(code),
        }
    } else {
        match link_static(&inputs, &lib_dirs, &lib_names, eh_frame_hdr, read_bytes) {
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

/// Static link: objects load eagerly, `ar` archives feed lazy member
/// selection. `-lfoo` resolves to `libfoo.a`.
fn link_static(
    inputs: &[std::path::PathBuf],
    lib_dirs: &[std::path::PathBuf],
    lib_names: &[String],
    eh_frame_hdr: bool,
    read_bytes: impl Fn(&std::path::Path) -> Result<Vec<u8>, ExitCode>,
) -> Result<Vec<u8>, ExitCode> {
    const AR_MAGIC: &[u8] = b"!<arch>\n";
    let mut objects = Vec::new();
    let mut libs: Vec<elf::Library> = Vec::new();
    for p in inputs {
        let bytes = read_bytes(p)?;
        if bytes.starts_with(AR_MAGIC) {
            libs.push(elf::Library { name: p.display().to_string(), bytes });
        } else {
            objects.push(parse_object(p, &bytes)?);
        }
    }
    for name in lib_names {
        let found = lib_dirs.iter().find_map(|d| {
            let cand = d.join(format!("lib{name}.a"));
            cand.exists().then_some(cand)
        });
        let Some(p) = found else {
            diag::error(&format!("unable to find library -l{name}"));
            return Err(ExitCode::from(1));
        };
        libs.push(elf::Library { name: p.display().to_string(), bytes: read_bytes(&p)? });
    }
    elf::link_static(objects, &libs, "_start", eh_frame_hdr).map_err(|e| {
        diag::error(&e.to_string());
        ExitCode::from(1)
    })
}

/// Dynamic link: objects load eagerly; `.so` inputs (positional or from
/// `-lfoo` → `libfoo.so`) provide imports resolved at runtime.
fn link_dynamic(
    inputs: &[std::path::PathBuf],
    lib_dirs: &[std::path::PathBuf],
    lib_names: &[String],
    interp: &str,
    eh_frame_hdr: bool,
    read_bytes: impl Fn(&std::path::Path) -> Result<Vec<u8>, ExitCode>,
) -> Result<Vec<u8>, ExitCode> {
    let mut objects = Vec::new();
    let mut shared = Vec::new();
    let mut push_input = |p: &std::path::Path, bytes: &[u8]| -> Result<(), ExitCode> {
        // ET_DYN (e_type == 3) is a shared object; otherwise a relocatable.
        if bytes.len() >= 18 && bytes[16] == 3 && bytes[17] == 0 {
            shared.push(parse_shared_lib(p, bytes)?);
        } else {
            objects.push(parse_object(p, bytes)?);
        }
        Ok(())
    };
    for p in inputs {
        let bytes = read_bytes(p)?;
        push_input(p, &bytes)?;
    }
    for name in lib_names {
        let found = lib_dirs.iter().find_map(|d| {
            let cand = d.join(format!("lib{name}.so"));
            cand.exists().then_some(cand)
        });
        let Some(p) = found else {
            diag::error(&format!("unable to find shared library -l{name}"));
            return Err(ExitCode::from(1));
        };
        let bytes = read_bytes(&p)?;
        push_input(&p, &bytes)?;
    }
    elf::link_dynamic_exec(&objects, &shared, "_start", interp, eh_frame_hdr).map_err(|e| {
        diag::error(&e.to_string());
        ExitCode::from(1)
    })
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
