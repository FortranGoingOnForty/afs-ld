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
    // Positional inputs, in command-line order: an object or an archive.
    let mut inputs: Vec<std::path::PathBuf> = Vec::new();
    let mut lib_dirs: Vec<std::path::PathBuf> = Vec::new();
    // `-lfoo` requests, resolved against `lib_dirs` after arg parsing so
    // a `-L` that follows a `-l` on the command line still applies.
    let mut lib_names: Vec<String> = Vec::new();
    let mut unsupported: Vec<String> = Vec::new();
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
            // Static-link flags we honor or safely ignore: group markers
            // are no-ops (selection iterates to a global fixed point);
            // -static and a target emulation are the expected mode.
            "-static" | "-Bstatic" | "--start-group" | "--end-group"
            | "-(" | "-)" | "--eh-frame-hdr" | "-melf_x86_64" => {}
            "-m" => {
                it.next();
            }
            // Dynamic-only flags belong to rung 3.
            "-pie" | "--pie" | "-shared" | "-Bdynamic" | "--dynamic-linker" | "-dynamic-linker" => {
                unsupported.push(a.to_string());
                if a.ends_with("dynamic-linker") {
                    it.next();
                }
            }
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
            "ELF static mode (x16 rung 2) does not support: {} — dynamic linking lands in rung 3",
            unsupported.join(" ")
        ));
        return Some(ExitCode::from(2));
    }
    let Some(output) = output else {
        diag::error("ELF mode requires -o <output>");
        return Some(ExitCode::from(2));
    };

    // Resolve `-lfoo` to `libfoo.a` on the search path.
    let mut archive_paths: Vec<std::path::PathBuf> = Vec::new();
    for name in &lib_names {
        let found = lib_dirs.iter().find_map(|d| {
            let cand = d.join(format!("lib{name}.a"));
            cand.exists().then_some(cand)
        });
        match found {
            Some(p) => archive_paths.push(p),
            None => {
                diag::error(&format!("unable to find library -l{name}"));
                return Some(ExitCode::from(1));
            }
        }
    }

    // Classify positional inputs by magic: ELF objects load eagerly,
    // `ar` archives feed lazy member selection. Preserve link order.
    const AR_MAGIC: &[u8] = b"!<arch>\n";
    let mut objects = Vec::new();
    let mut libs: Vec<elf::Library> = Vec::new();
    let read_bytes = |p: &std::path::Path| -> Result<Vec<u8>, ExitCode> {
        std::fs::read(p).map_err(|e| {
            diag::error(&format!("{}: {}", p.display(), e));
            ExitCode::from(1)
        })
    };
    for p in &inputs {
        let bytes = match read_bytes(p) {
            Ok(b) => b,
            Err(c) => return Some(c),
        };
        if bytes.starts_with(AR_MAGIC) {
            libs.push(elf::Library {
                name: p.display().to_string(),
                bytes,
            });
        } else {
            match elf::parse_rel(&p.display().to_string(), &bytes) {
                Ok(o) => objects.push(o),
                Err(e) => {
                    diag::error(&e.to_string());
                    return Some(ExitCode::from(1));
                }
            }
        }
    }
    for p in &archive_paths {
        match read_bytes(p) {
            Ok(bytes) => libs.push(elf::Library {
                name: p.display().to_string(),
                bytes,
            }),
            Err(c) => return Some(c),
        }
    }

    match elf::link_static(objects, &libs, "_start") {
        Ok(image) => {
            if let Err(e) = std::fs::write(&output, &image) {
                diag::error(&format!("{}: {}", output.display(), e));
                return Some(ExitCode::from(1));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &output,
                    std::fs::Permissions::from_mode(0o755),
                );
            }
            Some(ExitCode::SUCCESS)
        }
        Err(e) => {
            diag::error(&e.to_string());
            Some(ExitCode::from(1))
        }
    }
}
