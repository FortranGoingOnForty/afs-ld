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
    let mut inputs: Vec<std::path::PathBuf> = Vec::new();
    let mut unsupported: Vec<String> = Vec::new();
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-o" => {
                output = it.next().map(std::path::PathBuf::from);
            }
            s if s.starts_with('-') => unsupported.push(s.to_string()),
            _ => inputs.push(std::path::PathBuf::from(a)),
        }
    }
    let any_elf = inputs.iter().any(|p| {
        std::fs::read(p)
            .map(|b| b.len() >= 4 && &b[0..4] == b"\x7fELF")
            .unwrap_or(false)
    });
    if !any_elf {
        return None;
    }
    if !unsupported.is_empty() {
        diag::error(&format!(
            "ELF mode (x16 rung 1) supports only `-o <out> <objects...>`; unsupported: {} — the crt/library contract lands in rung 2",
            unsupported.join(" ")
        ));
        return Some(ExitCode::from(2));
    }
    let Some(output) = output else {
        diag::error("ELF mode requires -o <output>");
        return Some(ExitCode::from(2));
    };
    let mut objects = Vec::new();
    for p in &inputs {
        let bytes = match std::fs::read(p) {
            Ok(b) => b,
            Err(e) => {
                diag::error(&format!("{}: {}", p.display(), e));
                return Some(ExitCode::from(1));
            }
        };
        match elf::parse_rel(&p.display().to_string(), &bytes) {
            Ok(o) => objects.push(o),
            Err(e) => {
                diag::error(&e.to_string());
                return Some(ExitCode::from(1));
            }
        }
    }
    match elf::link_static_exec(&objects, "_start") {
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
