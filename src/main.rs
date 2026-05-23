use std::process::ExitCode;

use afs_ld::{args, diag, dump, LinkError, Linker};

fn usage() -> &'static str {
    "\
Usage: afs-ld [options] <inputs...>

Inputs:
  <path>                          Object, archive, dylib, or TBD input
  -l<name> / -l <name>            Search for library
  -L <dir>                        Add library search path
  -framework <name>               Link framework
  -weak_framework <name>          Link weak framework
  -all_load                       Force-load every archive member
  -force_load <archive>           Force-load one archive

Outputs:
  -o <path>                       Write output to <path>
  -dylib                          Emit a dylib instead of an executable
  -e <symbol>                     Set the entry symbol
  -rpath <path>                   Add LC_RPATH
  -install_name <path>            Override dylib install name
  -current_version <v>            Override dylib current version
  -compatibility_version <v>      Override dylib compatibility version

Symbols:
  -undefined <error|warning|suppress|dynamic_lookup>
                                  Control unresolved-symbol treatment
  -exported_symbols_list <file>   Export only symbols matching file patterns
  -unexported_symbols_list <file> Hide symbols matching file patterns
  -exported_symbol <sym>          Export one symbol/pattern
  -unexported_symbol <sym>        Hide one symbol/pattern
  -x                              Strip local symbols

Optimization:
  -no_uuid                        Omit LC_UUID
  -no_loh                         Compatibility no-op (currently warns)
  -thunks=<none|safe|all>         Configure branch thunks
  -dead_strip                     Dead-strip unreferenced code/data
  -icf=safe | -icf=none | -icf=all
                                  Configure ICF (`all` errors)
  -fixup_chains | -no_fixup_chains
                                  Select chained fixups vs classic dyld info

Diagnostics:
  -map <path>                     Emit text link map
  -why_live <symbol>              Print a reachability chain for <symbol>
  -t, -trace                      Print input paths as they are loaded
  --color=<auto|always|never>     Control ANSI diagnostic color (default: auto)
  --dump <path>                   Dump a Mach-O file summary
  --dump-archive <path>           Dump an archive summary
  --dump-dylib <path>             Dump a dylib summary
  --dump-tbd <path>               Dump a TBD summary
  -h, --help                      Show this help
  -v, --version                   Show afs-ld version

Platform:
  -arch arm64                     Select the arm64 target
  -syslibroot <path>              Prefix SDK search roots
  -platform_version macos <min> <sdk>
                                  Set LC_BUILD_VERSION payload

Compatibility:
  -ObjC                           Objective-C archive loading (warns; no effect)
  -S                              Strip debug symbols (warns; no effect)
  -r                              Relocatable output (deferred; errors)
  -bundle                         Bundle output (deferred; errors)
  -j <jobs>                       Limit worker jobs (`1` disables parallelism)
  -Wl,<arg,arg,...>               Normalize comma-separated driver flags
"
}

fn version() -> String {
    format!(
        "afs-ld {}\n\
         Bespoke ARM64 Mach-O linker for armfortas\n\
         Target: arm64-apple-macos\n\
         Commit: {}\n",
        env!("CARGO_PKG_VERSION"),
        env!("AFS_LD_COMMIT")
    )
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    diag::configure_from_argv(&argv[1..]);

    let opts = match args::parse(&argv[1..]) {
        Ok(opts) => opts,
        Err(e) => {
            diag::error(&e.to_string());
            return ExitCode::from(2);
        }
    };
    diag::set_color_mode(opts.color);

    if opts.show_help {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }

    if opts.show_version {
        print!("{}", version());
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
        Err(LinkError::MalformedInput { path, bytes, error }) => {
            diag::binary_error(&path, &bytes, &error);
            ExitCode::from(65)
        }
        Err(e) => {
            diag::error(&e.to_string());
            ExitCode::from(1)
        }
    }
}
