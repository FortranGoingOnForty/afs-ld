use std::process::ExitCode;

use afs_ld::{args, diag, dump, LinkError, Linker};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();

    let opts = match args::parse(&argv[1..]) {
        Ok(opts) => opts,
        Err(e) => {
            diag::error(&e.to_string());
            return ExitCode::from(2);
        }
    };

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

    match Linker::run(&opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(LinkError::NoInputs) => {
            diag::error("no input files");
            ExitCode::from(2)
        }
        Err(e) => {
            diag::error(&e.to_string());
            ExitCode::from(1)
        }
    }
}
