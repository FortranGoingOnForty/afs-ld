use std::process::ExitCode;

use afs_ld::{args, diag, LinkError, Linker};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();

    let opts = match args::parse(&argv[1..]) {
        Ok(opts) => opts,
        Err(e) => {
            diag::error(&e.to_string());
            return ExitCode::from(2);
        }
    };

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
