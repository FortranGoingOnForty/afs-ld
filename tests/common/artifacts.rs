#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub fn cargo_profile_dir() -> Option<PathBuf> {
    cargo_profile_dir_for_executable(&std::env::current_exe().ok()?)
}

fn cargo_profile_dir_for_executable(executable: &Path) -> Option<PathBuf> {
    let parent = executable.parent()?;
    if parent.file_name() == Some(std::ffi::OsStr::new("deps")) {
        parent.parent().map(Path::to_path_buf)
    } else {
        Some(parent.to_path_buf())
    }
}

pub fn workspace_artifact(file_name: &str) -> Option<PathBuf> {
    let candidate = cargo_profile_dir()?.join(file_name);
    candidate.is_file().then_some(candidate)
}

pub fn workspace_binary(name: &str) -> Option<PathBuf> {
    let file_name = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    workspace_artifact(&file_name)
}
