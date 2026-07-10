use std::path::Path;

#[path = "common/artifacts.rs"]
mod artifacts;

#[test]
fn workspace_artifacts_follow_the_running_test_profile() {
    let test_executable = std::env::current_exe().expect("resolve current test executable");
    let deps_dir = test_executable
        .parent()
        .expect("test executable has a parent directory");
    assert_eq!(deps_dir.file_name(), Some(Path::new("deps").as_os_str()));

    let profile_dir = deps_dir.parent().expect("deps has a profile directory");
    assert_eq!(artifacts::cargo_profile_dir().as_deref(), Some(profile_dir));

    let linker = artifacts::workspace_binary("afs-ld")
        .expect("afs-ld binary must be built for integration tests");
    assert_eq!(linker.parent(), Some(profile_dir));
}
