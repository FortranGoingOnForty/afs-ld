//! Atomic publication and identity checks for linker artifacts.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
const TEMP_CREATE_ATTEMPTS: usize = 128;

/// Permission handling applied to the completed temporary file before it is
/// renamed over the requested output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMode {
    /// Preserve an existing destination's Unix mode. New outputs retain the
    /// mode selected by normal file creation and the process umask.
    Preserve,
    /// Preserve the base mode and add execute permission wherever the file is
    /// readable, matching the Mach-O executable publication contract.
    AddExecute,
    /// Apply one exact Unix permission mode.
    Exact(u32),
}

/// Write a complete image beside its destination and atomically publish it.
///
/// Returned errors leave an existing destination untouched. Temporary files
/// are removed on every ordinary error path.
pub fn write_atomic(
    output: &Path,
    contents: &[u8],
    permission_mode: PermissionMode,
) -> io::Result<()> {
    write_atomic_with(output, permission_mode, |file| file.write_all(contents))
}

/// Return whether two paths currently name, or would publish to, the same file.
///
/// Existing paths are compared by filesystem identity so hard links and
/// symlinks are detected. Missing leaves are compared after resolving their
/// deepest existing ancestor, which also handles relative paths, `.` / `..`,
/// and symlinked parent directories.
pub(crate) fn paths_alias(left: &Path, right: &Path) -> io::Result<bool> {
    let left_identity = existing_file_identity(left)?;
    let right_identity = existing_file_identity(right)?;
    if left_identity.is_some() && left_identity == right_identity {
        return Ok(true);
    }

    Ok(comparison_path(left)? == comparison_path(right)?)
}

fn existing_file_identity(path: &Path) -> io::Result<Option<(u64, u64)>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some((metadata.dev(), metadata.ino()))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn comparison_path(path: &Path) -> io::Result<PathBuf> {
    let mut ancestor = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut missing_suffix = Vec::new();

    loop {
        match fs::canonicalize(&ancestor) {
            Ok(mut canonical) => {
                for component in missing_suffix.iter().rev() {
                    canonical.push(component);
                }
                return Ok(normalize_lexically(&canonical));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let Some(component) = ancestor.components().next_back() else {
                    return Err(error);
                };
                if matches!(component, Component::RootDir | Component::Prefix(_)) {
                    return Err(error);
                }
                missing_suffix.push(component.as_os_str().to_os_string());
                if !ancestor.pop() {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn write_atomic_with(
    output: &Path,
    permission_mode: PermissionMode,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let directory = output_directory(output);
    let mut pending = PendingOutput::create(directory)?;
    write(pending.file_mut())?;
    pending.apply_permissions(output, permission_mode)?;
    pending.commit(output)
}

fn output_directory(output: &Path) -> &Path {
    output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

struct PendingOutput {
    path: Option<PathBuf>,
    file: Option<File>,
}

impl PendingOutput {
    fn create(directory: &Path) -> io::Result<Self> {
        for _ in 0..TEMP_CREATE_ATTEMPTS {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let mut name = OsString::from(".afs-ld-tmp-");
            name.push(std::process::id().to_string());
            name.push("-");
            name.push(format!("{id:016x}"));
            let path = directory.join(name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path: Some(path),
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "unable to create a unique temporary output in {}",
                directory.display()
            ),
        ))
    }

    fn file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("pending output owns its file until commit")
    }

    fn apply_permissions(&self, output: &Path, permission_mode: PermissionMode) -> io::Result<()> {
        let file = self
            .file
            .as_ref()
            .expect("pending output owns its file until commit");

        let mode = match permission_mode {
            PermissionMode::Preserve => existing_mode(output)?,
            PermissionMode::AddExecute => {
                let base =
                    existing_mode(output)?.unwrap_or(file.metadata()?.permissions().mode() & 0o777);
                Some(base | ((base & 0o444) >> 2))
            }
            PermissionMode::Exact(mode) => Some(mode),
        };
        if let Some(mode) = mode {
            file.set_permissions(Permissions::from_mode(mode))?;
        }
        Ok(())
    }

    fn commit(mut self, output: &Path) -> io::Result<()> {
        drop(self.file.take());
        fs::rename(
            self.path
                .as_ref()
                .expect("pending output owns its path until commit"),
            output,
        )?;
        self.path = None;
        Ok(())
    }
}

fn existing_mode(output: &Path) -> io::Result<Option<u32>> {
    match fs::metadata(output) {
        Ok(metadata) => Ok(Some(metadata.permissions().mode() & 0o777)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

impl Drop for PendingOutput {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(label: &str) -> Self {
            loop {
                let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("afs-ld-output-{label}-{}-{id}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create scratch directory: {error}"),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn assert_no_temporary_output(directory: &Path) {
        assert!(fs::read_dir(directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("afs-ld-tmp")
        }));
    }

    #[test]
    fn failed_partial_write_preserves_destination_and_removes_temporary_file() {
        let scratch = ScratchDir::new("write-failure");
        let output = scratch.path().join("linked");
        let sentinel = b"previous complete output";
        fs::write(&output, sentinel).unwrap();

        let error = write_atomic_with(&output, PermissionMode::Preserve, |file| {
            file.write_all(b"partial replacement")?;
            Err(io::Error::other("injected write failure"))
        })
        .expect_err("injected write failure must abort publication");

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(fs::read(&output).unwrap(), sentinel);
        assert_no_temporary_output(scratch.path());
    }

    #[test]
    fn successful_publication_applies_each_permission_policy() {
        let scratch = ScratchDir::new("permissions");
        for (name, permission_mode, expected_mode) in [
            ("preserve", PermissionMode::Preserve, 0o640),
            ("add-execute", PermissionMode::AddExecute, 0o750),
            ("exact", PermissionMode::Exact(0o755), 0o755),
        ] {
            let output = scratch.path().join(name);
            fs::write(&output, b"old").unwrap();
            fs::set_permissions(&output, Permissions::from_mode(0o640)).unwrap();

            write_atomic(&output, b"complete image", permission_mode).unwrap();

            assert_eq!(fs::read(&output).unwrap(), b"complete image");
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                expected_mode
            );
        }
        assert_no_temporary_output(scratch.path());
    }
}
