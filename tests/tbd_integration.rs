//! Sprint 6 real-world gate: parse the installed SDK's `libSystem.tbd`,
//! materialize it as a `DylibFile` for `arm64-macos`, and confirm:
//!
//! - every TBD document parses cleanly (`parse_tbd` returns multiple,
//!   each with an `install-name`);
//! - the main document's DylibFile surfaces libSystem's direct
//!   exports (small set — `_mach_init_routine`,
//!   `_libSystem_init_after_boot_tasks_4launchd`, `___crashreporter_info__`);
//! - `reexported-libraries` surfaces as `DylibDependency` entries with
//!   `Reexport` load kind, with monotonic 1-based ordinals;
//! - scanning every document's exports reveals _malloc / _free
//!   somewhere in the re-export chain (libsystem_malloc / libsystem_c).
//!
//! Note: the SDK surfaces `dyld_stub_binder` in libSystem's re-export chain
//! (via the libdyld sub-document), not as a direct export of the main
//! libSystem umbrella document. Sprint 12 still handles it specially because
//! stub-helper synthesis needs to pin that import to libSystem's umbrella
//! load-command identity.
//!
//! Skipped if `xcrun` or `libSystem.tbd` aren't present.

use afs_ld::macho::dylib::{DylibFile, DylibLoadKind};
use afs_ld::macho::tbd::{parse_tbd, Arch, Platform, Target};

fn sdk_path() -> Option<String> {
    let out = std::process::Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[test]
fn libsystem_tbd_materializes_into_dylib_file() {
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: SDK path unavailable");
        return;
    };
    let path = format!("{sdk}/usr/lib/libSystem.tbd");
    let Ok(src) = std::fs::read_to_string(&path) else {
        eprintln!("skipping: libSystem.tbd not found at {path}");
        return;
    };
    let docs = parse_tbd(&src).unwrap_or_else(|e| panic!("libSystem.tbd failed to parse: {e}"));
    assert!(docs.len() >= 2, "expected multi-doc TBD");

    let main = &docs[0];
    assert_eq!(main.install_name, "/usr/lib/libSystem.B.dylib");

    let target = Target {
        arch: Arch::Arm64,
        platform: Platform::MacOs,
    };
    let dy = DylibFile::from_tbd(&path, main, &target);

    assert_eq!(dy.install_name, "/usr/lib/libSystem.B.dylib");

    // libSystem's main TBD doc only exposes a short list of internal
    // symbols directly; everything useful (malloc, printf, dyld binder)
    // flows through its `reexported-libraries`. Confirm at least one of
    // the direct exports made it through.
    let exports = dy.exports.entries().unwrap();
    let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
    let direct_candidates = [
        "_mach_init_routine",
        "_libSystem_init_after_boot_tasks_4launchd",
        "___crashreporter_info__",
    ];
    assert!(
        direct_candidates.iter().any(|n| names.contains(n)),
        "no libSystem direct export found; got {names:?}"
    );

    // Scan every document in the TBD — _malloc / _free / _printf surface
    // through libsystem_malloc / libsystem_c / (implicit libstdc), which
    // ship as their own --- !tapi-tbd documents inside libSystem.tbd.
    let mut found = std::collections::HashSet::<&str>::new();
    for doc in &docs {
        let sub = DylibFile::from_tbd(&path, doc, &target);
        for entry in sub.exports.entries().unwrap() {
            match entry.name.as_str() {
                "_malloc" => {
                    found.insert("_malloc");
                }
                "_free" => {
                    found.insert("_free");
                }
                "_printf" => {
                    found.insert("_printf");
                }
                _ => {}
            }
        }
    }
    assert!(
        found.contains("_malloc"),
        "_malloc not found anywhere in libSystem's TBD re-export chain"
    );
    assert!(
        found.contains("_free"),
        "_free not found anywhere in libSystem's TBD re-export chain"
    );

    // libSystem re-exports most actual libc symbols (malloc, free, etc.) from
    // sub-dylibs. They come from the `reexported-libraries`, not from
    // libSystem's own exports. Confirm we captured the chain.
    assert!(
        !dy.dependencies.is_empty(),
        "libSystem.tbd has no reexported-libraries"
    );
    assert!(dy
        .dependencies
        .iter()
        .all(|d| d.kind == DylibLoadKind::Reexport));

    // Common expected sub-dylibs we re-export — matches what `otool -L
    // libSystem.B.dylib` shows on a real macOS.
    let install_names: Vec<&str> = dy
        .dependencies
        .iter()
        .map(|d| d.install_name.as_str())
        .collect();
    for sub in [
        "/usr/lib/system/libsystem_c.dylib",
        "/usr/lib/system/libsystem_kernel.dylib",
    ] {
        assert!(
            install_names.contains(&sub),
            "expected {sub} in libSystem's reexported-libraries; got {install_names:?}"
        );
    }

    // Ordinals are strictly monotonic and 1-based.
    for (i, d) in dy.dependencies.iter().enumerate() {
        assert_eq!(d.ordinal as usize, i + 1);
    }
}
