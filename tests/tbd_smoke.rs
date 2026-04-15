//! Sanity-check the YAML parser against the real libSystem.tbd from the
//! installed SDK. Runs only when the SDK is available and the file
//! parses to more than one document (libSystem re-exports ~40 sub-dylibs
//! in this file).

use afs_ld::macho::tbd_yaml::parse_documents;

#[test]
fn libsystem_tbd_parses_to_many_documents() {
    let Some(sdk) = sdk_path() else {
        eprintln!("skipping: SDK path unavailable");
        return;
    };
    let tbd_path = format!("{sdk}/usr/lib/libSystem.tbd");
    let Ok(bytes) = std::fs::read_to_string(&tbd_path) else {
        eprintln!("skipping: no libSystem.tbd at {tbd_path}");
        return;
    };
    let docs = parse_documents(&bytes).unwrap_or_else(|e| {
        panic!("libSystem.tbd failed to parse: {e}");
    });
    assert!(docs.len() >= 2, "expected >=2 documents, got {}", docs.len());
    // Every doc should carry the !tapi-tbd tag.
    for (i, d) in docs.iter().enumerate() {
        assert_eq!(d.tag.as_deref(), Some("!tapi-tbd"), "doc[{i}] tag");
        assert!(
            d.root.get("install-name").is_some(),
            "doc[{i}] missing install-name"
        );
    }
}

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
