//! Sprint 4 real-world gate: parse `libarmfortas_rt.a` (if the parent
//! workspace has built it), walk its BSD symbol index, fetch a member, and
//! confirm the fetched member parses as an `ObjectFile` that defines the
//! expected symbol.
//!
//! If the runtime archive isn't present (a clean clone that has never been
//! built) the test is skipped with a clear message rather than failing.

use std::path::{Path, PathBuf};

use afs_ld::archive::{Archive, FetchError, SymbolIndex};
use afs_ld::symbol::SymKind;

fn find_runtime_archive() -> Option<PathBuf> {
    // afs-ld crate manifest sits at .../armfortas/afs-ld/; target/ lives at
    // .../armfortas/target/.
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for profile in ["debug", "release"] {
        let candidate = workspace.join("target").join(profile).join("libarmfortas_rt.a");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[test]
fn libarmfortas_rt_archive_walks_cleanly() {
    let Some(path) = find_runtime_archive() else {
        eprintln!("skipping: libarmfortas_rt.a not built; run `cargo build -p armfortas-rt` first");
        return;
    };

    let bytes = std::fs::read(&path).expect("read runtime archive");
    let ar = Archive::open(&path, &bytes).expect("parse runtime archive");

    // Archive should have members and a symbol index.
    let members: Vec<_> = ar.object_members().collect();
    assert!(!members.is_empty(), "runtime archive has no object members");

    let idx = ar.symbol_index().expect("runtime archive has a BSD symbol index");
    assert!(!idx.is_empty(), "runtime archive symbol index is empty");

    // Pick a symbol we're confident the runtime exports. `_afs_program_init`
    // is the entry-point the driver-synthesized _main calls.
    let target = "_afs_program_init";
    let Some(mem) = ar.first_member_defining(target) else {
        panic_with_index("runtime archive missing _afs_program_init", idx);
    };
    assert!(!mem.name.is_empty());

    // Fetch and parse that member. The member must expose the symbol as a
    // defined, external, section symbol.
    let obj = match ar.fetch_object_defining(target) {
        Some(Ok(o)) => o,
        Some(Err(FetchError::Read(e))) => panic!("parse error on {}: {e}", mem.name),
        Some(Err(FetchError::Io(e))) => panic!("i/o error on {}: {e}", mem.name),
        None => panic!("fetch returned None for {}", target),
    };

    // Find the symbol we asked for and confirm its shape.
    let defining = obj
        .symbols
        .iter()
        .find(|s| {
            obj.symbol_name(s)
                .map(|n| n == target)
                .unwrap_or(false)
                && s.kind() == SymKind::Sect
                && s.is_ext()
        })
        .unwrap_or_else(|| {
            let names: Vec<_> = obj
                .symbols
                .iter()
                .filter_map(|s| obj.symbol_name(s).ok().map(|n| n.to_string()))
                .collect();
            panic!(
                "member {:?} does not define {} as a SECT+EXT symbol (saw: {:?})",
                mem.name, target, names
            )
        });
    let _ = defining;
}

fn panic_with_index(msg: &str, idx: &SymbolIndex) -> ! {
    let preview: Vec<&str> = idx.entries.iter().take(10).map(|e| e.name.as_str()).collect();
    panic!("{msg}\nfirst 10 symbols: {preview:?}");
}
