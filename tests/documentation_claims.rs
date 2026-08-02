use std::fs;
use std::path::PathBuf;

fn repository_text(path: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn normalized_repository_text(path: &str) -> String {
    repository_text(path)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn capability_documents_do_not_deny_shipped_linkers() {
    let stale_claims = [
        (
            "README.md",
            "Sprint 0 — scaffolding only. Does not yet produce usable output.",
        ),
        (
            "AGENTS.md",
            "The project is Mach-O only, macOS only, arm64 only",
        ),
        ("AGENTS.md", "real `Linker::run` output production"),
        (
            "AGENTS.md",
            "argv -> args.rs -> Linker::run -> NotYetImplemented",
        ),
        (
            "src/lib.rs",
            "public surface is declared but every link attempt",
        ),
        (
            "src/elf.rs",
            "Rung 1 scope: freestanding executables from relocatable",
        ),
        ("CLAUDE.md", "`src/driver.rs`"),
        ("CLAUDE.md", "lands at Sprint 10+"),
    ];

    for (path, stale_claim) in stale_claims {
        let document = repository_text(path);
        assert!(
            !document.contains(stale_claim),
            "{path} still contains the stale capability claim `{stale_claim}`"
        );
    }
}

#[test]
fn capability_documents_name_both_shipped_pipelines() {
    for path in ["README.md", "AGENTS.md", "CLAUDE.md", "src/lib.rs"] {
        let document = repository_text(path);
        assert!(
            document.contains("ARM64 Mach-O"),
            "{path} must name the shipped ARM64 Mach-O pipeline"
        );
        assert!(
            document.contains("x86_64 ELF"),
            "{path} must name the shipped x86_64 ELF pipeline"
        );
    }

    let elf_module = repository_text("src/elf.rs");
    assert!(
        elf_module.contains("dynamically linked") && elf_module.contains("`ET_EXEC` images"),
        "src/elf.rs must describe its shipped dynamic executable writer"
    );
}

#[test]
fn chained_fixup_contract_is_explicitly_deferred() {
    let readme = normalized_repository_text("README.md");
    assert!(
        readme.contains("`-fixup_chains` is recognized for compatibility but rejected"),
        "README.md must state that chained-fixup output is not implemented"
    );
    assert!(
        !readme.contains(
            "Supports both classic `LC_DYLD_INFO` opcodes and modern `LC_DYLD_CHAINED_FIXUPS`"
        ),
        "README.md must not advertise both fixup encodings as shipped"
    );

    let help = normalized_repository_text("src/main.rs");
    assert!(
        help.contains("-fixup_chains Chained-fixup output is unsupported; errors"),
        "CLI help must label -fixup_chains as unsupported"
    );
    assert!(
        !help.contains("Select chained fixups vs classic dyld info"),
        "CLI help must not present -fixup_chains as a working output selector"
    );

    for path in ["CLAUDE.md", ".docs/overview.md"] {
        let document = normalized_repository_text(path);
        assert!(
            document.contains("does not emit `LC_DYLD_CHAINED_FIXUPS`"),
            "{path} must distinguish the planned chained-fixup format from shipped output"
        );
    }
}
