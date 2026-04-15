# Sprint 0: Scaffolding, References, Harness

## Prerequisites
None — this is where afs-ld begins. Assumes armfortas and afs-as already exist and compile.

## Current state to remediate

The `afs-ld/` directory currently sits inside armfortas's working tree as a plain subdirectory. `afs-ld/.gitignore` was accidentally committed to armfortas history (commit `85d5ba8 "init"`), tracking a file that will shortly belong to a separate repo. Before anything else in this sprint, afs-ld must be extracted into its own repo and wired back in as a Git submodule. The tracked `.gitignore` must be removed from armfortas's index (history can stay; removing a single file at HEAD is clean) so that afs-ld's contents live in the submodule and nowhere else.

## Goals
Extract afs-ld into its own repo, wire it back as a submodule, stand up the crate (CLAUDE.md, README, Cargo.toml, skeleton source), clone reference linkers, build the differential harness. End state: `cargo test -p afs-ld` runs from the parent workspace, at least one test passes meaningfully, and `git submodule status` lists afs-ld alongside afs-as.

## Deliverables

### 1. Submodule remediation (do first)

Goal: move from "afs-ld is a tracked subdirectory of armfortas" to "afs-ld is a submodule pointing at `git@github.com:FortranGoingOnForty/afs-ld.git`". Exact sequence:

1. **Preserve the current afs-ld contents**: copy `armfortas/afs-ld/` to a temp location (the `.docs/overview.md` and sprint files produced in planning are the primary content to preserve; `.fackr/` is scratch and can be dropped).
2. **Untrack from armfortas**: `git rm --cached afs-ld/.gitignore && git commit -m "remove accidentally-tracked afs-ld/.gitignore"`. Confirm `git ls-files afs-ld` returns empty.
3. **Delete the directory from armfortas's working tree** (submodule-add will recreate it): `rm -rf afs-ld/`.
4. **Create the external repo** `FortranGoingOnForty/afs-ld` on GitHub (empty, no README — submodule-add will seed it).
5. **Initialize locally and push**: in a scratch directory,
   ```
   git init afs-ld
   cd afs-ld
   <copy preserved contents back>
   git add -A
   git commit -m "init"
   git remote add origin git@github.com:FortranGoingOnForty/afs-ld.git
   git push -u origin trunk
   ```
6. **Add as submodule in armfortas**:
   ```
   cd <armfortas root>
   git submodule add git@github.com:FortranGoingOnForty/afs-ld.git afs-ld
   git commit -m "add afs-ld submodule"
   ```
   Confirm `.gitmodules` gained the stanza:
   ```
   [submodule "afs-ld"]
       path = afs-ld
       url = git@github.com:FortranGoingOnForty/afs-ld.git
   ```
7. **Verify** with `git submodule status` — afs-as and afs-ld both listed, each pinned to a commit hash.

Note: the old `git rm --cached` commit stays in armfortas history. Rewriting history to erase it is more destructive than it's worth for a single `.gitignore` file. The file at HEAD is gone; that is sufficient.

### 2. Crate wiring

- Root `Cargo.toml` adds `"afs-ld"` to `[workspace] members` alongside `afs-as`.
- `afs-ld/Cargo.toml`: binary + library, zero external dependencies, `edition = "2021"`. Mirror `afs-as/Cargo.toml` — same `keywords`, `categories`, `license = "GPL-3.0-only"`, adjusted `description` and `repository`.
- `afs-ld/src/lib.rs`: public re-exports of `Linker`, `LinkOptions`, `OutputKind` (types are stubs this sprint).
- `afs-ld/src/main.rs`: CLI that prints usage and exits 0 when run with no args; forwards real args to `Linker::run` (which errors with "not yet implemented" this sprint).

### 3. CLAUDE.md and README.md

- `afs-ld/CLAUDE.md`: mirror `afs-as/CLAUDE.md`, replacing assembler-isms with linker-isms. Non-negotiable rules: Rust std only, exhaustive matching, caret diagnostics, per-chunk commits, no co-authors, no sprint-number references in commits.
- `afs-ld/README.md`: one-page intro, supported CLI subset at current state (nothing yet — say so), build/test commands.
- `afs-ld/.gitignore`: `target/`, `.fackr/`, no `.docs/` since those files live in the repo. This one is intentionally tracked because it lives inside afs-ld's own repo now, not armfortas's.

### 4. Reference clones

Add to parent `.refs/` (gitignored):

- `.refs/ld64/` — `git clone --depth 1 https://github.com/apple-oss-distributions/ld64.git`. Apple's last publicly released ld64. Authoritative for Apple-parity edge cases.
- `.refs/mold/` — `git clone --depth 1 https://github.com/rui314/mold.git`. Performance reference and a second Rust-adjacent angle on Mach-O.

`.refs/llvm/lld/MachO/` already exists from armfortas Sprint 0 — primary architectural reference.

### 5. Differential harness

`afs-ld/tests/common/harness.rs`:

```rust
pub struct LinkCase {
    pub name: &'static str,
    pub inputs: Vec<PathBuf>,       // .o / .a / .tbd
    pub args: Vec<String>,          // -o, -e, -syslibroot, -l, ...
}

pub struct LinkOutputs {
    pub ours: Vec<u8>,              // afs-ld output
    pub theirs: Vec<u8>,            // system ld output
}

pub fn link_both(case: &LinkCase) -> LinkOutputs;
pub fn diff_macho(ours: &[u8], theirs: &[u8]) -> DiffReport;
```

`DiffReport` categorizes byte differences as `Tolerated` (UUID, timestamp, temp-path hashes) or `Critical` (anything else). Critical diffs fail the test.

Closeout note: the current Sprint 0 surface is intentionally synthetic. `diff_macho` exists and is tested, but `link_both` remains a placeholder until afs-ld can emit real linked output. That means the current harness validates diff categorization logic, not end-to-end linker parity yet.

### 6. Skeleton CLI and first failing test

- `afs-ld/src/args.rs`: hand-rolled argv parser stub that recognizes `-o`, `-e`, `-arch`, and positional inputs. Unknown flags error loudly with a hint.
- `afs-ld/tests/reader_empty.rs`: attempts to link `0 inputs → empty output`, expects the diagnostic `"afs-ld: error: no input files"`. Passes today by producing that exact string.
- `afs-ld/tests/diff_harness_sanity.rs`: exercises the diff surface against two identical synthetic byte slices and expects zero diffs. Passes.
- `afs-ld/tests/diff_harness_finds_critical.rs`: feeds the harness two synthetic binaries that differ in a non-tolerated byte range and asserts the harness reports `Critical`. Passes.

## Testing Strategy

- `cargo build -p afs-ld` compiles from a fresh clone of the parent with `git submodule update --init --recursive`.
- `cargo test -p afs-ld` runs harness-sanity, critical-detection, and empty-input tests.
- `cargo clippy -p afs-ld -- -D warnings` clean.
- Manual verification of submodule state:
  - `git ls-files | grep afs-ld` in armfortas prints only the `.gitmodules` entry (and nothing under `afs-ld/`).
  - `git submodule status` shows both afs-as and afs-ld with valid commit hashes.
  - `git submodule update --init --recursive` on a fresh armfortas clone populates afs-ld correctly.

## Definition of Done

- The accidentally-tracked `afs-ld/.gitignore` is removed from armfortas's index at HEAD.
- afs-ld exists as a standalone GitHub repo under `FortranGoingOnForty`.
- afs-ld is wired into armfortas as a Git submodule, visible in `.gitmodules` and `git submodule status`.
- `armfortas/Cargo.toml` lists `afs-ld` in `[workspace] members`.
- `afs-ld/CLAUDE.md`, `README.md`, `Cargo.toml`, `src/lib.rs`, `src/main.rs`, `src/args.rs` all committed in the new repo.
- `.refs/ld64/` and `.refs/mold/` cloned.
- Differential harness substrate runs, correctly reports zero diffs on identical byte slices, correctly reports critical diffs on intentionally-different byte slices.
- `cargo test --workspace` green.
