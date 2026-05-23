# Sprint 30 Diagnostic Audit

Date: 2026-05-23

## Scope

Sprint 30 covers afs-ld diagnostic and polish surfaces:

- binary-input caret diagnostics
- relocation-error context
- did-you-mean hints
- color behavior
- verbose and trace modes
- help/version shape
- deterministic stderr
- exit-code conventions
- regression coverage against low-quality diagnostics

## Closeout Findings

### Binary-Input Diagnostics

Status: implemented.

Evidence:

- `src/diag.rs` emits path, byte offset, hex line, and caret span.
- `tests/cli_diagnostics.rs::malformed_object_diagnostic_matches_snapshot`
  locks the user-facing stderr.
- `tests/snapshots/malformed_input.stderr` is the golden output.

### Relocation Context

Status: implemented for the fallback path promised by Sprint 30.

Evidence:

- `src/reloc/arm64.rs::enrich_reloc_error` maps relocation failures back to
  the owning atom symbol and input-section offset.
- `src/lib.rs` enriches relocation failures before converting them to
  user-facing `LinkError`.
- `reloc::arm64::tests::enrich_reloc_error_reports_atom_symbol_context`
  verifies the fallback context.

Decision:

- True originating `.s` line backmapping is deferred until afs-as emits debug
  line information. The Sprint 30 fallback requirement is covered by atom
  symbol plus input file/offset.

### Did-You-Mean

Status: implemented.

Evidence:

- Undefined-symbol, bad-flag, missing-library, missing-framework, and
  mistyped-architecture hints are covered in `tests/cli_diagnostics.rs` and
  `tests/resolve_integration.rs`.
- Undefined-symbol suggestions now use the documented 10-result cap.
- Golden snapshots cover bad flag, missing library, and undefined symbol.

### Color

Status: implemented.

Evidence:

- `--color=always`, `--color=never`, and `NO_COLOR` are tested.
- `tests/cli_diagnostics.rs::color_auto_colors_parse_errors_on_tty` uses the
  macOS `script` PTY harness to prove auto color turns on for a TTY stream.

### Verbose And Trace

Status: implemented.

Evidence:

- `-v` emits version, target, output mode, output path, entry, and active flag
  summary.
- `-t`, `-trace`, and `--trace` all enable input tracing.
- `-verbose_deprecation` emits explicit warnings for accepted compatibility
  flags that do not currently change linker behavior.

### Help And Version

Status: implemented.

Evidence:

- `tests/snapshots/help.txt` locks the help output.
- `tests/cli_diagnostics.rs::help_flag_prints_usage_and_exits_successfully`
  compares help byte-for-byte.
- A help-width check confirms no line exceeds 80 columns.
- `--version` includes version, purpose, target triple, and git commit.

### Deterministic Stderr

Status: implemented for the covered diagnostic categories.

Evidence:

- Golden stderr snapshots exist for bad flag, malformed input, missing
  library, undefined symbol, and duplicate symbol.
- `bad_flag_stderr_is_deterministic` verifies repeated parse failures produce
  identical stderr.
- Snapshot tests normalize only temp paths; no wall clock, pid, or thread id is
  emitted by the linker diagnostics.

### Exit Codes

Status: implemented for Sprint 30 categories.

Evidence:

- Success exits `0`.
- CLI misuse exits `2`.
- Link failures such as undefined/duplicate symbols and missing libraries exit
  `1`.
- Malformed input exits `65` (`EX_DATAERR`).
- Missing input exits `66` (`EX_NOINPUT`).

## Verification Commands

Focused commands run during closeout:

```text
cargo test -p afs-ld --lib args::tests::verbose_deprecation_flag_is_recorded
cargo test -p afs-ld --test cli_diagnostics verbose_deprecation_warns_for_deprecated_compatibility_flags
cargo test -p afs-ld --test cli_diagnostics help_flag_prints_usage_and_exits_successfully
cargo test -p afs-ld --test cli_diagnostics diagnostic_matches_snapshot
cargo test -p afs-ld --test cli_diagnostics undefined_warning_mode_links_and_warns_once
cargo test -p afs-ld --test cli_diagnostics color_auto_colors_parse_errors_on_tty
cargo test -p afs-ld --test cli_diagnostics bad_flag_stderr_is_deterministic
cargo check -p afs-ld
git -C afs-ld diff --check
```

## Result

Sprint 30 is closeout-ready from the diagnostic-contract perspective. The next
work should move to Sprint 31's final audit unless a new review finding lands
against one of the surfaces above.
