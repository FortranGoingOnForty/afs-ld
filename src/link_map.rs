use std::fmt::Write as _;
use std::io;
use std::path::Path;

use crate::layout::{Layout, LayoutInput};
use crate::macho::writer::LinkEditPlan;
use crate::icf::FoldedSymbol;
use crate::why_live::DeadStrippedSymbol;
use crate::LinkOptions;

pub fn write_link_map(
    path: &Path,
    opts: &LinkOptions,
    layout: &Layout,
    layout_inputs: &[LayoutInput<'_>],
    linkedit: &LinkEditPlan,
    folded_symbols: &[FoldedSymbol],
    dead_stripped: &[DeadStrippedSymbol],
) -> io::Result<()> {
    let output_path = opts.output.as_deref().unwrap_or_else(|| Path::new("a.out"));
    let mut out = String::new();

    writeln!(&mut out, "# Path: {}", output_path.display()).unwrap();
    writeln!(&mut out, "# Arch: arm64").unwrap();
    writeln!(&mut out, "# Object files:").unwrap();
    writeln!(&mut out, "[  0] linker synthesized").unwrap();
    for (idx, input) in layout_inputs.iter().enumerate() {
        writeln!(&mut out, "[{:>3}] {}", idx + 1, input.object.path.display()).unwrap();
    }

    writeln!(&mut out, "\n# Sections:").unwrap();
    writeln!(
        &mut out,
        "# Address          Size         Segment   Section"
    )
    .unwrap();
    for section in &layout.sections {
        writeln!(
            &mut out,
            "{:#018x} {:#010x}   {:<8}  {}",
            section.addr, section.size, section.segment, section.name
        )
        .unwrap();
    }

    writeln!(&mut out, "\n# Symbols:").unwrap();
    writeln!(&mut out, "# Address          Size         File    Name").unwrap();
    let mut symbols = linkedit.map_symbols.clone();
    symbols.sort_by(|lhs, rhs| {
        lhs.addr
            .cmp(&rhs.addr)
            .then_with(|| lhs.name.cmp(&rhs.name))
    });
    for symbol in &symbols {
        let file = if symbol.file_index == 0 {
            "linker".to_string()
        } else {
            format!("[{:>3}]", symbol.file_index)
        };
        writeln!(
            &mut out,
            "{:#018x} {:#010x}   {:<7} {}",
            symbol.addr, symbol.size, file, symbol.name
        )
        .unwrap();
    }

    writeln!(&mut out, "\n# Folded symbols:").unwrap();
    for symbol in folded_symbols {
        let file = if symbol.file_index == 0 {
            "linker".to_string()
        } else {
            format!("[{:>3}]", symbol.file_index)
        };
        writeln!(
            &mut out,
            "{:<7} {} folded to {}",
            file, symbol.name, symbol.winner
        )
        .unwrap();
    }

    writeln!(&mut out, "\n# Dead stripped:").unwrap();
    for symbol in dead_stripped {
        let file = if symbol.file_index == 0 {
            "linker".to_string()
        } else {
            format!("[{:>3}]", symbol.file_index)
        };
        writeln!(&mut out, "{:<7} {}", file, symbol.name).unwrap();
    }

    std::fs::write(path, out)
}
