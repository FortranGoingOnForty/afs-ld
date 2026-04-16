//! Numeric constants mirrored from Apple's `<mach-o/loader.h>`, `<mach-o/nlist.h>`,
//! `<mach-o/reloc.h>`, and `<mach-o/arm64/reloc.h>`. Duplicated from afs-as
//! rather than cross-crate coupled so each submodule remains independent.
//!
//! Sprint 0 lands the baseline set the reader needs in Sprint 1; later sprints
//! extend this module as new load commands / section flags / relocation types
//! come into scope.

// Magic and file types
pub const MH_MAGIC_64: u32 = 0xFEEDFACF;
pub const CPU_TYPE_ARM64: u32 = 0x0100_000C;
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;

pub const MH_OBJECT: u32 = 1;
pub const MH_EXECUTE: u32 = 2;
pub const MH_DYLIB: u32 = 6;

// Mach header flags
pub const MH_NOUNDEFS: u32 = 0x1;
pub const MH_DYLDLINK: u32 = 0x4;
pub const MH_TWOLEVEL: u32 = 0x80;
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;
pub const MH_PIE: u32 = 0x0020_0000;
pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x0080_0000;

// Load command kinds (subset afs-as emits plus the writer will need)
pub const LC_REQ_DYLD: u32 = 0x8000_0000;

pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_SYMTAB: u32 = 0x02;
pub const LC_DYSYMTAB: u32 = 0x0B;
pub const LC_LOAD_DYLIB: u32 = 0x0C;
pub const LC_ID_DYLIB: u32 = 0x0D;
pub const LC_LOAD_DYLINKER: u32 = 0x0E;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_REEXPORT_DYLIB: u32 = 0x1F | LC_REQ_DYLD;
pub const LC_UUID: u32 = 0x1B;
pub const LC_RPATH: u32 = 0x1C | LC_REQ_DYLD;
pub const LC_CODE_SIGNATURE: u32 = 0x1D;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2A;
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;

// Segment flags
pub const SG_READ_ONLY: u32 = 0x10;

// Section type nibble (flags & 0xff)
pub const SECTION_TYPE_MASK: u32 = 0x0000_00ff;
pub const S_REGULAR: u32 = 0x0;
pub const S_ZEROFILL: u32 = 0x1;
pub const S_CSTRING_LITERALS: u32 = 0x2;
pub const S_4BYTE_LITERALS: u32 = 0x3;
pub const S_8BYTE_LITERALS: u32 = 0x4;
pub const S_LITERAL_POINTERS: u32 = 0x5;
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
pub const S_SYMBOL_STUBS: u32 = 0x8;
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xA;
pub const S_COALESCED: u32 = 0xB;
pub const S_GB_ZEROFILL: u32 = 0xC;
pub const S_INTERPOSING: u32 = 0xD;
pub const S_16BYTE_LITERALS: u32 = 0xE;
pub const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u32 = 0x14;
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x15;

// Section attribute bits (high byte of flags)
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
pub const S_ATTR_NO_TOC: u32 = 0x4000_0000;
pub const S_ATTR_STRIP_STATIC_SYMS: u32 = 0x2000_0000;
pub const S_ATTR_NO_DEAD_STRIP: u32 = 0x1000_0000;
pub const S_ATTR_LIVE_SUPPORT: u32 = 0x0800_0000;
pub const S_ATTR_SELF_MODIFYING_CODE: u32 = 0x0400_0000;
pub const S_ATTR_DEBUG: u32 = 0x0200_0000;
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
pub const S_ATTR_EXT_RELOC: u32 = 0x0000_0200;
pub const S_ATTR_LOC_RELOC: u32 = 0x0000_0100;

// data_in_code_entry kinds
pub const DICE_KIND_DATA: u16 = 1;
pub const DICE_KIND_JUMP_TABLE8: u16 = 2;
pub const DICE_KIND_JUMP_TABLE16: u16 = 3;
pub const DICE_KIND_JUMP_TABLE32: u16 = 4;
pub const DICE_KIND_ABS_JUMP_TABLE32: u16 = 5;

// nlist_64 n_type
pub const N_STAB: u8 = 0xe0;
pub const N_PEXT: u8 = 0x10;
pub const N_TYPE: u8 = 0x0e;
pub const N_EXT: u8 = 0x01;

pub const N_UNDF: u8 = 0x0;
pub const N_ABS: u8 = 0x2;
pub const N_SECT: u8 = 0xe;
pub const N_INDR: u8 = 0xa;
pub const NO_SECT: u8 = 0;

// nlist_64 n_desc bits
pub const REFERENCED_DYNAMICALLY: u16 = 0x0010;
pub const N_NO_DEAD_STRIP: u16 = 0x0020;
pub const N_WEAK_REF: u16 = 0x0040;
pub const N_WEAK_DEF: u16 = 0x0080;
/// Symbol is an alternate entry point into the atom defined by the
/// preceding symbol in the same section. Folded into that atom's
/// `alt_entries` during atomization.
pub const N_ALT_ENTRY: u16 = 0x0200;

// ARM64 relocation kinds
pub const ARM64_RELOC_UNSIGNED: u8 = 0;
pub const ARM64_RELOC_SUBTRACTOR: u8 = 1;
pub const ARM64_RELOC_BRANCH26: u8 = 2;
pub const ARM64_RELOC_PAGE21: u8 = 3;
pub const ARM64_RELOC_PAGEOFF12: u8 = 4;
pub const ARM64_RELOC_GOT_LOAD_PAGE21: u8 = 5;
pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12: u8 = 6;
pub const ARM64_RELOC_POINTER_TO_GOT: u8 = 7;
pub const ARM64_RELOC_TLVP_LOAD_PAGE21: u8 = 8;
pub const ARM64_RELOC_TLVP_LOAD_PAGEOFF12: u8 = 9;
pub const ARM64_RELOC_ADDEND: u8 = 10;

// Platforms for LC_BUILD_VERSION
pub const PLATFORM_MACOS: u32 = 1;
pub const PLATFORM_IOS: u32 = 2;

// Export trie terminal-node flags (<mach-o/loader.h>)
pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u64 = 0x00;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u64 = 0x02;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64 = 0x04;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

// Classic dyld bind opcodes / flags (<mach-o/loader.h>)
pub const REBASE_TYPE_POINTER: u8 = 1;

pub const REBASE_OPCODE_MASK: u8 = 0xF0;
pub const REBASE_IMMEDIATE_MASK: u8 = 0x0F;
pub const REBASE_OPCODE_DONE: u8 = 0x00;
pub const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
pub const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
pub const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
pub const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
pub const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
pub const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;

// Classic dyld bind opcodes / flags (<mach-o/loader.h>)
pub const BIND_TYPE_POINTER: u8 = 1;

pub const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u8 = 0x1;

pub const BIND_OPCODE_MASK: u8 = 0xF0;
pub const BIND_IMMEDIATE_MASK: u8 = 0x0F;
pub const BIND_OPCODE_DONE: u8 = 0x00;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
pub const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
pub const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
pub const BIND_OPCODE_DO_BIND: u8 = 0x90;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;
