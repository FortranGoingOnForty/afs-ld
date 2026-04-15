//! Mach-O 64 reading and writing.
//!
//! Sprint 1 covers the reader's header and load-command surface; later sprints
//! layer section contents, symbols, relocations, dylibs, TBDs, and the writer
//! (both MH_EXECUTE and MH_DYLIB paths).

pub mod constants;
pub mod dylib;
pub mod exports;
pub mod reader;
pub mod tbd_yaml;
