use std::collections::HashMap;

use crate::resolve::{DylibId, SymbolId};

pub const STUB_SIZE: u32 = 12;
pub const LAZY_POINTER_SIZE: u32 = 8;
pub const STUB_HELPER_HEADER_SIZE: u32 = 24;
pub const STUB_HELPER_ENTRY_SIZE: u32 = 12;
pub const DYLD_PRIVATE_SIZE: u32 = 8;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StubsSection {
    pub entries: Vec<StubEntry>,
    pub index: HashMap<SymbolId, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StubEntry {
    pub symbol: SymbolId,
    pub dylib: DylibId,
    pub weak_import: bool,
}

impl StubsSection {
    pub fn intern(&mut self, symbol: SymbolId, dylib: DylibId, weak_import: bool) -> usize {
        if let Some(&idx) = self.index.get(&symbol) {
            return idx;
        }
        let idx = self.entries.len();
        self.entries.push(StubEntry {
            symbol,
            dylib,
            weak_import,
        });
        self.index.insert(symbol, idx);
        idx
    }

    pub fn get(&self, symbol: SymbolId) -> Option<(usize, &StubEntry)> {
        let idx = *self.index.get(&symbol)?;
        Some((idx, &self.entries[idx]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LazyPointerSection {
    pub entries: Vec<LazyPointerEntry>,
    pub index: HashMap<SymbolId, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LazyPointerEntry {
    pub symbol: SymbolId,
    pub dylib: DylibId,
    pub weak_import: bool,
}

impl LazyPointerSection {
    pub fn intern(&mut self, symbol: SymbolId, dylib: DylibId, weak_import: bool) -> usize {
        if let Some(&idx) = self.index.get(&symbol) {
            return idx;
        }
        let idx = self.entries.len();
        self.entries.push(LazyPointerEntry {
            symbol,
            dylib,
            weak_import,
        });
        self.index.insert(symbol, idx);
        idx
    }

    pub fn get(&self, symbol: SymbolId) -> Option<(usize, &LazyPointerEntry)> {
        let idx = *self.index.get(&symbol)?;
        Some((idx, &self.entries[idx]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stubs_and_lazy_pointers_share_symbol_dedup() {
        let mut stubs = StubsSection::default();
        let mut lazy = LazyPointerSection::default();

        let a = stubs.intern(SymbolId(3), DylibId(1), false);
        let b = stubs.intern(SymbolId(3), DylibId(1), true);
        let c = lazy.intern(SymbolId(3), DylibId(1), false);
        let d = lazy.intern(SymbolId(4), DylibId(2), true);

        assert_eq!(a, 0);
        assert_eq!(b, 0);
        assert_eq!(c, 0);
        assert_eq!(d, 1);
        assert_eq!(stubs.entries.len(), 1);
        assert_eq!(lazy.entries.len(), 2);
    }
}
