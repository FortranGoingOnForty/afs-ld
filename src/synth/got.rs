use std::collections::HashMap;

use crate::resolve::SymbolId;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GotSection {
    pub entries: Vec<GotEntry>,
    pub index: HashMap<SymbolId, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GotEntry {
    pub symbol: SymbolId,
    pub weak_import: bool,
}

impl GotSection {
    pub fn intern(&mut self, symbol: SymbolId, weak_import: bool) -> usize {
        if let Some(&idx) = self.index.get(&symbol) {
            return idx;
        }
        let idx = self.entries.len();
        self.entries.push(GotEntry {
            symbol,
            weak_import,
        });
        self.index.insert(symbol, idx);
        idx
    }

    pub fn get(&self, symbol: SymbolId) -> Option<(usize, &GotEntry)> {
        let idx = *self.index.get(&symbol)?;
        Some((idx, &self.entries[idx]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_deduplicates_symbol_slots() {
        let mut got = GotSection::default();
        let a = got.intern(SymbolId(7), false);
        let b = got.intern(SymbolId(7), true);
        let c = got.intern(SymbolId(9), true);
        assert_eq!(a, 0);
        assert_eq!(b, 0);
        assert_eq!(c, 1);
        assert_eq!(got.entries.len(), 2);
        assert!(!got.entries[0].weak_import);
        assert!(got.entries[1].weak_import);
    }
}
