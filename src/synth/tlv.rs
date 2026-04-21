use std::collections::HashMap;

use crate::resolve::SymbolId;

pub const THREAD_POINTER_SIZE: u32 = 8;
pub const THREAD_VARIABLE_DESCRIPTOR_SIZE: u32 = 24;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ThreadPointerSection {
    pub entries: Vec<ThreadPointerEntry>,
    pub index: HashMap<SymbolId, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadPointerEntry {
    pub symbol: SymbolId,
}

impl ThreadPointerSection {
    pub fn intern(&mut self, symbol: SymbolId) -> usize {
        if let Some(&idx) = self.index.get(&symbol) {
            return idx;
        }
        let idx = self.entries.len();
        self.entries.push(ThreadPointerEntry { symbol });
        self.index.insert(symbol, idx);
        idx
    }

    pub fn get(&self, symbol: SymbolId) -> Option<(usize, &ThreadPointerEntry)> {
        let idx = *self.index.get(&symbol)?;
        Some((idx, &self.entries[idx]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_deduplicates_thread_pointer_slots() {
        let mut ptrs = ThreadPointerSection::default();
        let a = ptrs.intern(SymbolId(5));
        let b = ptrs.intern(SymbolId(5));
        let c = ptrs.intern(SymbolId(9));
        assert_eq!(a, 0);
        assert_eq!(b, 0);
        assert_eq!(c, 1);
        assert_eq!(ptrs.entries.len(), 2);
    }
}
