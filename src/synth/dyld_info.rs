use std::collections::BTreeMap;

use crate::leb::{write_sleb, write_uleb};
use crate::macho::exports::{ExportEntry, ExportKind};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpcodeStream {
    buf: Vec<u8>,
}

impl OpcodeStream {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn uleb(&mut self, v: u64) {
        write_uleb(v, &mut self.buf);
    }

    pub fn sleb(&mut self, v: i64) {
        write_sleb(v, &mut self.buf);
    }

    pub fn string(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
    }

    pub fn byte(&mut self, op_and_imm: u8) {
        self.buf.push(op_and_imm);
    }

    pub fn bytes(&mut self, raw: &[u8]) {
        self.buf.extend_from_slice(raw);
    }

    pub fn done(&mut self) {
        self.buf.push(0);
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

#[derive(Debug, Clone, Default)]
struct TrieNode {
    terminal: Option<ExportEntry>,
    children: BTreeMap<String, TrieNode>,
}

impl TrieNode {
    fn insert(&mut self, name: &str, entry: ExportEntry) {
        let mut node = self;
        for byte in name.bytes() {
            let edge = char::from(byte).to_string();
            node = node.children.entry(edge).or_default();
        }
        node.terminal = Some(entry);
    }
}

#[derive(Debug, Clone)]
struct FlatTrieNode {
    terminal: Option<ExportEntry>,
    children: Vec<(String, usize)>,
}

pub fn build_export_trie(entries: &[ExportEntry]) -> Vec<u8> {
    if entries.is_empty() {
        return Vec::new();
    }

    let mut sorted = entries.to_vec();
    sorted.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));

    let mut root = TrieNode::default();
    for entry in sorted {
        let name = entry.name.clone();
        root.insert(&name, entry);
    }

    let mut nodes = Vec::new();
    flatten_trie(&root, &mut nodes);

    let mut offsets = vec![0usize; nodes.len()];
    loop {
        let mut cursor = 0usize;
        let mut changed = false;
        for (idx, node) in nodes.iter().enumerate() {
            if offsets[idx] != cursor {
                offsets[idx] = cursor;
                changed = true;
            }
            cursor += trie_node_size(node, &offsets);
        }
        if !changed {
            break;
        }
    }

    let total_size = nodes
        .iter()
        .enumerate()
        .map(|(idx, node)| offsets[idx] + trie_node_size(node, &offsets))
        .max()
        .unwrap_or(0);
    let mut out = Vec::with_capacity(total_size);
    for node in &nodes {
        emit_trie_node(node, &offsets, &mut out);
    }
    out
}

fn flatten_trie(node: &TrieNode, flat: &mut Vec<FlatTrieNode>) -> usize {
    let id = flat.len();
    flat.push(FlatTrieNode {
        terminal: node.terminal.clone(),
        children: Vec::new(),
    });

    let mut children = Vec::with_capacity(node.children.len());
    for (edge, child) in &node.children {
        let child_id = flatten_trie(child, flat);
        children.push((edge.clone(), child_id));
    }
    flat[id].children = children;
    id
}

fn trie_node_size(node: &FlatTrieNode, offsets: &[usize]) -> usize {
    let terminal = terminal_payload(node.terminal.as_ref());
    let mut size = uleb_size(terminal.len() as u64) + terminal.len() + 1;
    for (edge, child) in &node.children {
        size += edge.len() + 1 + uleb_size(offsets[*child] as u64);
    }
    size
}

fn emit_trie_node(node: &FlatTrieNode, offsets: &[usize], out: &mut Vec<u8>) {
    let terminal = terminal_payload(node.terminal.as_ref());
    let mut stream = OpcodeStream::new();
    stream.uleb(terminal.len() as u64);
    stream.bytes(&terminal);
    stream.byte(u8::try_from(node.children.len()).expect("export trie node fanout should fit in u8"));
    for (edge, child) in &node.children {
        stream.string(edge);
        stream.uleb(offsets[*child] as u64);
    }
    out.extend_from_slice(&stream.into_vec());
}

fn terminal_payload(entry: Option<&ExportEntry>) -> Vec<u8> {
    let Some(entry) = entry else {
        return Vec::new();
    };

    let mut payload = OpcodeStream::new();
    payload.uleb(entry.flags);
    match &entry.kind {
        ExportKind::Regular { address }
        | ExportKind::ThreadLocal { address }
        | ExportKind::Absolute { address } => payload.uleb(*address),
        ExportKind::Reexport {
            ordinal,
            imported_name,
        } => {
            payload.uleb(*ordinal as u64);
            payload.string(imported_name);
        }
        ExportKind::StubAndResolver { stub, resolver } => {
            payload.uleb(*stub);
            payload.uleb(*resolver);
        }
    }
    payload.into_vec()
}

fn uleb_size(mut value: u64) -> usize {
    let mut size = 1usize;
    while value >= 0x80 {
        value >>= 7;
        size += 1;
    }
    size
}

#[cfg(test)]
mod tests {
    use crate::leb::{read_sleb, read_uleb};
    use crate::macho::constants::{
        EXPORT_SYMBOL_FLAGS_KIND_REGULAR, EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL,
        EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION,
    };
    use crate::macho::exports::Exports;

    use super::*;

    #[test]
    fn opcode_stream_round_trips_boundary_ulebs() {
        let mut stream = OpcodeStream::new();
        for value in [0u64, 127, 128, 16_383, 16_384, 0xdead_beef] {
            stream.uleb(value);
        }
        let bytes = stream.into_vec();
        let mut cursor = 0usize;
        for expected in [0u64, 127, 128, 16_383, 16_384, 0xdead_beef] {
            let (actual, used) = read_uleb(&bytes[cursor..]).unwrap();
            cursor += used;
            assert_eq!(actual, expected);
        }
        assert_eq!(cursor, bytes.len());
    }

    #[test]
    fn opcode_stream_round_trips_sleb_and_string() {
        let mut stream = OpcodeStream::new();
        stream.sleb(-12345);
        stream.string("_symbol");
        let bytes = stream.into_vec();
        let (value, used) = read_sleb(&bytes).unwrap();
        assert_eq!(value, -12345);
        assert_eq!(&bytes[used..], b"_symbol\0");
    }

    #[test]
    fn export_trie_round_trips_reader() {
        let entries = vec![
            ExportEntry {
                name: "_alpha".into(),
                flags: EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
                kind: ExportKind::Regular { address: 0x40 },
            },
            ExportEntry {
                name: "_beta".into(),
                flags: EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL | EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION,
                kind: ExportKind::ThreadLocal { address: 0x88 },
            },
        ];
        let trie = build_export_trie(&entries);
        let mut decoded = Exports::from_trie_bytes(&trie).entries().unwrap();
        decoded.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
        assert_eq!(decoded, entries);
    }

    #[test]
    fn export_trie_is_deterministic_across_input_order() {
        let forward = vec![
            ExportEntry {
                name: "_alpha".into(),
                flags: EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
                kind: ExportKind::Regular { address: 0x10 },
            },
            ExportEntry {
                name: "_omega".into(),
                flags: EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
                kind: ExportKind::Regular { address: 0x18 },
            },
        ];
        let reverse = forward.iter().rev().cloned().collect::<Vec<_>>();
        assert_eq!(build_export_trie(&forward), build_export_trie(&reverse));
    }
}
