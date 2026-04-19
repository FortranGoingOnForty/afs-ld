use std::collections::BTreeMap;

use crate::leb::{write_sleb, write_uleb};
use crate::macho::constants::{
    BIND_IMMEDIATE_MASK, BIND_OPCODE_ADD_ADDR_ULEB, BIND_OPCODE_DO_BIND,
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, BIND_OPCODE_SET_ADDEND_SLEB,
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM, BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM, BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, BIND_OPCODE_SET_TYPE_IMM,
    BIND_SYMBOL_FLAGS_WEAK_IMPORT, BIND_TYPE_POINTER, REBASE_IMMEDIATE_MASK,
    REBASE_OPCODE_DO_REBASE_IMM_TIMES, REBASE_OPCODE_DO_REBASE_ULEB_TIMES,
};
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

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindRecordSpec<'a> {
    pub segment_index: u8,
    pub segment_offset: u64,
    pub ordinal: u16,
    pub name: &'a str,
    pub weak_import: bool,
    pub addend: i64,
    pub terminate: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct BindState {
    ordinal: Option<u16>,
    weak_import: Option<bool>,
    addend: i64,
    segment_index: Option<u8>,
    next_segment_offset: Option<u64>,
    pointer_type_set: bool,
}

#[derive(Debug, Clone, Default)]
struct TrieNode {
    terminal: Option<ExportEntry>,
    children: BTreeMap<u8, TrieNode>,
}

impl TrieNode {
    fn insert(&mut self, name: &str, entry: ExportEntry) {
        let mut node = self;
        for byte in name.bytes() {
            node = node.children.entry(byte).or_default();
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
    for (&edge, child) in &node.children {
        let (label, child_id) = flatten_edge(edge, child, flat);
        children.push((label, child_id));
    }
    flat[id].children = children;
    id
}

fn flatten_edge(first: u8, child: &TrieNode, flat: &mut Vec<FlatTrieNode>) -> (String, usize) {
    let mut label = vec![first];
    let mut node = child;
    while node.terminal.is_none() && node.children.len() == 1 {
        let (&next, next_child) = node
            .children
            .iter()
            .next()
            .expect("single-child trie node should expose one edge");
        label.push(next);
        node = next_child;
    }
    let label = String::from_utf8(label).expect("export labels should stay UTF-8");
    let child_id = flatten_trie(node, flat);
    (label, child_id)
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
    stream
        .byte(u8::try_from(node.children.len()).expect("export trie node fanout should fit in u8"));
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

pub fn emit_rebase_run(out: &mut OpcodeStream, count: usize) {
    if count <= REBASE_IMMEDIATE_MASK as usize {
        out.byte(REBASE_OPCODE_DO_REBASE_IMM_TIMES | count as u8);
    } else {
        out.byte(REBASE_OPCODE_DO_REBASE_ULEB_TIMES);
        out.uleb(count as u64);
    }
}

pub fn emit_bind_records(specs: &[BindRecordSpec<'_>]) -> Vec<u8> {
    let mut out = OpcodeStream::new();
    let mut state = BindState::default();
    let mut current_symbol: Option<String> = None;

    let mut idx = 0usize;
    while idx < specs.len() {
        let spec = specs[idx];
        if state.ordinal != Some(spec.ordinal) {
            emit_bind_ordinal(&mut out, spec.ordinal);
            state.ordinal = Some(spec.ordinal);
        }

        if current_symbol.as_deref() != Some(spec.name)
            || state.weak_import != Some(spec.weak_import)
        {
            out.byte(
                BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | bind_symbol_flags(spec.weak_import),
            );
            out.string(spec.name);
            current_symbol = Some(spec.name.to_string());
            state.weak_import = Some(spec.weak_import);
        }

        if state.addend != spec.addend {
            out.byte(BIND_OPCODE_SET_ADDEND_SLEB);
            out.sleb(spec.addend);
            state.addend = spec.addend;
        }

        if !state.pointer_type_set {
            out.byte(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
            state.pointer_type_set = true;
        }

        match (state.segment_index, state.next_segment_offset) {
            (Some(segment_index), Some(next_segment_offset))
                if segment_index == spec.segment_index
                    && next_segment_offset == spec.segment_offset => {}
            (Some(segment_index), Some(next_segment_offset))
                if segment_index == spec.segment_index
                    && next_segment_offset < spec.segment_offset =>
            {
                out.byte(BIND_OPCODE_ADD_ADDR_ULEB);
                out.uleb(spec.segment_offset - next_segment_offset);
            }
            _ => {
                out.byte(
                    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
                        | (spec.segment_index & BIND_IMMEDIATE_MASK),
                );
                out.uleb(spec.segment_offset);
            }
        }

        let run_len = bind_run_len(specs, idx);
        if run_len > 1 {
            let stride = specs[idx + 1].segment_offset - spec.segment_offset;
            let skip = stride - 8;
            out.byte(BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB);
            out.uleb(run_len as u64);
            out.uleb(skip);
            state.next_segment_offset = Some(spec.segment_offset + (run_len as u64) * stride);
            idx += run_len;
        } else {
            out.byte(BIND_OPCODE_DO_BIND);
            state.next_segment_offset = Some(spec.segment_offset + 8);
            idx += 1;
        }
        state.segment_index = Some(spec.segment_index);
    }

    if specs.last().is_some_and(|spec| spec.terminate) {
        out.done();
    }

    out.into_vec()
}

pub fn emit_lazy_bind_record(
    out: &mut OpcodeStream,
    segment_index: u8,
    segment_offset: u64,
    ordinal: u16,
    name: &str,
    weak_import: bool,
) {
    // dyld's lazy-bind stream only accepts the classic lazy subset; pointer type is implicit.
    out.byte(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | (segment_index & BIND_IMMEDIATE_MASK));
    out.uleb(segment_offset);
    emit_bind_ordinal(out, ordinal);
    out.byte(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | bind_symbol_flags(weak_import));
    out.string(name);
    out.byte(BIND_OPCODE_DO_BIND);
    out.done();
}

fn emit_bind_ordinal(out: &mut OpcodeStream, ordinal: u16) {
    let signed = ordinal as i16;
    if (-8..=-1).contains(&signed) {
        out.byte(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | ((signed as u8) & BIND_IMMEDIATE_MASK));
    } else if ordinal <= BIND_IMMEDIATE_MASK as u16 {
        out.byte(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | ordinal as u8);
    } else {
        out.byte(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
        out.uleb(ordinal as u64);
    }
}

fn bind_symbol_flags(weak_import: bool) -> u8 {
    if weak_import {
        BIND_SYMBOL_FLAGS_WEAK_IMPORT
    } else {
        0
    }
}

fn bind_run_len(specs: &[BindRecordSpec<'_>], start: usize) -> usize {
    let Some(next) = specs.get(start + 1) else {
        return 1;
    };
    let first = specs[start];
    if first.segment_index != next.segment_index
        || first.ordinal != next.ordinal
        || first.name != next.name
        || first.weak_import != next.weak_import
        || first.addend != next.addend
    {
        return 1;
    }
    let stride = next.segment_offset.saturating_sub(first.segment_offset);
    if stride < 8 {
        return 1;
    }

    let mut len = 2usize;
    while let Some(spec) = specs.get(start + len) {
        let expected_offset = first.segment_offset + (len as u64) * stride;
        if spec.segment_index != first.segment_index
            || spec.ordinal != first.ordinal
            || spec.name != first.name
            || spec.weak_import != first.weak_import
            || spec.addend != first.addend
            || spec.segment_offset != expected_offset
        {
            break;
        }
        len += 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use crate::leb::{read_sleb, read_uleb};
    use crate::macho::constants::{
        BIND_OPCODE_DO_BIND, BIND_OPCODE_SET_ADDEND_SLEB, BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,
        BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
        BIND_OPCODE_SET_TYPE_IMM, BIND_TYPE_POINTER, EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
        EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL, EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION,
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

    #[test]
    fn export_trie_compresses_single_child_paths() {
        let trie = build_export_trie(&[ExportEntry {
            name: "_alpha".into(),
            flags: EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
            kind: ExportKind::Regular { address: 0x40 },
        }]);

        let child_count = *trie.get(1).expect("root child count should exist");
        assert_eq!(child_count, 1);
        let edge_end = trie[2..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|idx| idx + 2)
            .expect("root edge should be null-terminated");
        assert_eq!(std::str::from_utf8(&trie[2..edge_end]).unwrap(), "_alpha");
    }

    #[test]
    fn bind_encoder_reuses_state_for_adjacent_binds() {
        let stream = emit_bind_records(&[
            BindRecordSpec {
                segment_index: 2,
                segment_offset: 0,
                ordinal: 1,
                name: "_alpha",
                weak_import: false,
                addend: 0,
                terminate: false,
            },
            BindRecordSpec {
                segment_index: 2,
                segment_offset: 8,
                ordinal: 1,
                name: "_beta",
                weak_import: false,
                addend: 0,
                terminate: true,
            },
        ]);

        assert_eq!(
            stream,
            vec![
                BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
                BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
                b'_',
                b'a',
                b'l',
                b'p',
                b'h',
                b'a',
                0,
                BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
                BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2,
                0,
                BIND_OPCODE_DO_BIND,
                BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
                b'_',
                b'b',
                b'e',
                b't',
                b'a',
                0,
                BIND_OPCODE_DO_BIND,
                0,
            ]
        );
    }

    #[test]
    fn bind_encoder_emits_zero_addend_only_after_nonzero_state() {
        let stream = emit_bind_records(&[
            BindRecordSpec {
                segment_index: 2,
                segment_offset: 0,
                ordinal: 1,
                name: "_alpha",
                weak_import: false,
                addend: 4,
                terminate: false,
            },
            BindRecordSpec {
                segment_index: 2,
                segment_offset: 8,
                ordinal: 1,
                name: "_beta",
                weak_import: false,
                addend: 0,
                terminate: true,
            },
        ]);

        assert!(stream.contains(&BIND_OPCODE_SET_ADDEND_SLEB));
        let zero_reset = stream
            .windows(2)
            .any(|window| window == [BIND_OPCODE_SET_ADDEND_SLEB, 0]);
        assert!(zero_reset, "expected explicit addend reset back to zero");
    }

    #[test]
    fn bind_encoder_batches_constant_stride_runs() {
        let stream = emit_bind_records(&[
            BindRecordSpec {
                segment_index: 3,
                segment_offset: 0x98,
                ordinal: 1,
                name: "__tlv_bootstrap",
                weak_import: false,
                addend: 0,
                terminate: false,
            },
            BindRecordSpec {
                segment_index: 3,
                segment_offset: 0xb0,
                ordinal: 1,
                name: "__tlv_bootstrap",
                weak_import: false,
                addend: 0,
                terminate: false,
            },
            BindRecordSpec {
                segment_index: 3,
                segment_offset: 0xc8,
                ordinal: 1,
                name: "__tlv_bootstrap",
                weak_import: false,
                addend: 0,
                terminate: true,
            },
        ]);

        assert!(stream.contains(&BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB));
        let idx = stream
            .iter()
            .position(|byte| *byte == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB)
            .unwrap();
        assert_eq!(stream[idx + 1], 3);
        assert_eq!(stream[idx + 2], 0x10);
        assert_eq!(stream.last().copied(), Some(0));
    }
}
