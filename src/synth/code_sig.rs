use std::{ffi::c_void, thread};

use crate::layout::Layout;
use crate::section::is_executable;
use crate::LinkOptions;

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CS_ADHOC: u32 = 0x0000_0002;
const CS_LINKER_SIGNED: u32 = 0x0002_0000;
const CS_HASHTYPE_SHA256: u8 = 2;
const CS_SHA256_LEN: u8 = 32;
const CS_SUPPORTSEXECSEG: u32 = 0x0002_0400;
const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;
const PAGE_SIZE_LOG2: u8 = 12;
const PAGE_SIZE: usize = 1 << PAGE_SIZE_LOG2;
const SUPERBLOB_HEADER_SIZE: usize = 20;
const CODEDIRECTORY_HEADER_SIZE: usize = 88;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignaturePlan {
    pub dataoff: u32,
    pub datasize: u32,
    code_limit: u32,
    identifier: String,
    exec_seg_base: u64,
    exec_seg_limit: u64,
    exec_seg_flags: u64,
}

impl CodeSignaturePlan {
    pub fn new(
        layout: &Layout,
        opts: &LinkOptions,
        code_limit: u64,
        executable: bool,
    ) -> Result<Self, &'static str> {
        let code_limit = u32::try_from(code_limit)
            .map_err(|_| "code-signature offset exceeds 32-bit Mach-O field width")?;
        let identifier = output_identifier(opts);
        let (exec_seg_base, exec_seg_limit, exec_seg_flags) = exec_segment_info(layout, executable);
        let blob_len = blob_len(code_limit as usize, &identifier);
        Ok(Self {
            dataoff: code_limit,
            datasize: u32::try_from(blob_len)
                .map_err(|_| "code-signature blob exceeds 32-bit Mach-O field width")?,
            code_limit,
            identifier,
            exec_seg_base,
            exec_seg_limit,
            exec_seg_flags,
        })
    }

    pub fn build(&self, signed_prefix: &[u8]) -> Vec<u8> {
        self.build_with_jobs(signed_prefix, 1)
    }

    pub fn build_with_jobs(&self, signed_prefix: &[u8], parallel_jobs: usize) -> Vec<u8> {
        debug_assert_eq!(signed_prefix.len(), self.code_limit as usize);

        let code_slots = code_slots(self.code_limit as usize);
        let ident_len = self.identifier.len() + 1;
        let hash_offset = CODEDIRECTORY_HEADER_SIZE + ident_len;
        let cd_len = hash_offset + code_slots * CS_SHA256_LEN as usize;
        let superblob_len = SUPERBLOB_HEADER_SIZE + cd_len;
        let padded_len = align_up(superblob_len as u64, 8) as usize;

        let mut out = Vec::with_capacity(padded_len);
        push_be_u32(&mut out, CSMAGIC_EMBEDDED_SIGNATURE);
        push_be_u32(&mut out, superblob_len as u32);
        push_be_u32(&mut out, 1);
        push_be_u32(&mut out, CSSLOT_CODEDIRECTORY);
        push_be_u32(&mut out, SUPERBLOB_HEADER_SIZE as u32);

        push_be_u32(&mut out, CSMAGIC_CODEDIRECTORY);
        push_be_u32(&mut out, cd_len as u32);
        push_be_u32(&mut out, CS_SUPPORTSEXECSEG);
        push_be_u32(&mut out, CS_ADHOC | CS_LINKER_SIGNED);
        push_be_u32(&mut out, hash_offset as u32);
        push_be_u32(&mut out, CODEDIRECTORY_HEADER_SIZE as u32);
        push_be_u32(&mut out, 0);
        push_be_u32(&mut out, code_slots as u32);
        push_be_u32(&mut out, self.code_limit);
        out.push(CS_SHA256_LEN);
        out.push(CS_HASHTYPE_SHA256);
        out.push(0);
        out.push(PAGE_SIZE_LOG2);
        push_be_u32(&mut out, 0);
        push_be_u32(&mut out, 0);
        push_be_u32(&mut out, 0);
        push_be_u32(&mut out, 0);
        push_be_u64(&mut out, 0);
        push_be_u64(&mut out, self.exec_seg_base);
        push_be_u64(&mut out, self.exec_seg_limit);
        push_be_u64(&mut out, self.exec_seg_flags);

        out.extend_from_slice(self.identifier.as_bytes());
        out.push(0);
        for hash in page_hashes(signed_prefix, parallel_jobs) {
            out.extend_from_slice(&hash);
        }
        out.resize(padded_len, 0);
        out
    }
}

fn output_identifier(opts: &LinkOptions) -> String {
    opts.output
        .as_ref()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "a.out".to_string())
}

fn exec_segment_info(layout: &Layout, executable: bool) -> (u64, u64, u64) {
    let mut min_off: Option<u64> = None;
    let mut max_end = 0u64;
    for section in &layout.sections {
        if !is_executable(section.kind) || section.is_zerofill() {
            continue;
        }
        min_off = Some(min_off.map_or(section.file_off, |min_off: u64| {
            min_off.min(section.file_off)
        }));
        max_end = max_end.max(section.file_off + section.size);
    }
    let exec_seg_limit = min_off.map_or(0, |min_off| max_end.saturating_sub(min_off));
    (
        0,
        exec_seg_limit,
        if executable && exec_seg_limit != 0 {
            CS_EXECSEG_MAIN_BINARY
        } else {
            0
        },
    )
}

fn blob_len(code_limit: usize, identifier: &str) -> usize {
    let cd_len = CODEDIRECTORY_HEADER_SIZE
        + identifier.len()
        + 1
        + code_slots(code_limit) * CS_SHA256_LEN as usize;
    align_up((SUPERBLOB_HEADER_SIZE + cd_len) as u64, 8) as usize
}

fn code_slots(code_limit: usize) -> usize {
    if code_limit == 0 {
        0
    } else {
        code_limit.div_ceil(PAGE_SIZE)
    }
}

fn page_hashes(data: &[u8], parallel_jobs: usize) -> Vec<[u8; 32]> {
    let page_count = code_slots(data.len());
    if page_count == 0 {
        return Vec::new();
    }
    let parallel_jobs = parallel_jobs.max(1).min(page_count);
    if parallel_jobs == 1 || page_count < 2 {
        return data.chunks(PAGE_SIZE).map(sha256).collect();
    }

    let chunk_pages = page_count.div_ceil(parallel_jobs);
    let chunk_bytes = PAGE_SIZE * chunk_pages;
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for chunk in data.chunks(chunk_bytes) {
            handles
                .push(scope.spawn(move || chunk.chunks(PAGE_SIZE).map(sha256).collect::<Vec<_>>()));
        }

        let mut hashes = Vec::with_capacity(page_count);
        for handle in handles {
            hashes.extend(handle.join().expect("code-signature hash worker panicked"));
        }
        hashes
    })
}

fn push_be_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_be_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    let mask = align - 1;
    (value + mask) & !mask
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn CC_SHA256(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;
}

fn sha256(data: &[u8]) -> [u8; 32] {
    #[cfg(target_os = "macos")]
    {
        let mut out = [0u8; 32];
        // afs-ld is macOS-only; libSystem's CommonCrypto SHA-256 is the same
        // platform primitive used by code-signing tools and is materially
        // faster than the portable fallback for thousands of 4 KiB pages.
        unsafe {
            CC_SHA256(
                data.as_ptr().cast::<c_void>(),
                data.len() as u32,
                out.as_mut_ptr(),
            );
        }
        out
    }

    #[cfg(not(target_os = "macos"))]
    {
        sha256_portable(data)
    }
}

#[cfg(not(target_os = "macos"))]
fn sha256_portable(data: &[u8]) -> [u8; 32] {
    const INIT: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut state = INIT;
    let mut block = [0u8; 128];
    let full_blocks = data.len() / 64;
    for idx in 0..full_blocks {
        compress(
            &mut state,
            (&data[idx * 64..idx * 64 + 64]).try_into().unwrap(),
            &K,
        );
    }

    let rem = &data[full_blocks * 64..];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] = 0x80;
    let bit_len = (data.len() as u64) * 8;
    if rem.len() >= 56 {
        block[120..128].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut state, (&block[..64]).try_into().unwrap(), &K);
        compress(&mut state, (&block[64..128]).try_into().unwrap(), &K);
    } else {
        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut state, (&block[..64]).try_into().unwrap(), &K);
    }

    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(not(target_os = "macos"))]
fn compress(state: &mut [u32; 8], block: &[u8; 64], k: &[u32; 64]) {
    let mut w = [0u32; 64];
    for (idx, word) in w.iter_mut().take(16).enumerate() {
        let base = idx * 4;
        *word = u32::from_be_bytes([
            block[base],
            block[base + 1],
            block[base + 2],
            block[base + 3],
        ]);
    }
    for idx in 16..64 {
        let s0 = w[idx - 15].rotate_right(7) ^ w[idx - 15].rotate_right(18) ^ (w[idx - 15] >> 3);
        let s1 = w[idx - 2].rotate_right(17) ^ w[idx - 2].rotate_right(19) ^ (w[idx - 2] >> 10);
        w[idx] = w[idx - 16]
            .wrapping_add(s0)
            .wrapping_add(w[idx - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for idx in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k[idx])
            .wrapping_add(w[idx]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use crate::layout::Layout;
    use crate::LinkOptions;

    use super::*;

    fn read_be_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn code_signature_matches_apple_minimal_shape() {
        let opts = LinkOptions {
            output: Some("apple".into()),
            ..LinkOptions::default()
        };
        let plan = CodeSignaturePlan::new(
            &Layout::empty(crate::OutputKind::Executable, 0),
            &opts,
            16_512,
            true,
        )
        .unwrap();
        let blob = plan.build(&vec![0; 16_512]);

        assert_eq!(plan.dataoff, 16_512);
        assert_eq!(blob.len(), 280);
        assert_eq!(read_be_u32(&blob, 0), CSMAGIC_EMBEDDED_SIGNATURE);
        assert_eq!(read_be_u32(&blob, 4), 274);
        assert_eq!(read_be_u32(&blob, 12), CSSLOT_CODEDIRECTORY);
        assert_eq!(read_be_u32(&blob, 20), CSMAGIC_CODEDIRECTORY);
        assert_eq!(read_be_u32(&blob, 24), 254);
        assert_eq!(read_be_u32(&blob, 28), CS_SUPPORTSEXECSEG);
        assert_eq!(read_be_u32(&blob, 32), CS_ADHOC | CS_LINKER_SIGNED);
        assert_eq!(read_be_u32(&blob, 36), 94);
        assert_eq!(read_be_u32(&blob, 40), 88);
        assert_eq!(read_be_u32(&blob, 48), 5);
        assert_eq!(read_be_u32(&blob, 52), 16_512);
        assert_eq!(&blob[108..114], b"apple\0");
    }

    #[test]
    fn parallel_page_hashes_preserve_serial_order() {
        let mut bytes = Vec::with_capacity(PAGE_SIZE * 9 + 123);
        for index in 0..PAGE_SIZE * 9 + 123 {
            bytes.push((index.wrapping_mul(37).wrapping_add(19) & 0xff) as u8);
        }

        let serial = page_hashes(&bytes, 1);
        let parallel = page_hashes(&bytes, 4);
        assert_eq!(parallel, serial);
        assert_eq!(parallel.len(), 10);
    }

    #[test]
    fn parallel_code_signature_matches_single_worker() {
        let opts = LinkOptions {
            output: Some("parallel".into()),
            ..LinkOptions::default()
        };
        let code_limit = PAGE_SIZE * 11 + 777;
        let plan = CodeSignaturePlan::new(
            &Layout::empty(crate::OutputKind::Executable, 0),
            &opts,
            code_limit as u64,
            true,
        )
        .unwrap();
        let mut signed_prefix = Vec::with_capacity(code_limit);
        for index in 0..code_limit {
            signed_prefix.push((index.wrapping_mul(13).wrapping_add(index / 7) & 0xff) as u8);
        }

        assert_eq!(
            plan.build_with_jobs(&signed_prefix, 8),
            plan.build_with_jobs(&signed_prefix, 1)
        );
    }
}
