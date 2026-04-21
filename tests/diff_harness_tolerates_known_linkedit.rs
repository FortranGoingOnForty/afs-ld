//! Tolerated-diff proof points for the parity harness.

mod common;

use common::harness::diff_macho;

const MH_MAGIC_64: u32 = 0xFEEDFACF;
const CPU_TYPE_ARM64: u32 = 0x0100_000C;
const MH_EXECUTE: u32 = 2;
const LC_ID_DYLIB: u32 = 0x0D;
const LC_UUID: u32 = 0x1B;
const LC_CODE_SIGNATURE: u32 = 0x1D;

#[test]
fn differing_uuid_bytes_are_tolerated() {
    let ours = synth_uuid_image([0x11; 16]);
    let theirs = synth_uuid_image([0x22; 16]);
    let report = diff_macho(&ours, &theirs);
    assert!(
        report.is_clean(),
        "UUID-only diff should be tolerated: {report:#?}"
    );
    assert_eq!(report.tolerated.len(), 1);
}

#[test]
fn differing_code_signature_blob_bytes_are_tolerated() {
    let ours = synth_code_signature_image([0xAA; 8]);
    let theirs = synth_code_signature_image([0xBB; 8]);
    let report = diff_macho(&ours, &theirs);
    assert!(
        report.is_clean(),
        "code-signature-only diff should be tolerated: {report:#?}"
    );
    assert_eq!(report.tolerated.len(), 1);
}

#[test]
fn differing_dylib_timestamps_are_tolerated() {
    let ours = synth_dylib_image(2);
    let theirs = synth_dylib_image(7);
    let report = diff_macho(&ours, &theirs);
    assert!(
        report.is_clean(),
        "dylib timestamp-only diff should be tolerated: {report:#?}"
    );
    assert_eq!(report.tolerated.len(), 1);
}

fn synth_uuid_image(uuid: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    push_header(&mut out, 1, 24);
    out.extend_from_slice(&LC_UUID.to_le_bytes());
    out.extend_from_slice(&24u32.to_le_bytes());
    out.extend_from_slice(&uuid);
    out
}

fn synth_code_signature_image(blob: [u8; 8]) -> Vec<u8> {
    let mut out = Vec::new();
    let dataoff = 0x40u32;
    let datasize = blob.len() as u32;
    push_header(&mut out, 1, 16);
    out.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&dataoff.to_le_bytes());
    out.extend_from_slice(&datasize.to_le_bytes());
    out.resize(dataoff as usize, 0);
    out.extend_from_slice(&blob);
    out
}

fn synth_dylib_image(timestamp: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let cmdsize = 32u32;
    push_header(&mut out, 1, cmdsize);
    out.extend_from_slice(&LC_ID_DYLIB.to_le_bytes());
    out.extend_from_slice(&cmdsize.to_le_bytes());
    out.extend_from_slice(&24u32.to_le_bytes());
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(b"x\0\0\0\0\0\0\0");
    out
}

fn push_header(out: &mut Vec<u8>, ncmds: u32, sizeofcmds: u32) {
    out.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    out.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&MH_EXECUTE.to_le_bytes());
    out.extend_from_slice(&ncmds.to_le_bytes());
    out.extend_from_slice(&sizeofcmds.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
}
