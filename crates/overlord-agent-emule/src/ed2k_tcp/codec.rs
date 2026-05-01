use std::{io::Read, path::Path};

use anyhow::{Context, Result};
use flate2::{Compress, Compression, FlushCompress, FlushDecompress, Status, read::ZlibDecoder};
use overlord_kad_proto::Ed2kHash;

use crate::ed2k_transfer::{
    ED2K_PART_SIZE, Ed2kAichHashset, Ed2kResumeManifest, Ed2kTransferState,
};

use super::{
    ED2K_SOURCE_EXCHANGE2_VERSION, ED2K_UPLOAD_PACKET_FRAGMENT_LEN,
    ED2K_UPLOAD_PACKET_SPLIT_THRESHOLD, Ed2kFileIdentifier, Ed2kHashsetAnswer2,
    Ed2kHashsetRequestOptions, Ed2kMd4HashsetDecode, EncodedUploadPartPacket,
    MAX_PEER_DECOMPRESSED_PACKET_LEN, OP_ACCEPTUPLOADREQ, OP_AICHFILEHASHREQ, OP_ANSWERSOURCES,
    OP_ANSWERSOURCES2, OP_COMPRESSEDPART, OP_COMPRESSEDPART_I64, OP_EDONKEYPROT, OP_EMULEPROT,
    OP_FILEREQANSNOFIL, OP_FILESTATUS, OP_HASHSETANSWER, OP_HASHSETANSWER2, OP_HASHSETREQUEST,
    OP_HASHSETREQUEST2, OP_MULTIPACKET_EXT2, OP_MULTIPACKETANSWER_EXT2, OP_PACKEDPROT,
    OP_QUEUERANKING, OP_REQFILENAMEANSWER, OP_REQUESTFILENAME, OP_REQUESTPARTS,
    OP_REQUESTPARTS_I64, OP_REQUESTSOURCES, OP_REQUESTSOURCES2, OP_SENDINGPART, OP_SENDINGPART_I64,
    OP_SETREQFILEID, OP_STARTUPLOADREQ, PendingCompressedPart, TCP_PACKET_HEADER_LEN,
};

pub(super) fn decode_peer_payload(protocol: u8, payload: Vec<u8>) -> Result<(u8, Vec<u8>)> {
    if protocol != OP_PACKEDPROT {
        return Ok((protocol, payload));
    }

    let mut decoder = ZlibDecoder::new(payload.as_slice());
    let mut decoded = Vec::with_capacity(
        payload
            .len()
            .saturating_mul(10)
            .saturating_add(300)
            .min(MAX_PEER_DECOMPRESSED_PACKET_LEN),
    );
    let mut chunk = [0u8; 4096];
    loop {
        let read = decoder.read(&mut chunk).context("zlib inflate failed")?;
        if read == 0 {
            break;
        }
        if decoded.len().saturating_add(read) > MAX_PEER_DECOMPRESSED_PACKET_LEN {
            anyhow::bail!(
                "decompressed ED2K peer packet exceeded {} bytes",
                MAX_PEER_DECOMPRESSED_PACKET_LEN
            );
        }
        decoded.extend_from_slice(&chunk[..read]);
    }
    Ok((OP_EMULEPROT, decoded))
}

pub(super) fn decode_file_status_payload(
    payload: &[u8],
) -> Result<(overlord_kad_proto::Ed2kHash, u16)> {
    if payload.len() < 18 {
        anyhow::bail!("short OP_FILESTATUS payload size {}", payload.len());
    }
    let returned_hash = overlord_kad_proto::Ed2kHash::from_bytes(payload[..16].try_into()?);
    let part_count = u16::from_le_bytes([payload[16], payload[17]]);
    let expected_bitfield_len = usize::from(part_count).div_ceil(8);
    if payload.len() != 18 + expected_bitfield_len {
        anyhow::bail!(
            "invalid OP_FILESTATUS payload size {} for part_count {}",
            payload.len(),
            part_count
        );
    }
    Ok((returned_hash, part_count))
}

pub(super) fn encode_file_status_complete(file_hash: &overlord_kad_proto::Ed2kHash) -> Vec<u8> {
    let mut payload = Vec::with_capacity(18);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    encode_packet(OP_EDONKEYPROT, OP_FILESTATUS, &payload)
}

pub(super) fn encode_packet(protocol: u8, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(TCP_PACKET_HEADER_LEN + payload.len());
    bytes.push(protocol);
    bytes.extend_from_slice(
        &(u32::try_from(payload.len() + 1).expect("payload too large")).to_le_bytes(),
    );
    bytes.push(opcode);
    bytes.extend_from_slice(payload);
    bytes
}

#[cfg(test)]
pub(super) fn encode_packed_packet(opcode: u8, payload: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write as _;

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(payload)
        .context("failed to deflate ED2K peer payload")?;
    let packed_payload = encoder
        .finish()
        .context("failed to finalize ED2K peer payload compression")?;
    Ok(encode_packet(OP_PACKEDPROT, opcode, &packed_payload))
}

pub(super) fn decode_file_hash_payload(payload: &[u8]) -> Result<Ed2kHash> {
    if payload.len() < 16 {
        anyhow::bail!("expected 16-byte file hash payload, got {}", payload.len());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    Ok(Ed2kHash::from_bytes(hash))
}

pub(super) fn encode_file_req_ans_nofil(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_FILEREQANSNOFIL, &file_hash.0)
}

pub(super) fn encode_accept_upload_req() -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ, &[])
}

pub(super) fn encode_queue_ranking(rank: u16) -> Vec<u8> {
    let mut payload = [0u8; 12];
    payload[..2].copy_from_slice(&rank.to_le_bytes());
    encode_packet(OP_EMULEPROT, OP_QUEUERANKING, &payload)
}

pub(super) fn encode_start_upload_req(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_STARTUPLOADREQ, &file_hash.0)
}

pub(super) fn ed2k_file_part_count(file_size: u64) -> u16 {
    if file_size == 0 {
        return 0;
    }
    u16::try_from(file_size.div_ceil(ED2K_PART_SIZE)).unwrap_or(u16::MAX)
}

pub(super) fn encode_request_filename_ext_info(manifest: &Ed2kResumeManifest) -> Vec<u8> {
    let piece_count = u16::try_from(manifest.pieces.len()).unwrap_or(u16::MAX);
    let bitfield_len = usize::from(piece_count).div_ceil(8);
    let mut payload = Vec::with_capacity(2 + bitfield_len + 2);
    payload.extend_from_slice(&piece_count.to_le_bytes());
    let mut current_byte = 0u8;
    for (index, piece) in manifest.pieces.iter().enumerate() {
        if piece.state == Ed2kTransferState::Verified {
            current_byte |= 1 << (index % 8);
        }
        if index % 8 == 7 {
            payload.push(current_byte);
            current_byte = 0;
        }
    }
    if piece_count % 8 != 0 {
        payload.push(current_byte);
    }
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload
}

pub(super) fn skip_request_filename_ext_info(payload: &[u8], file_size: u64) -> Result<&[u8]> {
    if payload.len() < 2 {
        anyhow::bail!("short OP_REQUESTFILENAME ext-info payload");
    }
    let part_count = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
    let expected_parts = usize::from(ed2k_file_part_count(file_size));
    let bitfield_len = part_count.div_ceil(8);
    let expected_len = 2 + bitfield_len + 2;
    if payload.len() < expected_len {
        anyhow::bail!(
            "short OP_REQUESTFILENAME ext-info payload {} expected at least {}",
            payload.len(),
            expected_len
        );
    }
    if expected_parts != 0 && part_count != expected_parts {
        anyhow::bail!(
            "OP_REQUESTFILENAME part count mismatch {} expected {}",
            part_count,
            expected_parts
        );
    }
    Ok(&payload[expected_len..])
}

pub(super) fn encode_request_filename(
    file_hash: &Ed2kHash,
    manifest: &Ed2kResumeManifest,
) -> Vec<u8> {
    let ext_info = encode_request_filename_ext_info(manifest);
    let mut payload = Vec::with_capacity(16 + ext_info.len());
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&ext_info);
    encode_packet(OP_EDONKEYPROT, OP_REQUESTFILENAME, &payload)
}

pub(super) fn encode_request_sources2_subpayload() -> [u8; 3] {
    let mut payload = [0u8; 3];
    payload[0] = ED2K_SOURCE_EXCHANGE2_VERSION;
    payload[1..].copy_from_slice(&0u16.to_le_bytes());
    payload
}

pub(super) fn encode_request_sources2(file_hash: &Ed2kHash) -> Vec<u8> {
    let mut payload = Vec::with_capacity(19);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&encode_request_sources2_subpayload());
    encode_packet(OP_EMULEPROT, OP_REQUESTSOURCES2, &payload)
}

pub(super) fn encode_answer_sources_empty(file_hash: &Ed2kHash) -> Vec<u8> {
    let mut payload = Vec::with_capacity(18);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    encode_packet(OP_EMULEPROT, OP_ANSWERSOURCES, &payload)
}

pub(super) fn encode_answer_sources2_empty(file_hash: &Ed2kHash, version: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(19);
    payload.push(version);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    encode_packet(OP_EMULEPROT, OP_ANSWERSOURCES2, &payload)
}

pub(super) fn encode_aich_file_hash_request(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EMULEPROT, OP_AICHFILEHASHREQ, &file_hash.0)
}

pub(super) fn encode_set_req_file_id(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_SETREQFILEID, &file_hash.0)
}

pub(super) fn encode_request_filename_answer_body(file_name: &str) -> Result<Vec<u8>> {
    let file_name = file_name.as_bytes();
    let mut payload = Vec::with_capacity(2 + file_name.len());
    payload.extend_from_slice(
        &(u16::try_from(file_name.len()).context("file name too large for ED2K filename reply")?)
            .to_le_bytes(),
    );
    payload.extend_from_slice(file_name);
    Ok(payload)
}

pub(super) fn decode_request_filename_answer_body(payload: &[u8]) -> Result<(String, &[u8])> {
    if payload.len() < 2 {
        anyhow::bail!("short OP_REQFILENAMEANSWER body");
    }
    let len = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
    if payload.len() < 2 + len {
        anyhow::bail!("short OP_REQFILENAMEANSWER string");
    }
    Ok((
        String::from_utf8_lossy(&payload[2..2 + len]).into_owned(),
        &payload[2 + len..],
    ))
}

pub(super) fn decode_request_filename_answer(payload: &[u8]) -> Result<(Ed2kHash, String)> {
    let file_hash = decode_file_hash_payload(payload)?;
    let (file_name, remaining) = decode_request_filename_answer_body(&payload[16..])?;
    if !remaining.is_empty() {
        anyhow::bail!(
            "unexpected trailing OP_REQFILENAMEANSWER payload of {} bytes",
            remaining.len()
        );
    }
    Ok((file_hash, file_name))
}

pub(super) fn encode_file_status_body_complete() -> Vec<u8> {
    0u16.to_le_bytes().to_vec()
}

pub(super) fn skip_file_status_body(payload: &[u8]) -> Result<(u16, &[u8])> {
    if payload.len() < 2 {
        anyhow::bail!("short OP_FILESTATUS body");
    }
    let part_count = u16::from_le_bytes([payload[0], payload[1]]);
    let bitfield_len = usize::from(part_count).div_ceil(8);
    let expected_len = 2 + bitfield_len;
    if payload.len() < expected_len {
        anyhow::bail!(
            "short OP_FILESTATUS body {} expected at least {}",
            payload.len(),
            expected_len
        );
    }
    Ok((part_count, &payload[expected_len..]))
}

pub(super) fn encode_multipacket_ext2_request(
    file_identifier: &Ed2kFileIdentifier,
    manifest: &Ed2kResumeManifest,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    file_identifier.encode_into(&mut payload);
    payload.push(OP_REQUESTFILENAME);
    payload.extend_from_slice(&encode_request_filename_ext_info(manifest));
    if manifest.file_size > ED2K_PART_SIZE {
        payload.push(OP_SETREQFILEID);
    }
    payload.push(OP_REQUESTSOURCES2);
    payload.extend_from_slice(&encode_request_sources2_subpayload());
    encode_packet(OP_EMULEPROT, OP_MULTIPACKET_EXT2, &payload)
}

pub(super) fn encode_multipacket_ext2_answer(
    file_identifier: &Ed2kFileIdentifier,
    file_name: &str,
    include_filename_answer: bool,
    include_file_status: bool,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(64);
    file_identifier.encode_into(&mut payload);
    if include_filename_answer {
        payload.push(OP_REQFILENAMEANSWER);
        payload.extend_from_slice(&encode_request_filename_answer_body(file_name)?);
    }
    if include_file_status {
        payload.push(OP_FILESTATUS);
        payload.extend_from_slice(&encode_file_status_body_complete());
    }
    Ok(encode_packet(
        OP_EMULEPROT,
        OP_MULTIPACKETANSWER_EXT2,
        &payload,
    ))
}

pub(super) fn encode_hashset_request(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_HASHSETREQUEST, &file_hash.0)
}

pub(super) fn encode_hashset_request2(
    file_identifier: &Ed2kFileIdentifier,
    request_options: Ed2kHashsetRequestOptions,
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        request_options.has_known_request(),
        "OP_HASHSETREQUEST2 expects at least one known hashset request"
    );
    let mut payload = Vec::with_capacity(46);
    file_identifier.encode_into(&mut payload);
    payload.push(request_options.encode());
    Ok(encode_packet(OP_EMULEPROT, OP_HASHSETREQUEST2, &payload))
}

pub(super) fn encode_hashset_answer(
    file_hash: &Ed2kHash,
    md4_hashset: &[[u8; 16]],
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(16 + 2 + (md4_hashset.len() * 16));
    encode_md4_hashset_body(file_hash, md4_hashset, &mut payload)?;
    Ok(encode_packet(OP_EDONKEYPROT, OP_HASHSETANSWER, &payload))
}

pub(super) fn encode_hashset_answer2(
    file_identifier: &Ed2kFileIdentifier,
    md4_hashset: Option<&[[u8; 16]]>,
    aich_hashset: Option<&Ed2kAichHashset>,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(48);
    file_identifier.encode_into(&mut payload);

    let include_md4 = md4_hashset.is_some_and(|hashset| {
        !hashset.is_empty()
            || file_identifier
                .file_size
                .is_some_and(|file_size| file_size > ED2K_PART_SIZE)
    });
    let include_aich = aich_hashset.is_some();
    payload.push(
        Ed2kHashsetRequestOptions {
            request_md4: include_md4,
            request_aich: include_aich,
        }
        .encode(),
    );
    if let Some(hashset) = md4_hashset.filter(|_| include_md4) {
        encode_md4_hashset_body(&file_identifier.file_hash, hashset, &mut payload)?;
    }
    if let Some(hashset) = aich_hashset {
        encode_aich_hashset_body(hashset, &mut payload)?;
    }

    Ok(encode_packet(OP_EMULEPROT, OP_HASHSETANSWER2, &payload))
}

pub(super) fn encode_md4_hashset_body(
    file_hash: &Ed2kHash,
    md4_hashset: &[[u8; 16]],
    payload: &mut Vec<u8>,
) -> Result<()> {
    let count = u16::try_from(md4_hashset.len()).context("MD4 hashset entry count exceeds u16")?;
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&count.to_le_bytes());
    for part_hash in md4_hashset {
        payload.extend_from_slice(part_hash);
    }
    Ok(())
}

pub(super) fn encode_aich_hashset_body(
    hashset: &Ed2kAichHashset,
    payload: &mut Vec<u8>,
) -> Result<()> {
    let count =
        u16::try_from(hashset.part_hashes.len()).context("AICH hashset entry count exceeds u16")?;
    payload.extend_from_slice(&hashset.master_hash);
    payload.extend_from_slice(&count.to_le_bytes());
    for part_hash in &hashset.part_hashes {
        payload.extend_from_slice(part_hash);
    }
    Ok(())
}

pub(super) fn encode_request_filename_answer(
    file_hash: &Ed2kHash,
    file_name: &str,
) -> Result<Vec<u8>> {
    let body = encode_request_filename_answer_body(file_name)?;
    let mut payload = Vec::with_capacity(16 + body.len());
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&body);
    Ok(encode_packet(
        OP_EDONKEYPROT,
        OP_REQFILENAMEANSWER,
        &payload,
    ))
}

pub(super) fn decode_hashset_request2(
    payload: &[u8],
) -> Result<(Ed2kFileIdentifier, Ed2kHashsetRequestOptions)> {
    let (file_identifier, remaining) = Ed2kFileIdentifier::decode(payload)?;
    let Some((&options, rest)) = remaining.split_first() else {
        anyhow::bail!("short OP_HASHSETREQUEST2 payload");
    };
    if !rest.is_empty() {
        anyhow::bail!("trailing OP_HASHSETREQUEST2 payload {}", rest.len());
    }
    Ok((file_identifier, Ed2kHashsetRequestOptions::decode(options)))
}

pub(super) fn decode_request_parts_payload(
    payload: &[u8],
    use_i64: bool,
) -> Result<(Ed2kHash, Vec<(u64, u64)>)> {
    if payload.len() < 16 {
        anyhow::bail!("short OP_REQUESTPARTS payload");
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let width = if use_i64 { 8 } else { 4 };
    let expected = 16 + (width * 3) + (width * 3);
    if payload.len() < expected {
        anyhow::bail!(
            "short OP_REQUESTPARTS payload {} expected at least {}",
            payload.len(),
            expected
        );
    }
    let starts = &payload[16..16 + (width * 3)];
    let ends = &payload[16 + (width * 3)..expected];
    let mut ranges = Vec::new();
    for index in 0..3usize {
        let start = if use_i64 {
            u64::from_le_bytes(
                starts[index * 8..index * 8 + 8]
                    .try_into()
                    .expect("i64 width"),
            )
        } else {
            u64::from(u32::from_le_bytes(
                starts[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("u32 width"),
            ))
        };
        let end = if use_i64 {
            u64::from_le_bytes(
                ends[index * 8..index * 8 + 8]
                    .try_into()
                    .expect("i64 width"),
            )
        } else {
            u64::from(u32::from_le_bytes(
                ends[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("u32 width"),
            ))
        };
        if end > start {
            ranges.push((start, end));
        }
    }
    Ok((Ed2kHash::from_bytes(hash), ranges))
}

pub(super) fn decode_request_sources_payload(opcode: u8, payload: &[u8]) -> Result<(Ed2kHash, u8)> {
    match opcode {
        OP_REQUESTSOURCES => Ok((decode_file_hash_payload(payload)?, 0)),
        OP_REQUESTSOURCES2 => {
            if payload.len() < 19 {
                anyhow::bail!("short OP_REQUESTSOURCES2 payload {}", payload.len());
            }
            Ok((decode_file_hash_payload(payload)?, payload[16]))
        }
        _ => anyhow::bail!("unsupported source request opcode 0x{opcode:02X}"),
    }
}

pub(super) fn decode_aich_file_hash_answer(payload: &[u8]) -> Result<Ed2kHash> {
    if payload.len() < 16 {
        anyhow::bail!("short OP_AICHFILEHASHANS payload {}", payload.len());
    }
    Ok(Ed2kHash::from_bytes(payload[..16].try_into()?))
}

/// Encode one ED2K `OP_REQUESTPARTS` packet with up to three ranges.
///
/// The successful public oracle capture used rolling multi-range requests
/// instead of emitting one separate request packet per range, so the native
/// downloader batches adjacent work into one packet to stay closer to that
/// accepted wire shape.
pub(super) fn encode_request_parts_batch(
    file_hash: &Ed2kHash,
    ranges: &[(u64, u64)],
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        !ranges.is_empty() && ranges.len() <= 3,
        "OP_REQUESTPARTS expects between one and three ranges"
    );
    let use_i64 = ranges.iter().any(|(_, end)| *end > u64::from(u32::MAX));
    let mut payload = Vec::with_capacity(16 + if use_i64 { 48 } else { 24 });
    payload.extend_from_slice(&file_hash.0);
    if use_i64 {
        for index in 0..3usize {
            let start = ranges.get(index).map_or(0, |(start, _)| *start);
            payload.extend_from_slice(&start.to_le_bytes());
        }
        for index in 0..3usize {
            let end = ranges.get(index).map_or(0, |(_, end)| *end);
            payload.extend_from_slice(&end.to_le_bytes());
        }
        return Ok(encode_packet(OP_EMULEPROT, OP_REQUESTPARTS_I64, &payload));
    }
    for index in 0..3usize {
        let start = ranges.get(index).map_or(0, |(start, _)| *start);
        let start = u32::try_from(start).context("start offset exceeds OP_REQUESTPARTS limit")?;
        payload.extend_from_slice(&start.to_le_bytes());
    }
    for index in 0..3usize {
        let end = ranges.get(index).map_or(0, |(_, end)| *end);
        let end = u32::try_from(end).context("end offset exceeds OP_REQUESTPARTS limit")?;
        payload.extend_from_slice(&end.to_le_bytes());
    }
    Ok(encode_packet(OP_EDONKEYPROT, OP_REQUESTPARTS, &payload))
}

pub(super) fn decode_hashset_answer(payload: &[u8]) -> Result<(Ed2kHash, Vec<[u8; 16]>)> {
    let (file_hash, hashset, remaining) = decode_md4_hashset_body(payload)?;
    if !remaining.is_empty() {
        anyhow::bail!("trailing OP_HASHSETANSWER payload {}", remaining.len());
    }
    Ok((file_hash, hashset))
}

pub(super) fn decode_hashset_answer2(payload: &[u8]) -> Result<Ed2kHashsetAnswer2> {
    let (file_identifier, remaining) = Ed2kFileIdentifier::decode(payload)?;
    let Some((&options, mut remaining)) = remaining.split_first() else {
        anyhow::bail!("short OP_HASHSETANSWER2 payload");
    };
    let options = Ed2kHashsetRequestOptions::decode(options);
    let md4_hashset = if options.request_md4 {
        let (returned_hash, hashset, rest) = decode_md4_hashset_body(remaining)?;
        if returned_hash != file_identifier.file_hash {
            anyhow::bail!(
                "OP_HASHSETANSWER2 MD4 section was for {} instead of {}",
                returned_hash,
                file_identifier.file_hash
            );
        }
        remaining = rest;
        Some(hashset)
    } else {
        None
    };
    let aich_hashset = if options.request_aich {
        let (hashset, rest) = decode_aich_hashset_body(remaining)?;
        if let Some(expected_root) = file_identifier.aich_root
            && hashset.master_hash != expected_root
        {
            anyhow::bail!(
                "OP_HASHSETANSWER2 AICH section root mismatch for {}",
                file_identifier.file_hash
            );
        }
        remaining = rest;
        Some(hashset)
    } else {
        None
    };
    if !remaining.is_empty() {
        anyhow::bail!("trailing OP_HASHSETANSWER2 payload {}", remaining.len());
    }
    Ok(Ed2kHashsetAnswer2 {
        file_identifier,
        md4_hashset,
        aich_hashset,
    })
}

pub(super) fn decode_md4_hashset_body(payload: &[u8]) -> Result<Ed2kMd4HashsetDecode<'_>> {
    if payload.len() < 18 {
        anyhow::bail!("short OP_HASHSETANSWER payload {}", payload.len());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let count = usize::from(u16::from_le_bytes([payload[16], payload[17]]));
    let expected = 18 + (count * 16);
    if payload.len() < expected {
        anyhow::bail!(
            "short OP_HASHSETANSWER payload length {} expected at least {}",
            payload.len(),
            expected
        );
    }
    let mut hashset = Vec::with_capacity(count);
    let mut cursor = 18usize;
    for _ in 0..count {
        let mut part_hash = [0u8; 16];
        part_hash.copy_from_slice(&payload[cursor..cursor + 16]);
        hashset.push(part_hash);
        cursor += 16;
    }
    Ok((Ed2kHash::from_bytes(hash), hashset, &payload[cursor..]))
}

pub(super) fn decode_aich_hashset_body(payload: &[u8]) -> Result<(Ed2kAichHashset, &[u8])> {
    if payload.len() < 22 {
        anyhow::bail!("short AICH hashset body {}", payload.len());
    }
    let mut master_hash = [0u8; 20];
    master_hash.copy_from_slice(&payload[..20]);
    let count = usize::from(u16::from_le_bytes([payload[20], payload[21]]));
    let expected = 22 + (count * 20);
    if payload.len() < expected {
        anyhow::bail!(
            "short AICH hashset body {} expected at least {}",
            payload.len(),
            expected
        );
    }
    let mut part_hashes = Vec::with_capacity(count);
    let mut cursor = 22usize;
    for _ in 0..count {
        let mut part_hash = [0u8; 20];
        part_hash.copy_from_slice(&payload[cursor..cursor + 20]);
        part_hashes.push(part_hash);
        cursor += 20;
    }
    Ok((
        Ed2kAichHashset {
            master_hash,
            part_hashes,
        },
        &payload[cursor..],
    ))
}

pub(super) fn decode_sending_part_payload(
    payload: &[u8],
    use_i64: bool,
) -> Result<(Ed2kHash, u64, u64, Vec<u8>)> {
    let header_len = 16 + if use_i64 { 16 } else { 8 };
    if payload.len() < header_len {
        anyhow::bail!("short OP_SENDINGPART payload {}", payload.len());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let (start, end) = if use_i64 {
        let start = u64::from_le_bytes(payload[16..24].try_into().expect("u64 width"));
        let end = u64::from_le_bytes(payload[24..32].try_into().expect("u64 width"));
        (start, end)
    } else {
        let start = u64::from(u32::from_le_bytes(
            payload[16..20].try_into().expect("u32 width"),
        ));
        let end = u64::from(u32::from_le_bytes(
            payload[20..24].try_into().expect("u32 width"),
        ));
        (start, end)
    };
    if end < start {
        anyhow::bail!("invalid OP_SENDINGPART range {start}..{end}");
    }
    let bytes = payload[header_len..].to_vec();
    if usize::try_from(end - start).unwrap_or(usize::MAX) != bytes.len() {
        anyhow::bail!(
            "OP_SENDINGPART body length {} does not match range {}..{}",
            bytes.len(),
            start,
            end
        );
    }
    Ok((Ed2kHash::from_bytes(hash), start, end, bytes))
}

pub(super) fn decode_compressed_part_fragment(
    payload: &[u8],
    use_i64: bool,
) -> Result<(Ed2kHash, u64, usize, &[u8])> {
    let header_len = 16 + if use_i64 { 12 } else { 8 };
    if payload.len() < header_len {
        anyhow::bail!("short OP_COMPRESSEDPART payload {}", payload.len());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let (start, advertised_compressed_len) = if use_i64 {
        let start = u64::from_le_bytes(payload[16..24].try_into().expect("u64 width"));
        let advertised_compressed_len = usize::try_from(u32::from_le_bytes(
            payload[24..28].try_into().expect("u32 width"),
        ))
        .unwrap_or(usize::MAX);
        (start, advertised_compressed_len)
    } else {
        let start = u64::from(u32::from_le_bytes(
            payload[16..20].try_into().expect("u32 width"),
        ));
        let advertised_compressed_len = usize::try_from(u32::from_le_bytes(
            payload[20..24].try_into().expect("u32 width"),
        ))
        .unwrap_or(usize::MAX);
        (start, advertised_compressed_len)
    };
    Ok((
        Ed2kHash::from_bytes(hash),
        start,
        advertised_compressed_len,
        &payload[header_len..],
    ))
}

pub(super) fn inflate_compressed_part_fragment(
    pending: &mut PendingCompressedPart,
    compressed_fragment: &[u8],
) -> Result<(Vec<u8>, bool)> {
    let mut remaining = compressed_fragment;
    let mut bytes = Vec::new();
    let mut finished = false;

    while !remaining.is_empty() {
        let mut output = [0u8; 16 * 1024];
        let total_in_before = pending.inflater.total_in();
        let total_out_before = pending.inflater.total_out();
        let status = pending
            .inflater
            .decompress(remaining, &mut output, FlushDecompress::Sync)
            .context("failed to inflate OP_COMPRESSEDPART fragment")?;
        let consumed = usize::try_from(pending.inflater.total_in() - total_in_before).unwrap_or(0);
        let produced =
            usize::try_from(pending.inflater.total_out() - total_out_before).unwrap_or(0);
        if produced != 0 {
            bytes.extend_from_slice(&output[..produced]);
        }
        remaining = &remaining[consumed..];
        match status {
            Status::StreamEnd => {
                finished = true;
                break;
            }
            Status::Ok => {
                if consumed == 0 && produced == 0 {
                    anyhow::bail!("OP_COMPRESSEDPART inflate made no progress");
                }
            }
            Status::BufError => {
                if consumed == 0 && produced == 0 {
                    break;
                }
            }
        }
    }

    pending.compressed_received += compressed_fragment.len();
    if pending.compressed_received > pending.advertised_compressed_len {
        anyhow::bail!(
            "OP_COMPRESSEDPART received {} compressed bytes, above advertised {}",
            pending.compressed_received,
            pending.advertised_compressed_len
        );
    }
    if pending.compressed_received == pending.advertised_compressed_len && !finished {
        loop {
            let mut output = [0u8; 16 * 1024];
            let total_out_before = pending.inflater.total_out();
            let status = pending
                .inflater
                .decompress(&[], &mut output, FlushDecompress::Finish)
                .context("failed to finish OP_COMPRESSEDPART inflate stream")?;
            let produced =
                usize::try_from(pending.inflater.total_out() - total_out_before).unwrap_or(0);
            if produced != 0 {
                bytes.extend_from_slice(&output[..produced]);
            }
            match status {
                Status::StreamEnd => {
                    finished = true;
                    break;
                }
                Status::Ok | Status::BufError if produced == 0 => {
                    finished = true;
                    break;
                }
                Status::Ok | Status::BufError => {}
            }
        }
    }
    pending.uncompressed_written += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    Ok((bytes, finished))
}

pub(super) fn upload_packet_fragment_len(remaining: usize) -> usize {
    if remaining < ED2K_UPLOAD_PACKET_SPLIT_THRESHOLD {
        remaining
    } else {
        ED2K_UPLOAD_PACKET_FRAGMENT_LEN
    }
}

pub(super) fn should_attempt_upload_compression(canonical_name: &str) -> bool {
    let Some(extension) = Path::new(canonical_name)
        .extension()
        .and_then(|value| value.to_str())
    else {
        return true;
    };
    let extension = extension.to_ascii_lowercase();
    !matches!(
        extension.as_str(),
        "zip" | "rar" | "7z" | "cbz" | "cbr" | "ogm" | "ace"
    )
}

pub(super) fn compress_upload_payload(
    canonical_name: &str,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>> {
    if !should_attempt_upload_compression(canonical_name) {
        return Ok(None);
    }

    let mut compressor = Compress::new(Compression::new(1), true);
    let mut compressed = Vec::with_capacity(bytes.len().saturating_add(300));
    let mut remaining = bytes;
    let mut output = [0u8; 16 * 1024];
    loop {
        let total_in_before = compressor.total_in();
        let total_out_before = compressor.total_out();
        let status = compressor
            .compress(remaining, &mut output, FlushCompress::Finish)
            .context("failed to deflate ED2K upload payload")?;
        let consumed = usize::try_from(compressor.total_in() - total_in_before).unwrap_or(0);
        let produced = usize::try_from(compressor.total_out() - total_out_before).unwrap_or(0);
        if produced != 0 {
            compressed.extend_from_slice(&output[..produced]);
        }
        remaining = &remaining[consumed..];
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                if consumed == 0 && produced == 0 {
                    anyhow::bail!("ED2K upload compression made no progress");
                }
            }
        }
    }

    if compressed.len() >= bytes.len() {
        return Ok(None);
    }

    Ok(Some(compressed))
}

pub(super) fn build_upload_part_packets(
    file_hash: &Ed2kHash,
    canonical_name: &str,
    start: u64,
    end: u64,
    bytes: &[u8],
    use_i64: bool,
) -> Result<Vec<EncodedUploadPartPacket>> {
    let range_len = usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX);
    if range_len != bytes.len() {
        anyhow::bail!(
            "upload payload length {} does not match requested range {}..{}",
            bytes.len(),
            start,
            end
        );
    }

    if let Some(compressed) = compress_upload_payload(canonical_name, bytes)? {
        let mut packets = Vec::new();
        let mut offset = 0usize;
        while offset < compressed.len() {
            let fragment_len = upload_packet_fragment_len(compressed.len() - offset);
            let packet = encode_compressed_part_fragment(
                file_hash,
                start,
                compressed.len(),
                &compressed[offset..offset + fragment_len],
                use_i64,
            )?;
            packets.push(EncodedUploadPartPacket {
                phase: "compressed_part",
                packet,
            });
            offset += fragment_len;
        }
        return Ok(packets);
    }

    let mut packets = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let fragment_len = upload_packet_fragment_len(bytes.len() - offset);
        let fragment_start = start + u64::try_from(offset).unwrap_or(u64::MAX);
        let fragment_end = fragment_start + u64::try_from(fragment_len).unwrap_or(u64::MAX);
        let packet = encode_sending_part(
            file_hash,
            fragment_start,
            fragment_end,
            &bytes[offset..offset + fragment_len],
            use_i64,
        )?;
        packets.push(EncodedUploadPartPacket {
            phase: "sending_part",
            packet,
        });
        offset += fragment_len;
    }
    Ok(packets)
}

pub(super) fn encode_sending_part(
    file_hash: &Ed2kHash,
    start: u64,
    end: u64,
    bytes: &[u8],
    use_i64: bool,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(16 + if use_i64 { 16 } else { 8 } + bytes.len());
    payload.extend_from_slice(&file_hash.0);
    if use_i64 {
        payload.extend_from_slice(&start.to_le_bytes());
        payload.extend_from_slice(&end.to_le_bytes());
        payload.extend_from_slice(bytes);
        return Ok(encode_packet(OP_EMULEPROT, OP_SENDINGPART_I64, &payload));
    }
    let start = u32::try_from(start).context("start offset exceeds OP_SENDINGPART limit")?;
    let end = u32::try_from(end).context("end offset exceeds OP_SENDINGPART limit")?;
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&end.to_le_bytes());
    payload.extend_from_slice(bytes);
    Ok(encode_packet(OP_EDONKEYPROT, OP_SENDINGPART, &payload))
}

pub(super) fn encode_compressed_part_fragment(
    file_hash: &Ed2kHash,
    start: u64,
    advertised_compressed_len: usize,
    compressed_fragment: &[u8],
    use_i64: bool,
) -> Result<Vec<u8>> {
    let advertised_compressed_len = u32::try_from(advertised_compressed_len)
        .context("compressed payload exceeds OP_COMPRESSEDPART length field")?;
    let mut payload =
        Vec::with_capacity(16 + if use_i64 { 12 } else { 8 } + compressed_fragment.len());
    payload.extend_from_slice(&file_hash.0);
    if use_i64 {
        payload.extend_from_slice(&start.to_le_bytes());
        payload.extend_from_slice(&advertised_compressed_len.to_le_bytes());
        payload.extend_from_slice(compressed_fragment);
        return Ok(encode_packet(OP_EMULEPROT, OP_COMPRESSEDPART_I64, &payload));
    }

    let start = u32::try_from(start).context("start offset exceeds OP_COMPRESSEDPART limit")?;
    payload.extend_from_slice(&start.to_le_bytes());
    payload.extend_from_slice(&advertised_compressed_len.to_le_bytes());
    payload.extend_from_slice(compressed_fragment);
    Ok(encode_packet(OP_EMULEPROT, OP_COMPRESSEDPART, &payload))
}
