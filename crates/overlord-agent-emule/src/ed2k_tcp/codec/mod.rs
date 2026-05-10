use std::io::Read;

use anyhow::{Context, Result};
use flate2::read::ZlibDecoder;
use overlord_kad_proto::Ed2kHash;

use crate::ed2k_transfer::{ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kTransferState};

mod hashset;
mod upload;

pub(super) use hashset::{
    decode_hashset_answer, decode_hashset_answer2, decode_hashset_request2, encode_hashset_answer,
    encode_hashset_answer2, encode_hashset_request, encode_hashset_request2,
};
pub(super) use upload::{
    build_upload_part_packets, decode_compressed_part_fragment, decode_request_parts_payload,
    decode_sending_part_payload, encode_request_parts_batch, inflate_compressed_part_fragment,
};
#[cfg(test)]
pub(super) use upload::{encode_compressed_part_fragment, encode_sending_part};

use super::{
    ED2K_SOURCE_EXCHANGE2_VERSION, Ed2kFileIdentifier, MAX_PEER_DECOMPRESSED_PACKET_LEN,
    OP_ACCEPTUPLOADREQ, OP_AICHFILEHASHREQ, OP_ANSWERSOURCES, OP_ANSWERSOURCES2, OP_EDONKEYPROT,
    OP_EMULEPROT, OP_FILEREQANSNOFIL, OP_FILESTATUS, OP_MULTIPACKET_EXT2,
    OP_MULTIPACKETANSWER_EXT2, OP_PACKEDPROT, OP_QUEUERANKING, OP_REQFILENAMEANSWER,
    OP_REQUESTFILENAME, OP_REQUESTSOURCES, OP_REQUESTSOURCES2, OP_SETREQFILEID, OP_STARTUPLOADREQ,
    TCP_PACKET_HEADER_LEN,
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

pub(super) fn encode_request_sources(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EMULEPROT, OP_REQUESTSOURCES, &file_hash.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SourceExchangePeer {
    pub(super) ip: [u8; 4],
    pub(super) tcp_port: u16,
    pub(super) server_ip: u32,
    pub(super) server_port: u16,
    pub(super) user_hash: Option<[u8; 16]>,
    pub(super) connect_options: u8,
}

pub(super) fn encode_answer_sources(
    file_hash: &Ed2kHash,
    sources: &[SourceExchangePeer],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(18 + sources.len() * 12);
    payload.extend_from_slice(&file_hash.0);
    encode_source_exchange_entries(&mut payload, 1, sources);
    encode_packet(OP_EMULEPROT, OP_ANSWERSOURCES, &payload)
}

pub(super) fn encode_answer_sources2(
    file_hash: &Ed2kHash,
    version: u8,
    sources: &[SourceExchangePeer],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(19 + sources.len() * 29);
    payload.push(version);
    payload.extend_from_slice(&file_hash.0);
    encode_source_exchange_entries(&mut payload, version, sources);
    encode_packet(OP_EMULEPROT, OP_ANSWERSOURCES2, &payload)
}

fn encode_source_exchange_entries(
    payload: &mut Vec<u8>,
    version: u8,
    sources: &[SourceExchangePeer],
) {
    let include_user_hash = version >= 2;
    let include_connect_options = version >= 4;
    let max_sources = sources
        .iter()
        .filter(|source| !include_user_hash || source.user_hash.is_some())
        .take(501)
        .count();
    payload.extend_from_slice(
        &u16::try_from(max_sources)
            .expect("source exchange count is capped")
            .to_le_bytes(),
    );
    for source in sources
        .iter()
        .filter(|source| !include_user_hash || source.user_hash.is_some())
        .take(501)
    {
        let client_id = if version < 3 {
            u32::from_le_bytes(source.ip)
        } else {
            u32::from_be_bytes(source.ip)
        };
        payload.extend_from_slice(&client_id.to_le_bytes());
        payload.extend_from_slice(&source.tcp_port.to_le_bytes());
        payload.extend_from_slice(&source.server_ip.to_le_bytes());
        payload.extend_from_slice(&source.server_port.to_le_bytes());
        if include_user_hash {
            payload.extend_from_slice(&source.user_hash.expect("filtered sources have user hash"));
        }
        if include_connect_options {
            payload.push(source.connect_options);
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PeerSourceExchangeRequest {
    None,
    V1,
    V2,
}

pub(super) fn encode_multipacket_ext2_request(
    file_identifier: &Ed2kFileIdentifier,
    manifest: &Ed2kResumeManifest,
    source_exchange_request: PeerSourceExchangeRequest,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    file_identifier.encode_into(&mut payload);
    payload.push(OP_REQUESTFILENAME);
    payload.extend_from_slice(&encode_request_filename_ext_info(manifest));
    if manifest.file_size > ED2K_PART_SIZE {
        payload.push(OP_SETREQFILEID);
    }
    match source_exchange_request {
        PeerSourceExchangeRequest::None => {}
        PeerSourceExchangeRequest::V1 => payload.push(OP_REQUESTSOURCES),
        PeerSourceExchangeRequest::V2 => {
            payload.push(OP_REQUESTSOURCES2);
            payload.extend_from_slice(&encode_request_sources2_subpayload());
        }
    }
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
