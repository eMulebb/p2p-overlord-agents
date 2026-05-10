use std::net::SocketAddr;

use anyhow::{Context, Result};
use overlord_kad_proto::Ed2kHash;

use crate::{
    ed2k_tcp::{
        ED2K_SOURCE_EXCHANGE2_VERSION, Ed2kFileIdentifier, Ed2kTransport, OP_AICHFILEHASHREQ,
        OP_REQUESTFILENAME, OP_REQUESTSOURCES, OP_REQUESTSOURCES2, OP_SETREQFILEID,
    },
    ed2k_transfer::Ed2kTransferRuntime,
};

use super::super::super::codec::{
    decode_file_hash_payload, decode_hashset_request2, decode_request_sources_payload,
    encode_answer_sources_empty, encode_answer_sources2_empty, encode_file_req_ans_nofil,
    encode_file_status_complete, encode_hashset_answer, encode_hashset_answer2,
    encode_multipacket_ext2_answer, encode_request_filename_answer, skip_request_filename_ext_info,
};
use super::super::super::dump::dump_ed2k_tcp_listener_send;

pub(in crate::ed2k_tcp) async fn handle_multipacket_ext2_request(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let (requested_identifier, mut remaining) = Ed2kFileIdentifier::decode(payload)?;
    let requested = requested_identifier.file_hash;
    let Some(shared) = transfer_runtime.local_entry(&requested).await? else {
        send_nofile(transport, peer_addr, &requested, "multipacket_ext2_nofil").await?;
        return Ok(Some(requested));
    };
    let shared_identifier = Ed2kFileIdentifier::from_shared_entry(&shared)?;
    if !shared_identifier.matches_relaxed(&requested_identifier) {
        send_nofile(
            transport,
            peer_addr,
            &requested,
            "multipacket_ext2_mismatch",
        )
        .await?;
        return Ok(Some(requested));
    }

    let mut include_filename = false;
    let mut include_status = false;
    while let Some((&sub_opcode, rest)) = remaining.split_first() {
        remaining = rest;
        match sub_opcode {
            OP_REQUESTFILENAME => {
                let rest = skip_request_filename_ext_info(remaining, shared.file_size)?;
                remaining = rest;
                include_filename = true;
            }
            OP_SETREQFILEID => {
                include_status = true;
            }
            OP_REQUESTSOURCES => {
                let reply = encode_answer_sources_empty(&requested);
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "answer_sources", &reply);
                transport
                    .write_all(&reply)
                    .await
                    .with_context(|| format!("failed to send OP_ANSWERSOURCES to {peer_addr}"))?;
            }
            OP_REQUESTSOURCES2 => {
                if remaining.len() < 3 {
                    anyhow::bail!("short OP_REQUESTSOURCES2 sub-payload in OP_MULTIPACKET_EXT2");
                }
                let requested_version = remaining[0];
                remaining = &remaining[3..];
                let reply = encode_answer_sources2_empty(
                    &requested,
                    requested_version.min(ED2K_SOURCE_EXCHANGE2_VERSION),
                );
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "answer_sources", &reply);
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to send source exchange reply to {peer_addr}")
                })?;
            }
            OP_AICHFILEHASHREQ => {}
            _ => {
                anyhow::bail!("unsupported OP_MULTIPACKET_EXT2 sub-op 0x{sub_opcode:02X}");
            }
        }
    }

    if include_filename || include_status {
        let reply = encode_multipacket_ext2_answer(
            &shared_identifier,
            &shared.canonical_name,
            include_filename,
            include_status,
        )?;
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "multipacket_ext2_answer", &reply);
        transport
            .write_all(&reply)
            .await
            .with_context(|| format!("failed to send OP_MULTIPACKETANSWER_EXT2 to {peer_addr}"))?;
    }
    Ok(Some(requested))
}

pub(in crate::ed2k_tcp) async fn handle_request_filename(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let requested = decode_file_hash_payload(payload)?;
    let reply = if let Some(shared) = transfer_runtime.local_entry(&requested).await? {
        encode_request_filename_answer(&requested, &shared.canonical_name)?
    } else {
        encode_file_req_ans_nofil(&requested)
    };
    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "request_filename", &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_REQFILENAMEANSWER to {peer_addr}"))?;
    Ok(Some(requested))
}

pub(in crate::ed2k_tcp) async fn handle_set_req_file_id(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let requested = decode_file_hash_payload(payload)?;
    let reply = if transfer_runtime.local_entry(&requested).await?.is_some() {
        encode_file_status_complete(&requested)
    } else {
        encode_file_req_ans_nofil(&requested)
    };
    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "set_req_file_id", &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_SETREQFILEID response to {peer_addr}"))?;
    Ok(Some(requested))
}

pub(in crate::ed2k_tcp) async fn handle_hashset_request(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let requested = decode_file_hash_payload(payload)?;
    let reply = if transfer_runtime.local_entry(&requested).await?.is_some() {
        if let Some(hashset) = transfer_runtime.md4_hashset(&requested).await? {
            encode_hashset_answer(&requested, &hashset)?
        } else {
            encode_file_req_ans_nofil(&requested)
        }
    } else {
        encode_file_req_ans_nofil(&requested)
    };
    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "hashset_request", &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_HASHSETANSWER to {peer_addr}"))?;
    Ok(Some(requested))
}

pub(in crate::ed2k_tcp) async fn handle_hashset_request2(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let (requested_identifier, request_options) = decode_hashset_request2(payload)?;
    let requested = requested_identifier.file_hash;
    if !request_options.has_known_request() {
        return Ok(Some(requested));
    }
    let reply = if let Some(shared) = transfer_runtime.local_entry(&requested).await? {
        let shared_identifier = Ed2kFileIdentifier::from_shared_entry(&shared)?;
        if !shared_identifier.matches_relaxed(&requested_identifier) {
            encode_file_req_ans_nofil(&requested)
        } else {
            let md4_hashset = if request_options.request_md4 {
                transfer_runtime.md4_hashset(&requested).await?
            } else {
                None
            };
            let aich_hashset = if request_options.request_aich {
                transfer_runtime.aich_hashset(&requested).await?
            } else {
                None
            };
            encode_hashset_answer2(
                &shared_identifier,
                md4_hashset.as_deref(),
                aich_hashset.as_ref(),
            )?
        }
    } else {
        encode_file_req_ans_nofil(&requested)
    };
    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "hashset_request", &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_HASHSETANSWER2 to {peer_addr}"))?;
    Ok(Some(requested))
}

pub(in crate::ed2k_tcp) async fn handle_source_request(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    opcode: u8,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let (requested, requested_version) = decode_request_sources_payload(opcode, payload)?;
    if transfer_runtime.local_entry(&requested).await?.is_some() {
        let reply = if opcode == OP_REQUESTSOURCES2 {
            encode_answer_sources2_empty(
                &requested,
                requested_version.min(ED2K_SOURCE_EXCHANGE2_VERSION),
            )
        } else {
            encode_answer_sources_empty(&requested)
        };
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "answer_sources", &reply);
        transport
            .write_all(&reply)
            .await
            .with_context(|| format!("failed to send source exchange response to {peer_addr}"))?;
    }
    Ok(Some(requested))
}

pub(in crate::ed2k_tcp) async fn handle_aich_file_hash_request(
    transfer_runtime: &Ed2kTransferRuntime,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let requested = decode_file_hash_payload(payload)?;
    let _ = transfer_runtime.local_entry(&requested).await?;
    Ok(Some(requested))
}

async fn send_nofile(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    requested: &Ed2kHash,
    phase: &'static str,
) -> Result<()> {
    let reply = encode_file_req_ans_nofil(requested);
    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, phase, &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_FILEREQANSNOFIL to {peer_addr}"))
}
