use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result};
use overlord_kad_proto::Ed2kHash;

use crate::ed2k_transfer::{Ed2kSourceHint, Ed2kTransferRuntime};

use super::super::{
    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, ED2K_SECURE_IDENT_SIGNATURE_NEEDED,
    Ed2kFileIdentifier, Ed2kHelloIdentity, Ed2kSecureIdent, Ed2kTransport, OP_ACCEPTUPLOADREQ,
    OP_AICHFILEHASHANS, OP_ANSWERSOURCES, OP_ANSWERSOURCES2, OP_COMPRESSEDPART,
    OP_COMPRESSEDPART_I64, OP_EDONKEYPROT, OP_EMULEINFO, OP_EMULEINFOANSWER, OP_EMULEPROT,
    OP_FILEDESC, OP_FILEREQANSNOFIL, OP_FILESTATUS, OP_HASHSETANSWER, OP_HASHSETANSWER2, OP_HELLO,
    OP_HELLOANSWER, OP_MULTIPACKETANSWER_EXT2, OP_PUBLICKEY, OP_QUEUERANKING, OP_REQFILENAMEANSWER,
    OP_SECIDENTSTATE, OP_SENDINGPART, OP_SENDINGPART_I64, OP_SETREQFILEID, OP_SIGNATURE,
    begin_secure_ident_probe, build_hello_responses, decode_aich_file_hash_answer,
    decode_answer_sources2_payload, decode_file_status_payload, decode_hashset_answer,
    decode_hashset_answer2, decode_hello_profile, decode_public_key_payload,
    decode_request_filename_answer, decode_request_filename_answer_body, decode_secident_state,
    dump_ed2k_tcp_download_meta, dump_ed2k_tcp_download_recv, dump_ed2k_tcp_download_send,
    encode_emule_info_answer, encode_packet, is_connection_shutdown_error, skip_file_status_body,
    try_send_secure_ident_signature,
};
use super::{
    ActiveDownloadPiece, DownloadRequestWindowState, PendingCompressedPart, PendingPartRequest,
    flush_buffered_download_prefixes, next_download_read_timeout, pump_download_request_window,
    reconcile_download_manifest_metadata,
};
mod parts;
mod startup;
mod state;

use parts::{DownloadPartPacket, handle_download_part_packet};
use startup::{DownloadStartupStep, HASHSET_STALL_UPLOAD_FALLBACK, advance_download_startup};
use state::DownloadSessionState;
/// Outcome of one outbound ED2K peer download attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ed2kPeerDownloadOutcome {
    /// The peer contributed enough data for the manifest to complete.
    Completed,
    /// The peer accepted the session and looked valid, but the transfer did not
    /// complete before the peer closed or the attempt timed out.
    AcceptedButIncomplete,
}

pub(in crate::ed2k_tcp) struct DownloadSessionOptions<'a> {
    pub(in crate::ed2k_tcp) transport: &'a mut Ed2kTransport,
    pub(in crate::ed2k_tcp) peer_addr: SocketAddr,
    pub(in crate::ed2k_tcp) hello_identity: Ed2kHelloIdentity,
    pub(in crate::ed2k_tcp) secure_ident: &'a Ed2kSecureIdent,
    pub(in crate::ed2k_tcp) transfer_runtime: &'a Ed2kTransferRuntime,
    pub(in crate::ed2k_tcp) file_hash: Ed2kHash,
    pub(in crate::ed2k_tcp) file_hash_hex: &'a str,
    pub(in crate::ed2k_tcp) timeout: Duration,
    pub(in crate::ed2k_tcp) send_initial_requests: bool,
    pub(in crate::ed2k_tcp) source_exchange_allowed: bool,
    pub(in crate::ed2k_tcp) initial_hello_complete: bool,
    pub(in crate::ed2k_tcp) initial_secure_ident_started: bool,
}

pub(in crate::ed2k_tcp) async fn drive_download_session(
    options: DownloadSessionOptions<'_>,
) -> Result<Ed2kPeerDownloadOutcome> {
    let DownloadSessionOptions {
        transport,
        peer_addr,
        hello_identity,
        secure_ident,
        transfer_runtime,
        file_hash,
        file_hash_hex,
        timeout,
        send_initial_requests,
        source_exchange_allowed,
        initial_hello_complete,
        initial_secure_ident_started,
    } = options;
    const QUEUE_RANK_GRACE: Duration = Duration::from_secs(20);
    const PART_RESPONSE_GRACE: Duration = Duration::from_secs(20);
    // eMule keeps a pending block scheduler that is broader than one live wire
    // request. We mirror that with one claimed piece, a queued-vs-unqueued
    // block list, and wire packets that carry up to three queued ranges.
    let mut pending_part_requests: Vec<PendingPartRequest> = Vec::new();
    let mut pending_compressed_parts: Vec<PendingCompressedPart> = Vec::new();
    let mut manifest = transfer_runtime.manifest(file_hash_hex).await?;
    let mut request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
    let mut session_state = DownloadSessionState::new(
        initial_hello_complete,
        initial_secure_ident_started,
        source_exchange_allowed,
    );

    let session_result = async {
        loop {
            if manifest.completed {
                return Ok(Ed2kPeerDownloadOutcome::Completed);
            }

            advance_download_startup(DownloadStartupStep {
                transport,
                peer_addr,
                secure_ident,
                transfer_runtime,
                file_hash: &file_hash,
                file_hash_hex,
                send_initial_requests,
                manifest: &mut manifest,
                request_file_identifier: &request_file_identifier,
                session_state: &mut session_state,
            })
            .await?;

            if manifest.md4_hashset_acquired
                && session_state.upload_accepted
                && let Some(next_deadline) = pump_download_request_window(
                    transport,
                    peer_addr,
                    DownloadRequestWindowState {
                        transfer_runtime,
                        file_hash: &file_hash,
                        file_hash_hex,
                        file_size: manifest.file_size,
                        manifest: &manifest,
                        active_piece_request: &mut session_state.active_piece_request,
                        pending_part_requests: &mut pending_part_requests,
                        upload_accepted_at: session_state.upload_accepted_at
                            .unwrap_or_else(tokio::time::Instant::now),
                        completed_block_count: session_state.completed_block_count,
                        session_payload_down: session_state.session_payload_down,
                        part_response_grace: PART_RESPONSE_GRACE,
                    },
                )
                .await?
            {
                session_state.part_response_deadline = Some(next_deadline);
            }

            let fallback_poll_delay = if send_initial_requests
                && session_state.hello_complete
                && session_state.hashset_requested
                && !manifest.md4_hashset_acquired
                && !session_state.upload_requested
                && !session_state.waiting_for_peer_secure_ident()
            {
                session_state.hashset_requested_at.map(|requested_at| {
                    HASHSET_STALL_UPLOAD_FALLBACK.saturating_sub(requested_at.elapsed())
                })
            } else {
                None
            };
            let now = tokio::time::Instant::now();
            let read_timeout = next_download_read_timeout(
                now,
                timeout,
                fallback_poll_delay,
                session_state.queued_until,
                session_state.part_response_deadline,
            );
            let packet = match tokio::time::timeout(read_timeout, transport.read_packet()).await {
                Ok(Ok(Some(packet))) => packet,
                Ok(Ok(None)) => {
                    if session_state.hello_complete {
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "peer_closed_incomplete",
                            format!("file_hash={file_hash_hex}"),
                        );
                        return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                    }
                    anyhow::bail!("peer {peer_addr} closed ED2K download session");
                }
                Ok(Err(error)) => {
                    if session_state.hello_complete && is_connection_shutdown_error(&error) {
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "peer_shutdown_incomplete",
                            format!("file_hash={file_hash_hex}"),
                        );
                        return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                    }
                    return Err(error)
                        .with_context(|| format!("failed to read eD2k packet from {peer_addr}"));
                }
                Err(_) => {
                    if fallback_poll_delay.is_some() {
                        continue;
                    }
                    if session_state.queued_until.is_some_and(|deadline| tokio::time::Instant::now() < deadline) {
                        continue;
                    }
                    if !pending_part_requests.iter().any(|request| request.queued) {
                        session_state.part_response_deadline = None;
                    }
                    if session_state.part_response_deadline
                        .is_some_and(|deadline| tokio::time::Instant::now() < deadline)
                    {
                        continue;
                    }
                    if session_state.hello_complete {
                        dump_ed2k_tcp_download_meta(
                            peer_addr,
                            Some(transport.mode),
                            "peer_timeout_incomplete",
                            format!("file_hash={file_hash_hex}"),
                        );
                        return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                    }
                    anyhow::bail!("timed out waiting for ED2K peer packet from {peer_addr}");
                }
            };
            dump_ed2k_tcp_download_recv(peer_addr, transport.mode, "session", &packet);

            match (packet.protocol, packet.opcode) {
                (OP_EDONKEYPROT, OP_HELLO) => {
                    let hello_profile = decode_hello_profile(&packet.payload)?;
                    for reply in build_hello_responses(&packet.payload, hello_identity)? {
                        dump_ed2k_tcp_download_send(peer_addr, transport.mode, "hello_reply", &reply);
                        transport.write_all(&reply).await.with_context(|| {
                            format!("failed to reply to OP_HELLO during download with {peer_addr}")
                        })?;
                    }
                    session_state.hello_complete = true;
                    session_state.remote_supports_file_identifiers = hello_profile.supports_file_identifiers;
                    session_state.remote_supports_source_exchange = hello_profile.supports_source_exchange;
                    session_state.remote_supports_source_exchange2 = hello_profile.supports_source_exchange2;
                    if hello_profile.is_mule_hello && !session_state.peer_secure_ident.requested_peer_key {
                        let secure_ident_probe = begin_secure_ident_probe(&mut session_state.peer_secure_ident);
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "secure_ident_probe",
                            &secure_ident_probe,
                        );
                        transport
                            .write_all(&secure_ident_probe)
                            .await
                            .with_context(|| {
                                format!("failed to send OP_SECIDENTSTATE to {peer_addr}")
                            })?;
                        session_state.secure_ident_started = true;
                    }
                }
                (OP_EDONKEYPROT, OP_HELLOANSWER) => {
                    let hello_profile = decode_hello_profile(&packet.payload)?;
                    session_state.hello_complete = true;
                    session_state.remote_supports_file_identifiers = hello_profile.supports_file_identifiers;
                    session_state.remote_supports_source_exchange = hello_profile.supports_source_exchange;
                    session_state.remote_supports_source_exchange2 = hello_profile.supports_source_exchange2;
                    if send_initial_requests
                        && hello_profile.is_mule_hello
                        && !session_state.peer_secure_ident.requested_peer_key
                    {
                        let secure_ident_probe = begin_secure_ident_probe(&mut session_state.peer_secure_ident);
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "secure_ident_probe",
                            &secure_ident_probe,
                        );
                        transport
                            .write_all(&secure_ident_probe)
                            .await
                            .with_context(|| {
                                format!("failed to send OP_SECIDENTSTATE to {peer_addr}")
                            })?;
                        session_state.secure_ident_started = true;
                    }
                }
                (OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ) => {
                    session_state.upload_accepted = true;
                    session_state.upload_accepted_at.get_or_insert_with(tokio::time::Instant::now);
                    session_state.queued_until = None;
                }
                (OP_EMULEPROT, OP_EMULEINFO) => {
                    transport
                        .write_all(&encode_emule_info_answer(hello_identity.udp_port))
                        .await
                        .with_context(|| {
                            format!("failed to send OP_EMULEINFOANSWER to {peer_addr}")
                        })?;
                }
                (OP_EMULEPROT, OP_EMULEINFOANSWER) => {}
                (OP_EMULEPROT, OP_SECIDENTSTATE) => {
                    let (state, challenge) = decode_secident_state(&packet.payload)?;
                    session_state.peer_secure_ident.peer_challenge_from = Some(challenge);
                    if state != 0 {
                        session_state.peer_secure_ident.pending_signature = true;
                    }
                    if state == ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED {
                        let public_key = encode_packet(
                            OP_EMULEPROT,
                            OP_PUBLICKEY,
                            &secure_ident.public_key_payload()?,
                        );
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "public_key",
                            &public_key,
                        );
                        transport.write_all(&public_key).await.with_context(|| {
                            format!("failed to send OP_PUBLICKEY to {peer_addr}")
                        })?;
                    }
                    if !try_send_secure_ident_signature(
                        transport,
                        peer_addr,
                        secure_ident,
                        &mut session_state.peer_secure_ident,
                    )
                    .await?
                        && state == ED2K_SECURE_IDENT_SIGNATURE_NEEDED
                        && !session_state.peer_secure_ident.requested_peer_key
                    {
                        let secure_ident_probe = begin_secure_ident_probe(&mut session_state.peer_secure_ident);
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "secure_ident_probe",
                            &secure_ident_probe,
                        );
                        transport
                            .write_all(&secure_ident_probe)
                            .await
                            .with_context(|| {
                                format!("failed to send fallback OP_SECIDENTSTATE to {peer_addr}")
                            })?;
                        session_state.secure_ident_started = true;
                    }
                }
                (OP_EMULEPROT, OP_PUBLICKEY) => {
                    session_state.peer_secure_ident.peer_public_key =
                        Some(decode_public_key_payload(&packet.payload)?);
                    let _ = try_send_secure_ident_signature(
                        transport,
                        peer_addr,
                        secure_ident,
                        &mut session_state.peer_secure_ident,
                    )
                    .await?;
                }
                (OP_EMULEPROT, OP_SIGNATURE) => {
                    session_state.peer_secure_ident.peer_signature_received = true;
                }
                (OP_EDONKEYPROT, OP_HASHSETANSWER) => {
                    let (returned_hash, hashset) = decode_hashset_answer(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "peer {peer_addr} returned hashset for unexpected file {}",
                            returned_hash
                        );
                    }
                    manifest = transfer_runtime
                        .store_md4_hashset(file_hash_hex, hashset)
                        .await?;
                }
                (OP_EMULEPROT, OP_HASHSETANSWER2) => {
                    let hashset_answer = decode_hashset_answer2(&packet.payload)?;
                    if !request_file_identifier
                        .matches_relaxed(&hashset_answer.file_identifier)
                    {
                        anyhow::bail!(
                            "peer {peer_addr} returned OP_HASHSETANSWER2 for unexpected file {}",
                            hashset_answer.file_identifier.file_hash
                        );
                    }
                    reconcile_download_manifest_metadata(
                        transfer_runtime,
                        file_hash_hex,
                        &mut manifest,
                        &mut request_file_identifier,
                        &hashset_answer.file_identifier,
                        None,
                    )
                    .await?;
                    if let Some(hashset) = hashset_answer.md4_hashset {
                        manifest = transfer_runtime
                            .store_md4_hashset(file_hash_hex, hashset)
                            .await?;
                    }
                    if let Some(hashset) = hashset_answer.aich_hashset {
                        manifest = transfer_runtime
                            .store_aich_hashset(file_hash_hex, hashset)
                            .await?;
                        request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
                    }
                }
                (OP_EDONKEYPROT, OP_REQFILENAMEANSWER) => {
                    let (returned_hash, returned_file_name) =
                        decode_request_filename_answer(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "OP_REQFILENAMEANSWER hash mismatch {} expected {}",
                            returned_hash,
                            file_hash
                        );
                    }
                    manifest = transfer_runtime
                        .reconcile_job_metadata(
                            file_hash_hex,
                            Some(returned_file_name.as_str()),
                            None,
                        )
                        .await?;
                    request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
                    session_state.startup_file_response_received = true;
                }
                (OP_EDONKEYPROT, OP_FILESTATUS) => {
                    let (returned_hash, _part_count) = decode_file_status_payload(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "peer {peer_addr} returned file status for unexpected file {}",
                            returned_hash
                        );
                    }
                    session_state.startup_file_response_received = true;
                }
                (OP_EMULEPROT, OP_MULTIPACKETANSWER_EXT2) => {
                    let (returned_identifier, mut remaining) =
                        Ed2kFileIdentifier::decode(&packet.payload)?;
                    if !request_file_identifier.matches_relaxed(&returned_identifier) {
                        anyhow::bail!(
                            "peer {peer_addr} returned OP_MULTIPACKETANSWER_EXT2 for unexpected file {}",
                            returned_identifier.file_hash
                        );
                    }
                    let mut returned_file_name = None;
                    while let Some((&sub_opcode, rest)) = remaining.split_first() {
                        remaining = rest;
                        match sub_opcode {
                            OP_REQFILENAMEANSWER => {
                                let (file_name, rest) =
                                    decode_request_filename_answer_body(remaining)?;
                                remaining = rest;
                                returned_file_name = Some(file_name);
                            }
                            OP_FILESTATUS => {
                                let (_part_count, rest) = skip_file_status_body(remaining)?;
                                remaining = rest;
                            }
                            _ => {
                                anyhow::bail!(
                                    "unsupported OP_MULTIPACKETANSWER_EXT2 sub-op 0x{sub_opcode:02X}"
                                );
                            }
                        }
                    }
                    reconcile_download_manifest_metadata(
                        transfer_runtime,
                        file_hash_hex,
                        &mut manifest,
                        &mut request_file_identifier,
                        &returned_identifier,
                        returned_file_name.as_deref(),
                    )
                    .await?;
                    session_state.startup_file_response_received = true;
                }
                (OP_EMULEPROT, OP_AICHFILEHASHANS) => {
                    let (returned_hash, aich_root) = decode_aich_file_hash_answer(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "peer {peer_addr} returned AICH file hash for unexpected file {}",
                            returned_hash
                        );
                    }
                    manifest = transfer_runtime
                        .reconcile_aich_root(file_hash_hex, Some(aich_root))
                        .await?;
                    request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
                }
                (OP_EDONKEYPROT, OP_SETREQFILEID) => {
                    // Non-oracle peers sometimes echo the file id again instead of
                    // the expected file-status payload. Stay tolerant, but do not
                    // treat it as the startup gate that oracle-like peers rely on.
                }
                (OP_EMULEPROT, OP_ANSWERSOURCES2) => {
                    let (answer_hash, sources) = decode_answer_sources2_payload(&packet.payload)?;
                    if answer_hash == file_hash {
                        for source in sources {
                            if source.tcp_port == 0 || source.ip == [0, 0, 0, 0] {
                                continue;
                            }
                            transfer_runtime
                                .remember_source(
                                    file_hash_hex,
                                    Ed2kSourceHint {
                                        ip: Ipv4Addr::from(source.ip).to_string(),
                                        tcp_port: source.tcp_port,
                                        user_hash: source.user_hash.map(hex::encode),
                                    },
                                )
                                .await?;
                        }
                    }
                }
                (OP_EMULEPROT, OP_ANSWERSOURCES) => {
                    // Legacy SX1 replies need the peer's SX1 version to decode safely.
                    // SX2 replies carry their version in-band and are consumed above.
                }
                (OP_EMULEPROT, OP_QUEUERANKING) => {
                    session_state.queued_until = Some(tokio::time::Instant::now() + QUEUE_RANK_GRACE);
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "queue_ranking",
                        format!("file_hash={file_hash_hex}"),
                    );
                }
                (OP_EMULEPROT, OP_FILEDESC) => {
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "file_desc",
                        format!("file_hash={file_hash_hex}"),
                    );
                }
                (OP_EDONKEYPROT, OP_FILEREQANSNOFIL) => {
                    anyhow::bail!("peer {peer_addr} does not serve requested file {file_hash_hex}");
                }
                (OP_EDONKEYPROT, OP_SENDINGPART)
                | (OP_EMULEPROT, OP_SENDINGPART_I64)
                | (OP_EMULEPROT, OP_COMPRESSEDPART)
                | (OP_EMULEPROT, OP_COMPRESSEDPART_I64) => {
                    if let Some(outcome) = handle_download_part_packet(DownloadPartPacket {
                            transfer_runtime,
                            file_hash: &file_hash,
                            file_hash_hex,
                            pending_part_requests: &mut pending_part_requests,
                            pending_compressed_parts: &mut pending_compressed_parts,
                            manifest: &mut manifest,
                            session_state: &mut session_state,
                            peer_addr,
                            transport_mode: transport.mode,
                            packet: &packet,
                        })
                        .await?
                    {
                        return Ok(outcome);
                    }
                }
                _ => {}
            }
        }
    }
    .await;

    if matches!(
        &session_result,
        Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete)
    ) {
        flush_buffered_download_prefixes(
            transfer_runtime,
            file_hash_hex,
            &mut pending_part_requests,
            &mut session_state.active_piece_request,
            &mut manifest,
            peer_addr,
            transport.mode,
        )
        .await?;
    }

    if let Some(active_piece) = session_state.active_piece_request.or_else(|| {
        pending_part_requests
            .first()
            .map(|request| ActiveDownloadPiece {
                piece_index: request.piece_index,
                next_offset: request.end,
                piece_end: request.end,
            })
    }) {
        transfer_runtime
            .release_piece_request(file_hash_hex, active_piece.piece_index)
            .await?;
    }

    session_result
}
