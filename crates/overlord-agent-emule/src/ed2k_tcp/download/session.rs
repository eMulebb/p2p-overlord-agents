use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use flate2::Decompress;
use overlord_kad_proto::Ed2kHash;

use crate::ed2k_transfer::{ED2K_PART_SIZE, Ed2kTransferRuntime};

use super::super::{
    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, ED2K_SECURE_IDENT_SIGNATURE_NEEDED,
    Ed2kFileIdentifier, Ed2kHashsetRequestOptions, Ed2kHelloIdentity, Ed2kSecureIdent,
    Ed2kTransport, OP_ACCEPTUPLOADREQ, OP_AICHFILEHASHANS, OP_ANSWERSOURCES, OP_ANSWERSOURCES2,
    OP_COMPRESSEDPART, OP_COMPRESSEDPART_I64, OP_EDONKEYPROT, OP_EMULEINFO, OP_EMULEINFOANSWER,
    OP_EMULEPROT, OP_FILEDESC, OP_FILEREQANSNOFIL, OP_FILESTATUS, OP_HASHSETANSWER,
    OP_HASHSETANSWER2, OP_HELLO, OP_HELLOANSWER, OP_MULTIPACKETANSWER_EXT2, OP_PUBLICKEY,
    OP_QUEUERANKING, OP_REQFILENAMEANSWER, OP_SECIDENTSTATE, OP_SENDINGPART, OP_SENDINGPART_I64,
    OP_SETREQFILEID, OP_SIGNATURE, begin_secure_ident_probe, build_hello_responses,
    decode_aich_file_hash_answer, decode_compressed_part_fragment, decode_file_status_payload,
    decode_hashset_answer, decode_hashset_answer2, decode_hello_profile, decode_public_key_payload,
    decode_request_filename_answer, decode_request_filename_answer_body, decode_secident_state,
    decode_sending_part_payload, dump_ed2k_tcp_download_meta, dump_ed2k_tcp_download_recv,
    dump_ed2k_tcp_download_send, encode_aich_file_hash_request, encode_emule_info_answer,
    encode_hashset_request, encode_hashset_request2, encode_multipacket_ext2_request,
    encode_packet, encode_request_filename, encode_request_sources2, encode_set_req_file_id,
    encode_start_upload_req, inflate_compressed_part_fragment, is_connection_shutdown_error,
    skip_file_status_body, try_send_secure_ident_signature,
};
use super::{
    ActiveDownloadPiece, DownloadRequestWindowState, PendingCompressedPart, PendingPartRequest,
    ReadyDownloadBlocks, flush_buffered_download_prefixes, flush_ready_download_blocks,
    next_download_read_timeout, pump_download_request_window, reconcile_download_manifest_metadata,
};
mod state;

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
        initial_hello_complete,
        initial_secure_ident_started,
    } = options;
    const HASHSET_STALL_UPLOAD_FALLBACK: Duration = Duration::from_millis(500);
    const QUEUE_RANK_GRACE: Duration = Duration::from_secs(20);
    const PART_RESPONSE_GRACE: Duration = Duration::from_secs(20);
    // eMule keeps a pending block scheduler that is broader than one live wire
    // request. We mirror that with one claimed piece, a queued-vs-unqueued
    // block list, and wire packets that carry up to three queued ranges.
    let mut pending_part_requests: Vec<PendingPartRequest> = Vec::new();
    let mut pending_compressed_parts: Vec<PendingCompressedPart> = Vec::new();
    let mut manifest = transfer_runtime.manifest(file_hash_hex).await?;
    let mut request_file_identifier = Ed2kFileIdentifier::from_manifest(&manifest)?;
    let mut session_state =
        DownloadSessionState::new(initial_hello_complete, initial_secure_ident_started);

    let session_result = async {
        loop {
            if manifest.completed {
                return Ok(Ed2kPeerDownloadOutcome::Completed);
            }

            let waiting_for_peer_secure_ident = session_state.secure_ident_started
                && (session_state.peer_secure_ident.peer_challenge_from.is_none()
                    || session_state.peer_secure_ident.pending_signature
                    || (session_state.peer_secure_ident.requested_peer_key
                        && session_state.peer_secure_ident.peer_public_key.is_none())
                    || (session_state.peer_secure_ident.challenge_for.is_some()
                        && !session_state.peer_secure_ident.peer_signature_received));

            if send_initial_requests && session_state.hello_complete && !session_state.secure_ident_started {
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
                    .with_context(|| format!("failed to send OP_SECIDENTSTATE to {peer_addr}"))?;
                session_state.secure_ident_started = true;
            }

            if send_initial_requests
                && session_state.hello_complete
                && !session_state.startup_file_requests_sent
                && !waiting_for_peer_secure_ident
            {
                if session_state.remote_supports_file_identifiers {
                    let multipacket_ext2 =
                        encode_multipacket_ext2_request(&request_file_identifier, &manifest);
                    dump_ed2k_tcp_download_send(
                        peer_addr,
                        transport.mode,
                        "multipacket_ext2_request",
                        &multipacket_ext2,
                    );
                    transport
                        .write_all(&multipacket_ext2)
                        .await
                        .with_context(|| {
                            format!("failed to send OP_MULTIPACKET_EXT2 to {peer_addr}")
                        })?;
                    session_state.source_request_sent = true;
                    session_state.aich_file_hash_requested = true;
                } else {
                    let request_filename = encode_request_filename(&file_hash, &manifest);
                    dump_ed2k_tcp_download_send(
                        peer_addr,
                        transport.mode,
                        "request_filename",
                        &request_filename,
                    );
                    transport
                        .write_all(&request_filename)
                        .await
                        .with_context(|| {
                            format!("failed to send OP_REQUESTFILENAME to {peer_addr}")
                        })?;

                    if manifest.file_size > ED2K_PART_SIZE {
                        let set_req_file_id = encode_set_req_file_id(&file_hash);
                        dump_ed2k_tcp_download_send(
                            peer_addr,
                            transport.mode,
                            "set_req_file_id",
                            &set_req_file_id,
                        );
                        transport
                            .write_all(&set_req_file_id)
                            .await
                            .with_context(|| {
                                format!("failed to send OP_SETREQFILEID to {peer_addr}")
                            })?;
                    }
                }
                session_state.startup_file_requests_sent = true;
            }

            if send_initial_requests
                && session_state.hello_complete
                && !session_state.source_request_sent
                && !waiting_for_peer_secure_ident
                && !session_state.remote_supports_file_identifiers
            {
                let source_request = encode_request_sources2(&file_hash);
                dump_ed2k_tcp_download_send(
                    peer_addr,
                    transport.mode,
                    "request_sources2",
                    &source_request,
                );
                transport
                    .write_all(&source_request)
                    .await
                    .with_context(|| {
                        format!("failed to send OP_REQUESTSOURCES2 to {peer_addr}")
                    })?;
                session_state.source_request_sent = true;
            }

            if send_initial_requests
                && session_state.hello_complete
                && !session_state.aich_file_hash_requested
                && !waiting_for_peer_secure_ident
                && !session_state.remote_supports_file_identifiers
            {
                let aich_file_hash_request = encode_aich_file_hash_request(&file_hash);
                dump_ed2k_tcp_download_send(
                    peer_addr,
                    transport.mode,
                    "aich_file_hash_request",
                    &aich_file_hash_request,
                );
                transport
                    .write_all(&aich_file_hash_request)
                    .await
                    .with_context(|| {
                        format!("failed to send OP_AICHFILEHASHREQ to {peer_addr}")
                    })?;
                session_state.aich_file_hash_requested = true;
            }

            if send_initial_requests
                && session_state.hello_complete
                && manifest.file_size != 0
                && !manifest.md4_hashset_acquired
                && !session_state.hashset_requested
                && !waiting_for_peer_secure_ident
                && session_state.startup_file_response_received
            {
                if manifest.file_size <= ED2K_PART_SIZE {
                    manifest = transfer_runtime
                        .store_md4_hashset(file_hash_hex, Vec::new())
                        .await?;
                } else {
                    let hashset_request = if session_state.remote_supports_file_identifiers {
                        encode_hashset_request2(
                            &request_file_identifier,
                            Ed2kHashsetRequestOptions {
                                request_md4: true,
                                request_aich: manifest.file_size > ED2K_PART_SIZE
                                    && request_file_identifier.aich_root.is_some(),
                            },
                        )?
                    } else {
                        encode_hashset_request(&file_hash)
                    };
                    dump_ed2k_tcp_download_send(
                        peer_addr,
                        transport.mode,
                        "hashset_request",
                        &hashset_request,
                    );
                    transport
                        .write_all(&hashset_request)
                        .await
                        .with_context(|| {
                            if session_state.remote_supports_file_identifiers {
                                format!("failed to send OP_HASHSETREQUEST2 to {peer_addr}")
                            } else {
                                format!("failed to send OP_HASHSETREQUEST to {peer_addr}")
                            }
                        })?;
                    session_state.hashset_requested = true;
                    session_state.hashset_requested_at = Some(tokio::time::Instant::now());
                }
            }

            let hashset_request_stalled = session_state.hashset_requested_at
                .is_some_and(|requested_at| requested_at.elapsed() >= HASHSET_STALL_UPLOAD_FALLBACK);
            if send_initial_requests
                && session_state.hello_complete
                && manifest.file_size != 0
                && (manifest.md4_hashset_acquired || hashset_request_stalled)
                && !session_state.upload_requested
                && !waiting_for_peer_secure_ident
                && session_state.startup_file_response_received
            {
                if hashset_request_stalled && !manifest.md4_hashset_acquired {
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "upload_request_hashset_fallback",
                        format!("file_hash={file_hash_hex}"),
                    );
                }
                let start_upload = encode_start_upload_req(&file_hash);
                dump_ed2k_tcp_download_send(
                    peer_addr,
                    transport.mode,
                    "start_upload",
                    &start_upload,
                );
                transport
                    .write_all(&start_upload)
                    .await
                    .with_context(|| format!("failed to send OP_STARTUPLOADREQ to {peer_addr}"))?;
                session_state.upload_requested = true;
            }

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
                && !waiting_for_peer_secure_ident
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
                    let returned_hash = decode_aich_file_hash_answer(&packet.payload)?;
                    if returned_hash != file_hash {
                        anyhow::bail!(
                            "peer {peer_addr} returned AICH file hash for unexpected file {}",
                            returned_hash
                        );
                    }
                }
                (OP_EDONKEYPROT, OP_SETREQFILEID) => {
                    // Non-oracle peers sometimes echo the file id again instead of
                    // the expected file-status payload. Stay tolerant, but do not
                    // treat it as the startup gate that oracle-like peers rely on.
                }
                (OP_EMULEPROT, OP_ANSWERSOURCES) | (OP_EMULEPROT, OP_ANSWERSOURCES2) => {
                    // Source-exchange replies are opportunistic parity traffic. The
                    // direct downloader does not consume them yet, but the oracle does
                    // emit the request during startup, so stay tolerant here.
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
                    let use_i64 = packet.opcode == OP_SENDINGPART_I64
                        || packet.opcode == OP_COMPRESSEDPART_I64;
                    if packet.opcode == OP_COMPRESSEDPART || packet.opcode == OP_COMPRESSEDPART_I64 {
                        let (returned_hash, start, advertised_compressed_len, compressed_fragment) =
                            decode_compressed_part_fragment(&packet.payload, use_i64)?;
                        if returned_hash != file_hash {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_part_hash",
                                format!(
                                    "expected_file_hash={file_hash_hex} returned_file_hash={returned_hash} start={start} compressed_len={advertised_compressed_len}"
                                ),
                            );
                            continue;
                        }
                        if !pending_part_requests.iter().any(|request| request.queued) {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_compressed_part_without_queued_request",
                                format!(
                                    "file_hash={file_hash_hex} start={start} compressed_len={advertised_compressed_len}"
                                ),
                            );
                            return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                        }
                        let Some(pending_index) = pending_part_requests.iter().position(
                            |request| request.queued && request.start == start && request.end > request.start,
                        ) else {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_compressed_part_range",
                                format!(
                                    "file_hash={file_hash_hex} start={start} compressed_len={advertised_compressed_len} pending={:?}",
                                    pending_part_requests
                                ),
                            );
                            return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                        };
                        let expected_request = pending_part_requests[pending_index].clone();
                        let expected_part = expected_request.piece_index;
                        let expected_start = expected_request.start;
                        let expected_end = expected_request.end;
                        let compressed_index = if let Some(index) = pending_compressed_parts
                            .iter()
                            .position(|pending| {
                                pending.piece_index == expected_part
                                    && pending.start == expected_start
                                    && pending.end == expected_end
                            })
                        {
                            let pending = &pending_compressed_parts[index];
                            if pending.advertised_compressed_len != advertised_compressed_len {
                                anyhow::bail!(
                                    "peer {peer_addr} changed compressed-part framing for piece {expected_part} start={}..{} advertised={} expected={}..{} advertised={}",
                                    pending.start,
                                    pending.end,
                                    pending.advertised_compressed_len,
                                    expected_start,
                                    expected_end,
                                    advertised_compressed_len
                                );
                            }
                            index
                        } else {
                            pending_compressed_parts.push(PendingCompressedPart {
                                piece_index: expected_part,
                                start: expected_start,
                                end: expected_end,
                                advertised_compressed_len,
                                compressed_received: 0,
                                uncompressed_written: 0,
                                inflater: Decompress::new(true),
                            });
                            pending_compressed_parts.len() - 1
                        };
                        let (bytes, finished) = {
                            let pending = &mut pending_compressed_parts[compressed_index];
                            inflate_compressed_part_fragment(pending, compressed_fragment)?
                        };
                        let stream_end = {
                            let pending = &pending_compressed_parts[compressed_index];
                            pending.start + pending.uncompressed_written
                        };
                        if !bytes.is_empty() {
                            let stream_start = stream_end
                                .checked_sub(u64::try_from(bytes.len()).unwrap_or(0))
                                .unwrap_or(start);
                            let expected_received_start =
                                pending_part_requests[pending_index].received_end;
                            if stream_start != expected_received_start {
                                dump_ed2k_tcp_download_meta(
                                    peer_addr,
                                    Some(transport.mode),
                                    "out_of_order_compressed_part_range",
                                    format!(
                                        "file_hash={file_hash_hex} piece_index={expected_part} expected_start={} start={stream_start} end={stream_end} pending={:?}",
                                        expected_received_start,
                                        pending_part_requests
                                    ),
                                );
                                return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                            }
                            pending_part_requests[pending_index]
                                .buffer_response_bytes(stream_start, stream_end, &bytes)?;
                        }
                        let piece_len = expected_end - expected_start;
                        let pending = &pending_compressed_parts[compressed_index];
                        if pending.uncompressed_written > piece_len {
                            anyhow::bail!(
                                "peer {peer_addr} decompressed beyond requested piece boundary for piece {expected_part}: wrote {} expected {}",
                                pending.uncompressed_written,
                                piece_len
                            );
                        }
                        if finished && pending.uncompressed_written != piece_len {
                            anyhow::bail!(
                                "peer {peer_addr} ended compressed stream early for piece {expected_part}: wrote {} expected {}",
                                pending.uncompressed_written,
                                piece_len
                            );
                        }
                        if pending.uncompressed_written == piece_len {
                            pending_compressed_parts.remove(compressed_index);
                        }
                        flush_ready_download_blocks(ReadyDownloadBlocks {
                            transfer_runtime,
                            file_hash_hex,
                            pending_part_requests: &mut pending_part_requests,
                            active_piece_request: &mut session_state.active_piece_request,
                            manifest: &mut manifest,
                            peer_addr,
                            transport_mode: transport.mode,
                            completed_block_count: &mut session_state.completed_block_count,
                            session_payload_down: &mut session_state.session_payload_down,
                            part_response_deadline: &mut session_state.part_response_deadline,
                        })
                        .await?;
                    } else {
                        let (returned_hash, start, end, bytes) =
                            decode_sending_part_payload(&packet.payload, use_i64)?;
                        if returned_hash != file_hash {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_part_hash",
                                format!(
                                    "expected_file_hash={file_hash_hex} returned_file_hash={returned_hash} start={start} end={end}"
                                ),
                            );
                            continue;
                        }
                        if !pending_part_requests.iter().any(|request| request.queued) {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_part_without_queued_request",
                                format!("file_hash={file_hash_hex} start={start} end={end}"),
                            );
                            return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                        }
                        let Some(pending_index) = pending_part_requests.iter().position(
                            |request| request.matches_uncompressed_fragment(start, end),
                        ) else {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_part_range",
                                format!(
                                    "file_hash={file_hash_hex} start={start} end={end} pending={:?}",
                                    pending_part_requests
                                ),
                            );
                            return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                        };
                        let expected_request = pending_part_requests[pending_index].clone();
                        let expected_start = expected_request.start;
                        if start < expected_start {
                            dump_ed2k_tcp_download_meta(
                                peer_addr,
                                Some(transport.mode),
                                "unexpected_part_fragment_start",
                                format!(
                                    "file_hash={file_hash_hex} expected_start={expected_start} start={start} end={end} pending={:?}",
                                    pending_part_requests
                                ),
                            );
                            return Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
                        }
                        pending_part_requests[pending_index]
                            .buffer_response_bytes(start, end, &bytes)?;
                        flush_ready_download_blocks(ReadyDownloadBlocks {
                            transfer_runtime,
                            file_hash_hex,
                            pending_part_requests: &mut pending_part_requests,
                            active_piece_request: &mut session_state.active_piece_request,
                            manifest: &mut manifest,
                            peer_addr,
                            transport_mode: transport.mode,
                            completed_block_count: &mut session_state.completed_block_count,
                            session_payload_down: &mut session_state.session_payload_down,
                            part_response_deadline: &mut session_state.part_response_deadline,
                        })
                        .await?;
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
