use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result};
use tokio::{
    net::TcpStream,
    sync::{Mutex, RwLock},
};
use tracing::{debug, info};

use overlord_kad_dht::DhtNode;
use overlord_kad_proto::{Ed2kHash, FirewallUdp, KadPacket};

use crate::{
    ed2k_server::Ed2kServerState,
    ed2k_transfer::{
        Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadSessionHandle,
        Ed2kUploadSessionStatus,
    },
    kad_firewall::KadFirewallState,
};

use super::super::codec::{
    build_upload_part_packets, decode_file_hash_payload, decode_hashset_request2,
    decode_request_parts_payload, decode_request_sources_payload, encode_accept_upload_req,
    encode_answer_sources_empty, encode_answer_sources2_empty, encode_file_req_ans_nofil,
    encode_file_status_complete, encode_hashset_answer, encode_hashset_answer2,
    encode_multipacket_ext2_answer, encode_packet, encode_queue_ranking,
    encode_request_filename_answer, skip_request_filename_ext_info,
};
use super::super::download::{
    DownloadSessionOptions, Ed2kPeerDownloadOutcome, drive_download_session,
};
use super::super::dump::{
    dump_ed2k_tcp_listener_meta, dump_ed2k_tcp_listener_recv, dump_ed2k_tcp_listener_send,
};
use super::super::hello::{
    DecodedHelloIdentity, build_hello_responses, decode_hello_profile, encode_emule_info_answer,
};
use super::super::identity::{
    Ed2kPeerSecureIdentState, begin_secure_ident_probe, decode_public_key_payload,
    decode_secident_state, encode_secident_state, random_nonzero_u32,
    try_send_secure_ident_signature,
};
use super::super::{
    ED2K_CONNECTION_IDLE_TIMEOUT, ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
    ED2K_SECURE_IDENT_SIGNATURE_NEEDED, ED2K_SOURCE_EXCHANGE2_VERSION,
    ED2K_UPLOAD_QUEUE_POLL_INTERVAL, ED2K_UPLOAD_QUEUE_REFRESH_INTERVAL, Ed2kFileIdentifier,
    Ed2kHelloIdentity, Ed2kSecureIdent, Ed2kTransport, FirewallCheckUdpRequest, OP_AICHFILEHASHREQ,
    OP_CANCELTRANSFER, OP_EDONKEYPROT, OP_EMULEINFO, OP_EMULEINFOANSWER, OP_EMULEPROT,
    OP_FWCHECKUDPREQ, OP_HASHSETREQUEST, OP_HASHSETREQUEST2, OP_HELLO, OP_HELLOANSWER,
    OP_MULTIPACKET_EXT2, OP_PUBLICKEY, OP_REQUESTFILENAME, OP_REQUESTPARTS, OP_REQUESTPARTS_I64,
    OP_REQUESTSOURCES, OP_REQUESTSOURCES2, OP_SECIDENTSTATE, OP_SETREQFILEID, OP_SIGNATURE,
    OP_STARTUPLOADREQ, apply_server_state,
};

pub(in crate::ed2k_tcp) struct Ed2kConnectionContext<'a> {
    pub(in crate::ed2k_tcp) dht: &'a DhtNode,
    pub(in crate::ed2k_tcp) server_state: &'a Arc<RwLock<Ed2kServerState>>,
    pub(in crate::ed2k_tcp) kad_firewall: &'a Arc<Mutex<KadFirewallState>>,
    pub(in crate::ed2k_tcp) secure_ident: &'a Arc<Ed2kSecureIdent>,
    pub(in crate::ed2k_tcp) transfer_runtime: &'a Arc<Ed2kTransferRuntime>,
    pub(in crate::ed2k_tcp) hello_identity: Ed2kHelloIdentity,
}

pub(in crate::ed2k_tcp) async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    context: Ed2kConnectionContext<'_>,
) -> Result<()> {
    let Ed2kConnectionContext {
        dht,
        server_state,
        kad_firewall,
        secure_ident,
        transfer_runtime,
        hello_identity,
    } = context;
    let local_addr = stream.local_addr().with_context(|| {
        format!("failed to resolve local eD2k listener address for {peer_addr}")
    })?;
    dump_ed2k_tcp_listener_meta(
        peer_addr,
        None,
        "tcp_accept",
        format!("local_addr={local_addr}"),
    );
    let kad_udp_port = dht
        .bind_addr()
        .context("failed to resolve Kad bind address for eD2k hello response")?
        .port();
    let response_identity = Ed2kHelloIdentity {
        udp_port: kad_udp_port,
        ..hello_identity
    };
    let response_identity =
        enrich_hello_identity(response_identity, server_state, kad_firewall).await;
    let mut transport = match tokio::time::timeout(
        ED2K_CONNECTION_IDLE_TIMEOUT,
        Ed2kTransport::accept(stream, hello_identity.user_hash),
    )
    .await
    {
        Ok(Ok(transport)) => transport,
        Ok(Err(error)) => {
            dump_ed2k_tcp_listener_meta(
                peer_addr,
                None,
                "accept_failed",
                format!("local_addr={local_addr} error={error:#}"),
            );
            return Err(error).with_context(|| {
                format!("failed to accept inbound eD2k peer transport from {peer_addr}")
            });
        }
        Err(_) => {
            dump_ed2k_tcp_listener_meta(
                peer_addr,
                None,
                "accept_timeout",
                format!(
                    "local_addr={local_addr} idle_timeout_secs={}",
                    ED2K_CONNECTION_IDLE_TIMEOUT.as_secs()
                ),
            );
            anyhow::bail!("timed out waiting for initial eD2k peer bytes");
        }
    };
    transport
        .stream
        .set_nodelay(true)
        .with_context(|| format!("failed to enable TCP_NODELAY for inbound peer {peer_addr}"))?;
    debug!(
        "accepted eD2k TCP peer from {peer_addr} transport={}",
        transport.mode.as_str()
    );
    dump_ed2k_tcp_listener_meta(
        peer_addr,
        Some(transport.mode),
        "accept",
        format!("udp_port={kad_udp_port}"),
    );
    let mut peer_secure_ident = Ed2kPeerSecureIdentState::default();
    let mut requested_file_hash: Option<Ed2kHash> = None;
    let mut peer_upload_identity = upload_peer_identity_from_socket(peer_addr);
    let mut upload_session: Option<Ed2kUploadSessionHandle> = None;
    let mut upload_session_file_hash: Option<Ed2kHash> = None;
    let mut upload_granted_sent = false;
    let mut last_queue_rank = None;
    let mut last_queue_rank_sent_at = None;

    let result = loop {
        let read_timeout = if upload_session.is_some() {
            ED2K_UPLOAD_QUEUE_POLL_INTERVAL
        } else {
            ED2K_CONNECTION_IDLE_TIMEOUT
        };
        let packet = match tokio::time::timeout(read_timeout, transport.read_packet()).await {
            Ok(packet) => {
                packet.with_context(|| format!("failed to read eD2k packet from {peer_addr}"))?
            }
            Err(_) => {
                let Some(upload_session_handle) = upload_session.as_ref() else {
                    break Ok(());
                };
                match transfer_runtime
                    .poll_upload_session(upload_session_handle, true)
                    .await
                {
                    Ed2kUploadSessionStatus::Granted => {
                        if !upload_granted_sent {
                            let reply = encode_accept_upload_req();
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "accept_upload",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send OP_ACCEPTUPLOADREQ to {peer_addr}")
                            })?;
                            upload_granted_sent = true;
                            last_queue_rank = None;
                            last_queue_rank_sent_at = None;
                        }
                        continue;
                    }
                    Ed2kUploadSessionStatus::Waiting { rank } => {
                        let now = tokio::time::Instant::now();
                        let should_refresh = last_queue_rank != Some(rank)
                            || last_queue_rank_sent_at.is_none_or(|sent_at| {
                                now.duration_since(sent_at) >= ED2K_UPLOAD_QUEUE_REFRESH_INTERVAL
                            });
                        if should_refresh {
                            let reply = encode_queue_ranking(rank);
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "queue_ranking",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send OP_QUEUERANKING to {peer_addr}")
                            })?;
                            last_queue_rank = Some(rank);
                            last_queue_rank_sent_at = Some(now);
                        }
                        continue;
                    }
                    Ed2kUploadSessionStatus::Stale => break Ok(()),
                }
            }
        };
        let Some(packet) = packet else {
            break Ok(());
        };
        dump_ed2k_tcp_listener_recv(peer_addr, transport.mode, "session", &packet);

        match (packet.protocol, packet.opcode) {
            (OP_EDONKEYPROT, OP_HELLO) => {
                let hello_profile = decode_hello_profile(&packet.payload)?;
                peer_upload_identity =
                    upload_peer_identity_from_hello(peer_addr, &hello_profile.identity);
                debug!(
                    "received eD2k OP_HELLO from {peer_addr} transport={} mule_hello={}",
                    transport.mode.as_str(),
                    hello_profile.is_mule_hello,
                );
                for reply in build_hello_responses(&packet.payload, response_identity)? {
                    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "hello_reply", &reply);
                    transport
                        .write_all(&reply)
                        .await
                        .with_context(|| format!("failed to reply to OP_HELLO from {peer_addr}"))?;
                }
                if hello_profile.is_mule_hello && !peer_secure_ident.requested_peer_key {
                    let request = begin_secure_ident_probe(&mut peer_secure_ident);
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "secure_ident_probe",
                        &request,
                    );
                    transport.write_all(&request).await.with_context(|| {
                        format!("failed to send OP_SECIDENTSTATE to {peer_addr}")
                    })?;
                }
                if let Some(callback_intent) = transfer_runtime
                    .claim_callback_intent(hello_profile.identity.client_id)
                    .await
                {
                    let file_hash =
                        Ed2kHash::from_str(&callback_intent.file_hash).with_context(|| {
                            format!(
                                "invalid callback file hash {} for client_id={}",
                                callback_intent.file_hash, callback_intent.client_id
                            )
                        })?;
                    info!(
                        "claimed inbound ED2K callback download file_hash={} client_id={} peer={peer_addr}",
                        callback_intent.file_hash, callback_intent.client_id
                    );
                    match drive_download_session(DownloadSessionOptions {
                        transport: &mut transport,
                        peer_addr,
                        hello_identity: response_identity,
                        secure_ident: secure_ident.as_ref(),
                        transfer_runtime,
                        file_hash,
                        file_hash_hex: &callback_intent.file_hash,
                        timeout: ED2K_CONNECTION_IDLE_TIMEOUT,
                        send_initial_requests: true,
                        initial_hello_complete: true,
                        initial_secure_ident_started: true,
                    })
                    .await?
                    {
                        Ed2kPeerDownloadOutcome::Completed => break Ok(()),
                        Ed2kPeerDownloadOutcome::AcceptedButIncomplete => break Ok(()),
                    }
                }
            }
            (OP_EDONKEYPROT, OP_HELLOANSWER) => {
                debug!(
                    "received eD2k OP_HELLOANSWER from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
            }
            (OP_EMULEPROT, OP_MULTIPACKET_EXT2) => {
                let (requested_identifier, mut remaining) =
                    Ed2kFileIdentifier::decode(&packet.payload)?;
                let requested = requested_identifier.file_hash;
                requested_file_hash = Some(requested);
                let Some(shared) = transfer_runtime.local_entry(&requested).await? else {
                    let reply = encode_file_req_ans_nofil(&requested);
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "multipacket_ext2_nofil",
                        &reply,
                    );
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_FILEREQANSNOFIL to {peer_addr}")
                    })?;
                    continue;
                };
                let shared_identifier = Ed2kFileIdentifier::from_shared_entry(&shared)?;
                if !shared_identifier.matches_relaxed(&requested_identifier) {
                    let reply = encode_file_req_ans_nofil(&requested);
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "multipacket_ext2_mismatch",
                        &reply,
                    );
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_FILEREQANSNOFIL to {peer_addr}")
                    })?;
                    continue;
                }

                let mut include_filename_answer = false;
                let mut include_file_status = false;
                while let Some((&sub_opcode, rest)) = remaining.split_first() {
                    remaining = rest;
                    match sub_opcode {
                        OP_REQUESTFILENAME => {
                            remaining =
                                skip_request_filename_ext_info(remaining, shared.file_size)?;
                            include_filename_answer = true;
                        }
                        OP_SETREQFILEID => {
                            include_file_status = true;
                        }
                        OP_REQUESTSOURCES => {
                            let reply = encode_answer_sources_empty(&requested);
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "answer_sources",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send source exchange reply to {peer_addr}")
                            })?;
                        }
                        OP_REQUESTSOURCES2 => {
                            if remaining.len() < 3 {
                                anyhow::bail!(
                                    "short OP_REQUESTSOURCES2 sub-payload in OP_MULTIPACKET_EXT2"
                                );
                            }
                            let requested_version = remaining[0];
                            remaining = &remaining[3..];
                            let reply = encode_answer_sources2_empty(
                                &requested,
                                requested_version.max(ED2K_SOURCE_EXCHANGE2_VERSION),
                            );
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "answer_sources",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send source exchange reply to {peer_addr}")
                            })?;
                        }
                        OP_AICHFILEHASHREQ => {}
                        _ => {
                            anyhow::bail!(
                                "unsupported OP_MULTIPACKET_EXT2 sub-op 0x{sub_opcode:02X}"
                            );
                        }
                    }
                }

                if include_filename_answer || include_file_status {
                    let reply = encode_multipacket_ext2_answer(
                        &shared_identifier,
                        &shared.canonical_name,
                        include_filename_answer,
                        include_file_status,
                    )?;
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "multipacket_ext2_answer",
                        &reply,
                    );
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_MULTIPACKETANSWER_EXT2 to {peer_addr}")
                    })?;
                }
            }
            (OP_EDONKEYPROT, OP_REQUESTFILENAME) => {
                let requested = decode_file_hash_payload(&packet.payload)?;
                let reply = if let Some(shared) = transfer_runtime.local_entry(&requested).await? {
                    requested_file_hash = Some(requested);
                    encode_request_filename_answer(&requested, &shared.canonical_name)?
                } else {
                    encode_file_req_ans_nofil(&requested)
                };
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "request_filename", &reply);
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to send OP_REQFILENAMEANSWER to {peer_addr}")
                })?;
            }
            (OP_EDONKEYPROT, OP_SETREQFILEID) => {
                let requested = decode_file_hash_payload(&packet.payload)?;
                requested_file_hash = Some(requested);
                let reply = if transfer_runtime.local_entry(&requested).await?.is_some() {
                    encode_file_status_complete(&requested)
                } else {
                    encode_file_req_ans_nofil(&requested)
                };
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "set_req_file_id", &reply);
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to send OP_SETREQFILEID response to {peer_addr}")
                })?;
            }
            (OP_EDONKEYPROT, OP_STARTUPLOADREQ) => {
                let requested = decode_file_hash_payload(&packet.payload)?;
                requested_file_hash = Some(requested);
                let reply = if transfer_runtime.local_entry(&requested).await?.is_some() {
                    let status = if upload_session_file_hash == Some(requested) {
                        match upload_session.as_ref() {
                            Some(upload_session_handle) => {
                                transfer_runtime
                                    .poll_upload_session(upload_session_handle, true)
                                    .await
                            }
                            None => Ed2kUploadSessionStatus::Stale,
                        }
                    } else {
                        let (session_handle, status) = transfer_runtime
                            .begin_upload_session(peer_upload_identity.clone(), &requested)
                            .await;
                        upload_session = Some(session_handle);
                        upload_session_file_hash = Some(requested);
                        status
                    };
                    match status {
                        Ed2kUploadSessionStatus::Granted => {
                            upload_granted_sent = true;
                            last_queue_rank = None;
                            last_queue_rank_sent_at = None;
                            encode_accept_upload_req()
                        }
                        Ed2kUploadSessionStatus::Waiting { rank } => {
                            upload_granted_sent = false;
                            last_queue_rank = Some(rank);
                            last_queue_rank_sent_at = Some(tokio::time::Instant::now());
                            encode_queue_ranking(rank)
                        }
                        Ed2kUploadSessionStatus::Stale => {
                            upload_granted_sent = false;
                            last_queue_rank = Some(1);
                            last_queue_rank_sent_at = Some(tokio::time::Instant::now());
                            encode_queue_ranking(1)
                        }
                    }
                } else {
                    encode_file_req_ans_nofil(&requested)
                };
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "start_upload", &reply);
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to send OP_STARTUPLOADREQ response to {peer_addr}")
                })?;
            }
            (OP_EDONKEYPROT, OP_CANCELTRANSFER) => {
                if let Some(upload_session_handle) = upload_session.as_ref() {
                    transfer_runtime
                        .release_upload_session(upload_session_handle)
                        .await;
                }
                upload_session = None;
                break Ok(());
            }
            (OP_EDONKEYPROT, OP_HASHSETREQUEST) => {
                let requested = decode_file_hash_payload(&packet.payload)?;
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
            }
            (OP_EMULEPROT, OP_HASHSETREQUEST2) => {
                let (requested_identifier, request_options) =
                    decode_hashset_request2(&packet.payload)?;
                let requested = requested_identifier.file_hash;
                requested_file_hash = Some(requested);
                if !request_options.has_known_request() {
                    continue;
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
            }
            (OP_EMULEPROT, OP_REQUESTSOURCES) | (OP_EMULEPROT, OP_REQUESTSOURCES2) => {
                let (requested, requested_version) =
                    decode_request_sources_payload(packet.opcode, &packet.payload)?;
                requested_file_hash = Some(requested);
                if transfer_runtime.local_entry(&requested).await?.is_some() {
                    let reply = if packet.opcode == OP_REQUESTSOURCES2 {
                        encode_answer_sources2_empty(
                            &requested,
                            requested_version.max(ED2K_SOURCE_EXCHANGE2_VERSION),
                        )
                    } else {
                        encode_answer_sources_empty(&requested)
                    };
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "answer_sources",
                        &reply,
                    );
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send source exchange reply to {peer_addr}")
                    })?;
                }
            }
            (OP_EMULEPROT, OP_AICHFILEHASHREQ) => {
                let requested = decode_file_hash_payload(&packet.payload)?;
                requested_file_hash = Some(requested);
                if transfer_runtime.local_entry(&requested).await?.is_some() {
                    // Keep the legacy AICH probe from tearing down the upload
                    // session even when we do not currently expose an AICH tree.
                }
            }
            (OP_EDONKEYPROT, OP_REQUESTPARTS) | (OP_EMULEPROT, OP_REQUESTPARTS_I64) => {
                let is_i64 = packet.opcode == OP_REQUESTPARTS_I64;
                let (requested, ranges) = decode_request_parts_payload(&packet.payload, is_i64)?;
                requested_file_hash = Some(requested);
                let Some(shared) = transfer_runtime.local_entry(&requested).await? else {
                    let reply = encode_file_req_ans_nofil(&requested);
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "request_parts_nofil",
                        &reply,
                    );
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_FILEREQANSNOFIL to {peer_addr}")
                    })?;
                    continue;
                };

                if upload_session_file_hash != Some(requested) {
                    let (session_handle, status) = transfer_runtime
                        .begin_upload_session(peer_upload_identity.clone(), &requested)
                        .await;
                    upload_session = Some(session_handle);
                    upload_session_file_hash = Some(requested);
                    upload_granted_sent = false;
                    match status {
                        Ed2kUploadSessionStatus::Granted => {
                            let reply = encode_accept_upload_req();
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "accept_upload",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send OP_ACCEPTUPLOADREQ to {peer_addr}")
                            })?;
                            upload_granted_sent = true;
                            last_queue_rank = None;
                            last_queue_rank_sent_at = None;
                        }
                        Ed2kUploadSessionStatus::Waiting { rank } => {
                            let reply = encode_queue_ranking(rank);
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "queue_ranking",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send OP_QUEUERANKING to {peer_addr}")
                            })?;
                            last_queue_rank = Some(rank);
                            last_queue_rank_sent_at = Some(tokio::time::Instant::now());
                            continue;
                        }
                        Ed2kUploadSessionStatus::Stale => continue,
                    }
                }

                let Some(upload_session_handle) = upload_session.as_ref() else {
                    continue;
                };
                match transfer_runtime
                    .note_upload_request_parts(upload_session_handle)
                    .await
                {
                    Ed2kUploadSessionStatus::Granted => {
                        if !upload_granted_sent {
                            let reply = encode_accept_upload_req();
                            dump_ed2k_tcp_listener_send(
                                peer_addr,
                                transport.mode,
                                "accept_upload",
                                &reply,
                            );
                            transport.write_all(&reply).await.with_context(|| {
                                format!("failed to send OP_ACCEPTUPLOADREQ to {peer_addr}")
                            })?;
                            upload_granted_sent = true;
                        }
                        last_queue_rank = None;
                        last_queue_rank_sent_at = None;
                    }
                    Ed2kUploadSessionStatus::Waiting { rank } => {
                        let reply = encode_queue_ranking(rank);
                        dump_ed2k_tcp_listener_send(
                            peer_addr,
                            transport.mode,
                            "queue_ranking",
                            &reply,
                        );
                        transport.write_all(&reply).await.with_context(|| {
                            format!("failed to send OP_QUEUERANKING to {peer_addr}")
                        })?;
                        last_queue_rank = Some(rank);
                        last_queue_rank_sent_at = Some(tokio::time::Instant::now());
                        continue;
                    }
                    Ed2kUploadSessionStatus::Stale => break Ok(()),
                }
                for (start, end) in ranges {
                    let Some(bytes) = transfer_runtime
                        .read_verified_range(&requested, start, end)
                        .await?
                    else {
                        continue;
                    };
                    for reply in build_upload_part_packets(
                        &requested,
                        &shared.canonical_name,
                        start,
                        end,
                        &bytes,
                        is_i64,
                    )? {
                        dump_ed2k_tcp_listener_send(
                            peer_addr,
                            transport.mode,
                            reply.phase,
                            &reply.packet,
                        );
                        transport.write_all(&reply.packet).await.with_context(|| {
                            format!("failed to send ED2K upload payload to {peer_addr}")
                        })?;
                    }
                }
            }
            (OP_EMULEPROT, OP_EMULEINFO) => {
                debug!(
                    "received eMule OP_EMULEINFO from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
                let reply = encode_emule_info_answer(kad_udp_port);
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "emule_info_answer", &reply);
                transport
                    .write_all(&reply)
                    .await
                    .with_context(|| format!("failed to send OP_EMULEINFOANSWER to {peer_addr}"))?;
            }
            (OP_EMULEPROT, OP_EMULEINFOANSWER) => {
                debug!(
                    "received eMule OP_EMULEINFOANSWER from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
            }
            (OP_EMULEPROT, OP_SECIDENTSTATE) => {
                let (state, challenge) = decode_secident_state(&packet.payload)?;
                debug!(
                    "received eMule OP_SECIDENTSTATE from {peer_addr} transport={} state={} challenge={challenge}",
                    transport.mode.as_str(),
                    state
                );
                peer_secure_ident.peer_challenge_from = Some(challenge);
                if state != 0 {
                    peer_secure_ident.pending_signature = true;
                }
                if state == ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED {
                    let public_key = encode_packet(
                        OP_EMULEPROT,
                        OP_PUBLICKEY,
                        &secure_ident.public_key_payload()?,
                    );
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "public_key",
                        &public_key,
                    );
                    transport
                        .write_all(&public_key)
                        .await
                        .with_context(|| format!("failed to send OP_PUBLICKEY to {peer_addr}"))?;
                }
                if !try_send_secure_ident_signature(
                    &mut transport,
                    peer_addr,
                    secure_ident,
                    &mut peer_secure_ident,
                )
                .await?
                    && state == ED2K_SECURE_IDENT_SIGNATURE_NEEDED
                    && !peer_secure_ident.requested_peer_key
                {
                    let challenge_for = random_nonzero_u32();
                    peer_secure_ident.challenge_for = Some(challenge_for);
                    peer_secure_ident.pending_signature = true;
                    peer_secure_ident.requested_peer_key = true;
                    let request = encode_secident_state(
                        ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                        challenge_for,
                    );
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "secure_ident_probe",
                        &request,
                    );
                    transport.write_all(&request).await.with_context(|| {
                        format!("failed to send fallback OP_SECIDENTSTATE to {peer_addr}")
                    })?;
                }
            }
            (OP_EMULEPROT, OP_PUBLICKEY) => {
                peer_secure_ident.peer_public_key =
                    Some(decode_public_key_payload(&packet.payload)?);
                debug!(
                    "received eMule OP_PUBLICKEY from {peer_addr} transport={} key_len={}",
                    transport.mode.as_str(),
                    peer_secure_ident
                        .peer_public_key
                        .as_ref()
                        .map_or(0, Vec::len)
                );
                let _ = try_send_secure_ident_signature(
                    &mut transport,
                    peer_addr,
                    secure_ident,
                    &mut peer_secure_ident,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_SIGNATURE) => {
                debug!(
                    "received eMule OP_SIGNATURE from {peer_addr} transport={} payload_len={}",
                    transport.mode.as_str(),
                    packet.payload.len()
                );
            }
            (OP_EMULEPROT, OP_FWCHECKUDPREQ) => {
                debug!(
                    "received eMule OP_FWCHECKUDPREQ from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
                let request = FirewallCheckUdpRequest::decode(&packet.payload)?;
                dump_ed2k_tcp_listener_meta(
                    peer_addr,
                    Some(transport.mode),
                    "fwcheck_request",
                    format!(
                        "internal_udp_port={} external_udp_port={} sender_udp_key={}",
                        request.internal_udp_port,
                        request.external_udp_port,
                        request.sender_udp_key
                    ),
                );
                reply_with_firewall_udp(dht, peer_addr.ip(), request).await?;
            }
            _ => {
                if let Some(requested_file_hash) = requested_file_hash {
                    debug!(
                        "closing eD2k connection from {peer_addr}: unsupported protocol=0x{:02X} opcode=0x{:02X} requested_file_hash={requested_file_hash}",
                        packet.protocol, packet.opcode
                    );
                    break Ok(());
                }
                debug!(
                    "closing eD2k connection from {peer_addr}: unsupported protocol=0x{:02X} opcode=0x{:02X}",
                    packet.protocol, packet.opcode
                );
                break Ok(());
            }
        }
    };

    if let Some(upload_session_handle) = upload_session.as_ref() {
        transfer_runtime
            .release_upload_session(upload_session_handle)
            .await;
    }
    result
}

fn upload_peer_identity_from_socket(peer_addr: SocketAddr) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        ip: peer_addr.ip(),
        tcp_port: peer_addr.port(),
        user_hash: None,
        client_id: None,
    }
}

fn upload_peer_identity_from_hello(
    peer_addr: SocketAddr,
    remote_hello: &DecodedHelloIdentity,
) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        ip: peer_addr.ip(),
        tcp_port: if remote_hello.tcp_port == 0 {
            peer_addr.port()
        } else {
            remote_hello.tcp_port
        },
        user_hash: Some(remote_hello.user_hash),
        client_id: Some(remote_hello.client_id),
    }
}

pub(crate) async fn reply_with_firewall_udp(
    dht: &DhtNode,
    peer_ip: IpAddr,
    request: FirewallCheckUdpRequest,
) -> Result<()> {
    let ports = if request.external_udp_port != 0
        && request.external_udp_port != request.internal_udp_port
    {
        vec![request.internal_udp_port, request.external_udp_port]
    } else {
        vec![request.internal_udp_port]
    };

    let error_code = match peer_ip {
        IpAddr::V4(ip) => {
            if dht
                .routing_contacts()
                .await
                .iter()
                .any(|contact| contact.ip == ip)
            {
                1u8
            } else {
                0u8
            }
        }
        IpAddr::V6(_) => 1,
    };

    for port in ports.into_iter().filter(|port| *port != 0) {
        let target = SocketAddr::new(peer_ip, port);
        if request.sender_udp_key != 0 {
            dht.register_peer_key(target, request.sender_udp_key);
        }
        dht.send_packet(
            target,
            &KadPacket::FirewallUdp(FirewallUdp {
                error_code,
                udp_port: port,
            }),
        )
        .await
        .with_context(|| format!("failed to send KADEMLIA2_FIREWALLUDP to {target}"))?;
    }
    Ok(())
}

async fn enrich_hello_identity(
    identity: Ed2kHelloIdentity,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
) -> Ed2kHelloIdentity {
    let mut identity = {
        let state = server_state.read().await;
        apply_server_state(identity, &state)
    };
    let firewall = kad_firewall.lock().await;
    identity.direct_udp_callback = identity.client_id != 0
        && identity.client_id < 0x0100_0000
        && firewall.udp_verified
        && firewall.udp_open;
    identity
}
