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
    ed2k_transfer::{Ed2kTransferRuntime, Ed2kUploadPeerIdentity},
    kad_firewall::KadFirewallState,
};

use super::super::codec::{
    decode_file_hash_payload, decode_public_ip_answer_payload, encode_file_req_ans_nofil,
    encode_packet, encode_public_ip_answer,
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
    ED2K_SECURE_IDENT_SIGNATURE_NEEDED, Ed2kHelloIdentity, Ed2kSecureIdent, Ed2kTransport,
    FirewallCheckUdpRequest, OP_AICHFILEHASHREQ, OP_CANCELTRANSFER, OP_EDONKEYPROT, OP_EMULEINFO,
    OP_EMULEINFOANSWER, OP_EMULEPROT, OP_FWCHECKUDPREQ, OP_HASHSETREQUEST, OP_HASHSETREQUEST2,
    OP_HELLO, OP_HELLOANSWER, OP_MULTIPACKET, OP_MULTIPACKET_EXT, OP_MULTIPACKET_EXT2,
    OP_PUBLICIP_ANSWER, OP_PUBLICIP_REQ, OP_PUBLICKEY, OP_REQUESTFILENAME, OP_REQUESTPARTS,
    OP_REQUESTPARTS_I64, OP_REQUESTSOURCES, OP_REQUESTSOURCES2, OP_SECIDENTSTATE, OP_SETREQFILEID,
    OP_SIGNATURE, OP_STARTUPLOADREQ, apply_server_state,
};

mod shared_file;
mod upload_payload;
mod upload_queue;

use shared_file::{
    handle_aich_file_hash_request, handle_hashset_request, handle_hashset_request2,
    handle_multipacket_ext2_request, handle_multipacket_request, handle_request_filename,
    handle_set_req_file_id, handle_source_request,
};
use upload_payload::{UploadPayloadOutcome, UploadPayloadRequest, serve_upload_payload};
use upload_queue::{ListenerQueuePoll, ListenerUploadQueue};

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
    let mut upload_queue = ListenerUploadQueue::new();

    let result = loop {
        let read_timeout = upload_queue.read_timeout();
        let packet = match tokio::time::timeout(read_timeout, transport.read_packet()).await {
            Ok(packet) => {
                packet.with_context(|| format!("failed to read eD2k packet from {peer_addr}"))?
            }
            Err(_) => match upload_queue
                .poll_on_timeout(transfer_runtime, &mut transport, peer_addr)
                .await?
            {
                ListenerQueuePoll::Continue => continue,
                ListenerQueuePoll::Close => break Ok(()),
            },
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
                        source_exchange_allowed: true,
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
            (OP_EMULEPROT, OP_MULTIPACKET) | (OP_EMULEPROT, OP_MULTIPACKET_EXT) => {
                requested_file_hash = handle_multipacket_request(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    packet.opcode,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_MULTIPACKET_EXT2) => {
                requested_file_hash = handle_multipacket_ext2_request(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EDONKEYPROT, OP_REQUESTFILENAME) => {
                requested_file_hash = handle_request_filename(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EDONKEYPROT, OP_SETREQFILEID) => {
                requested_file_hash = handle_set_req_file_id(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EDONKEYPROT, OP_STARTUPLOADREQ) => {
                let requested = decode_file_hash_payload(&packet.payload)?;
                requested_file_hash = Some(requested);
                let reply = if transfer_runtime.local_entry(&requested).await?.is_some() {
                    upload_queue
                        .start_upload_reply(
                            transfer_runtime,
                            peer_upload_identity.clone(),
                            &requested,
                        )
                        .await
                } else {
                    encode_file_req_ans_nofil(&requested)
                };
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "start_upload", &reply);
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to send OP_STARTUPLOADREQ response to {peer_addr}")
                })?;
            }
            (OP_EDONKEYPROT, OP_CANCELTRANSFER) => {
                upload_queue.release(transfer_runtime).await;
                break Ok(());
            }
            (OP_EDONKEYPROT, OP_HASHSETREQUEST) => {
                requested_file_hash = handle_hashset_request(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_HASHSETREQUEST2) => {
                requested_file_hash = handle_hashset_request2(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_REQUESTSOURCES) | (OP_EMULEPROT, OP_REQUESTSOURCES2) => {
                requested_file_hash = handle_source_request(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    packet.opcode,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EMULEPROT, OP_AICHFILEHASHREQ) => {
                requested_file_hash = handle_aich_file_hash_request(
                    transfer_runtime,
                    &mut transport,
                    peer_addr,
                    &packet.payload,
                )
                .await?;
            }
            (OP_EDONKEYPROT, OP_REQUESTPARTS) | (OP_EMULEPROT, OP_REQUESTPARTS_I64) => {
                match serve_upload_payload(UploadPayloadRequest {
                    transfer_runtime,
                    upload_queue: &mut upload_queue,
                    peer_upload_identity: peer_upload_identity.clone(),
                    transport: &mut transport,
                    peer_addr,
                    opcode: packet.opcode,
                    payload: &packet.payload,
                })
                .await?
                {
                    UploadPayloadOutcome::Continue { requested } => {
                        requested_file_hash = Some(requested);
                    }
                    UploadPayloadOutcome::Close => {
                        break Ok(());
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
            (OP_EMULEPROT, OP_PUBLICIP_REQ) => {
                debug!(
                    "received eMule OP_PUBLICIP_REQ from {peer_addr} transport={}",
                    transport.mode.as_str()
                );
                if let IpAddr::V4(peer_ip) = peer_addr.ip() {
                    let reply = encode_public_ip_answer(peer_ip);
                    dump_ed2k_tcp_listener_send(
                        peer_addr,
                        transport.mode,
                        "public_ip_answer",
                        &reply,
                    );
                    transport.write_all(&reply).await.with_context(|| {
                        format!("failed to send OP_PUBLICIP_ANSWER to {peer_addr}")
                    })?;
                }
            }
            (OP_EMULEPROT, OP_PUBLICIP_ANSWER) => {
                let public_ip = decode_public_ip_answer_payload(&packet.payload)?;
                dump_ed2k_tcp_listener_meta(
                    peer_addr,
                    Some(transport.mode),
                    "public_ip_answer",
                    format!("public_ip={public_ip}"),
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

    upload_queue.release(transfer_runtime).await;
    result
}

fn upload_peer_identity_from_socket(peer_addr: SocketAddr) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        ip: peer_addr.ip(),
        tcp_port: peer_addr.port(),
        user_hash: None,
        client_id: None,
        friend_slot: false,
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
        friend_slot: false,
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
