use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::Result;
use tokio::{sync::RwLock, time::Instant as TokioInstant};
use tracing::{debug, info, warn};

use overlord_kad_proto::Ed2kHash;

use crate::ed2k_tcp::{connect_callback_peer, enrich_hello_identity};

use super::types::{CallbackRequest, ServerSessionContext, ServerUdpPacket};
use super::udp_runtime::{
    bind_server_udp_socket, read_server_udp_packet, send_server_udp_status_request,
};
use super::{
    BackgroundServerSearchRequest, Ed2kFoundSource, Ed2kPacket, Ed2kServerLoopOptions,
    Ed2kServerSearchInbox, Ed2kServerState, OP_CALLBACK_FAIL, OP_CALLBACKREQUESTED,
    OP_FOUNDSOURCES, OP_FOUNDSOURCES_OBFU, OP_IDCHANGE, OP_LOGINREQUEST, OP_OFFERFILES,
    OP_QUERY_MORE_RESULT, OP_REJECT, OP_SEARCHREQUEST, OP_SEARCHRESULT, OP_SERVERIDENT,
    OP_SERVERLIST, OP_SERVERMESSAGE, OP_SERVERSTATUS, PendingBackgroundServerSearch,
    ResolvedServerEntry, ST_DESCRIPTION, ST_SERVERNAME, ServerSession, ServerSessionPhase,
    configured_server_entries, decode_ed2k_string, decode_found_sources, decode_search_result_page,
    decode_tag, encode_login_request, encode_packet, encode_search_request,
    fail_background_search_request, fail_pending_background_search, format_connect_options,
    format_server_flags, handle_background_udp_packet, is_low_id, log_search_result_page,
    login_identity_for_server_transport, resolve_server_entry, send_connected_server_startup,
    send_offer_files_advertisement, server_udp_endpoint, should_use_server_obfuscation,
    start_background_server_search, wait_for_offer_files_settle,
};
/// Runs the minimal oracle-shaped ED2K server session loop for the configured endpoints.
pub async fn run_ed2k_server_loop(options: Ed2kServerLoopOptions) {
    let Ed2kServerLoopOptions {
        bind_ip,
        nat,
        config,
        hello_identity,
        shared_catalog,
        state,
        mut search_inbox,
        kad_firewall,
        shutdown,
    } = options;
    let reconnect_delay = Duration::from_secs(config.reconnect_interval_secs.max(1));
    let session_context = ServerSessionContext {
        bind_ip,
        nat,
        hello_identity,
        probe_search_term: config.probe_search_term.clone(),
        shared_catalog,
        state: Arc::clone(&state),
        kad_firewall,
        keepalive_interval: Duration::from_secs(config.keepalive_secs.max(1)),
        connect_timeout: Duration::from_secs(config.connect_timeout_secs.max(1)),
        rotation_interval: (config.session_rotation_secs > 0)
            .then(|| Duration::from_secs(config.session_rotation_secs)),
        shutdown: Arc::clone(&shutdown),
    };

    let configured_servers = match configured_server_entries(&config) {
        Ok(entries) => entries,
        Err(error) => {
            warn!("ED2K server session disabled: invalid server configuration: {error}");
            return;
        }
    };
    if configured_servers.is_empty() {
        info!(
            "ED2K server session disabled: no p2p.ed2k.server_entries or p2p.ed2k.server_endpoints configured"
        );
        return;
    }

    while !shutdown.load(Ordering::Relaxed) {
        let mut attempted_any = false;
        for configured_server in &configured_servers {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            attempted_any = true;
            match resolve_server_entry(configured_server).await {
                Ok(server) => {
                    if let Err(error) =
                        run_one_server_session(&server, &session_context, &mut search_inbox).await
                    {
                        clear_server_connection_state(&state).await;
                        warn!(
                            "ED2K server session ended for {} name={}: {error}",
                            server.base_endpoint(),
                            server.entry.display_name()
                        );
                    }
                }
                Err(error) => {
                    warn!(
                        "failed to resolve ED2K server endpoint {} name={}: {error}",
                        configured_server.base_endpoint_text(),
                        configured_server.display_name()
                    );
                }
            }

            if !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(reconnect_delay).await;
            }
        }

        if !attempted_any && !shutdown.load(Ordering::Relaxed) {
            tokio::time::sleep(reconnect_delay).await;
        }
    }
}

async fn run_one_server_session(
    server: &ResolvedServerEntry,
    context: &ServerSessionContext,
    search_inbox: &mut Ed2kServerSearchInbox,
) -> Result<()> {
    let use_server_obfuscation =
        should_use_server_obfuscation(context.hello_identity.connect_options, server);
    let login_identity =
        login_identity_for_server_transport(context.hello_identity, use_server_obfuscation);
    let transport_endpoint = server.transport_endpoint(use_server_obfuscation);
    let mut session = ServerSession::connect(
        context.bind_ip,
        transport_endpoint,
        Arc::clone(&context.state),
        "background",
        context.connect_timeout,
    )
    .await?;
    let server_udp_socket = match bind_server_udp_socket(context.bind_ip).await {
        Ok(socket) => {
            info!(
                "bound ED2K server UDP helper local={} remote={} trace_id={}",
                socket.local_addr()?,
                server_udp_endpoint(server),
                session.trace_id
            );
            Some(socket)
        }
        Err(error) => {
            warn!(
                "failed to bind ED2K server UDP helper for {}: {error}",
                server.base_endpoint()
            );
            None
        }
    };
    {
        let mut guard = context.state.write().await;
        guard.endpoint = Some(server.base_endpoint());
        guard.connected = false;
        guard.client_id = None;
        guard.server_flags = None;
    }

    let nat_status = context.nat.status().await;
    let observed_external_ip = nat_status.observed_external_addresses.first().cloned();
    let login_payload = encode_login_request(login_identity);
    info!(
        "connected to ED2K server {} name={} trace_id={} role=background bind_ip={} observed_external_ip={} transport={} connect_options={} supports_obf_tcp={} obf_port={} udp_flags=0x{:08X} udp_key_present={} chosen_port={}",
        server.base_endpoint(),
        server.entry.display_name(),
        session.trace_id,
        context.bind_ip,
        observed_external_ip.as_deref().unwrap_or("unknown"),
        if use_server_obfuscation {
            "obfuscated"
        } else {
            "plaintext"
        },
        format_connect_options(login_identity.connect_options),
        server.entry.supports_obfuscation_tcp(),
        server.entry.obfuscation_port_tcp,
        server.entry.udp_flags,
        server.entry.udp_key != 0,
        transport_endpoint.port(),
    );
    if use_server_obfuscation {
        let login_request = encode_packet(OP_LOGINREQUEST, &login_payload, false)?;
        session
            .negotiate_obfuscation_and_send(&login_request)
            .await?;
    } else {
        session.send_packet(OP_LOGINREQUEST, &login_payload).await?;
    }
    session.set_phase(
        ServerSessionPhase::AwaitingIdChange,
        "login request sent; awaiting OP_IDCHANGE",
    );

    let rotation_deadline = context
        .rotation_interval
        .map(|interval| TokioInstant::now() + interval);
    let mut queued_background_search = None;
    let mut pending_background_search = None;

    loop {
        if context.shutdown.load(Ordering::Relaxed) {
            fail_background_search_request(
                &mut queued_background_search,
                "ED2K background session is shutting down before search dispatch",
            );
            fail_pending_background_search(
                &mut pending_background_search,
                "ED2K background session is shutting down before search completion",
            );
            clear_server_connection_state(&context.state).await;
            return Ok(());
        }

        tokio::select! {
            _ = async {
                if let Some(deadline) = rotation_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if queued_background_search.is_none() && pending_background_search.is_none() => {
                fail_background_search_request(
                    &mut queued_background_search,
                    "ED2K background session rotated before search dispatch",
                );
                fail_pending_background_search(
                    &mut pending_background_search,
                    "ED2K background session rotated before search completion",
                );
                info!(
                    "rotating ED2K server session from {} after {:?}",
                    server.base_endpoint(),
                    context.rotation_interval.expect("rotation interval is set"),
                );
                clear_server_connection_state(&context.state).await;
                return Ok(());
            }
            request = search_inbox.receiver.recv(), if queued_background_search.is_none() && pending_background_search.is_none() => {
                if let Some(request) = request {
                    if session.login_accepted {
                        match start_background_server_search(
                            &mut session,
                            server,
                            server_udp_socket.as_ref(),
                            context.hello_identity.connect_options,
                            request,
                        )
                        .await
                        {
                            Ok(pending) => pending_background_search = pending,
                            Err(error) => warn!("failed to start ED2K background server search on {}: {error}", server.base_endpoint()),
                        }
                    } else {
                        match &request {
                            BackgroundServerSearchRequest::Keyword { query, .. } => info!(
                                "queued ED2K background keyword search query={query:?} endpoint={} trace_id={} awaiting login",
                                session.endpoint,
                                session.trace_id
                            ),
                            BackgroundServerSearchRequest::Source { file_hash, .. } => info!(
                                "queued ED2K background source search file_hash={} endpoint={} trace_id={} awaiting login",
                                file_hash,
                                session.endpoint,
                                session.trace_id
                            ),
                            BackgroundServerSearchRequest::Callback { client_id, .. } => info!(
                                "queued ED2K background callback request client_id={} endpoint={} trace_id={} awaiting login",
                                client_id,
                                session.endpoint,
                                session.trace_id
                            ),
                        }
                        queued_background_search = Some(request);
                    }
                }
            }
            _ = async {
                if let Some(pending) = pending_background_search.as_ref() {
                    let deadline = match pending {
                        PendingBackgroundServerSearch::Keyword { deadline, .. }
                        | PendingBackgroundServerSearch::Source { deadline, .. } => *deadline,
                    };
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if pending_background_search.is_some() => {
                let timeout_error = match pending_background_search.as_ref() {
                    Some(PendingBackgroundServerSearch::Keyword { .. }) => {
                        "ED2K background session search timed out waiting for OP_SEARCHRESULT"
                    }
                    Some(PendingBackgroundServerSearch::Source { .. }) => {
                        "ED2K background session search timed out waiting for OP_FOUNDSOURCES"
                    }
                    None => unreachable!("pending background search timeout without search"),
                };
                fail_pending_background_search(&mut pending_background_search, timeout_error);
            }
            packet = session.read_packet() => {
                let Some(packet) = packet? else {
                    let closed_error = format!(
                        "ED2K server {} closed the connection",
                        server.base_endpoint()
                    );
                    fail_background_search_request(
                        &mut queued_background_search,
                        &format!("{closed_error} before search dispatch"),
                    );
                    fail_pending_background_search(
                        &mut pending_background_search,
                        &format!("{closed_error} before search completion"),
                    );
                    anyhow::bail!(
                        "{closed_error}"
                    );
                };
                if let Some(pending) = pending_background_search.take() {
                    match (packet.opcode, pending) {
                        (OP_SEARCHRESULT, PendingBackgroundServerSearch::Keyword {
                            query,
                            deadline,
                            mut results,
                            mut page_count,
                            response,
                        }) => {
                            let page = decode_search_result_page(&packet.payload)?;
                            log_search_result_page(session.endpoint, &page.files);
                            page_count += 1;
                            results.extend(page.files);
                            if page.more_results_available {
                                session.set_phase(
                                    ServerSessionPhase::AwaitingMore,
                                    format!(
                                        "received background search page {} query={query:?}; requesting more",
                                        page_count
                                    ),
                                );
                                session.send_packet(OP_QUERY_MORE_RESULT, &[]).await?;
                                pending_background_search = Some(PendingBackgroundServerSearch::Keyword {
                                    query,
                                    deadline,
                                    results,
                                    page_count,
                                    response,
                                });
                                continue;
                            }
                            session.set_phase(
                                ServerSessionPhase::Completed,
                                format!(
                                    "completed background keyword search query={query:?} pages={page_count} results={}",
                                    results.len()
                                ),
                            );
                            info!(
                                "completed ED2K background keyword search query={:?} endpoint={} trace_id={} result_count={} pages={}",
                                query,
                                session.endpoint,
                                session.trace_id,
                                results.len(),
                                page_count
                            );
                            let _ = response.send(Ok(results));
                            continue;
                        }
                        (OP_FOUNDSOURCES | OP_FOUNDSOURCES_OBFU, PendingBackgroundServerSearch::Source {
                            file_hash,
                            response,
                            ..
                        }) => {
                            let results = annotate_found_sources_server(
                                decode_found_sources(
                                    &packet.payload,
                                    packet.opcode == OP_FOUNDSOURCES_OBFU,
                                )?,
                                session.endpoint,
                            );
                            validate_found_sources(&results, file_hash)?;
                            session.set_phase(
                                ServerSessionPhase::Completed,
                                format!(
                                    "completed background source search file_hash={} sources={}",
                                    file_hash,
                                    results.len()
                                ),
                            );
                            info!(
                                "completed ED2K background source search file_hash={} endpoint={} trace_id={} source_count={} obfuscated={}",
                                file_hash,
                                session.endpoint,
                                session.trace_id,
                                results.len(),
                                packet.opcode == OP_FOUNDSOURCES_OBFU
                            );
                            let _ = response.send(Ok(results));
                            continue;
                        }
                        (_, pending) => {
                            pending_background_search = Some(pending);
                        }
                    }
                }
                handle_server_packet(
                    &mut session,
                    packet,
                    context,
                    queued_background_search.is_none() && pending_background_search.is_none(),
                )
                .await?;
                if session.login_accepted
                    && pending_background_search.is_none()
                    && let Some(request) = queued_background_search.take()
                {
                    match start_background_server_search(
                        &mut session,
                        server,
                        server_udp_socket.as_ref(),
                        context.hello_identity.connect_options,
                        request,
                    )
                    .await
                    {
                        Ok(pending) => pending_background_search = pending,
                        Err(error) => warn!("failed to start ED2K background server search on {}: {error}", server.base_endpoint()),
                    }
                }
            }
            udp_packet = async {
                if let Some(socket) = server_udp_socket.as_ref() {
                    read_server_udp_packet(socket, server).await
                } else {
                    std::future::pending::<Result<Option<ServerUdpPacket>>>().await
                }
            } => {
                match udp_packet {
                    Ok(Some(packet)) => {
                        handle_background_udp_packet(
                            server,
                            &packet,
                            &mut pending_background_search,
                            &context.state,
                        )?;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(
                            "ignoring ED2K server UDP helper receive failure for {}: {error}",
                            server.base_endpoint()
                        );
                    }
                }
            }
            _ = tokio::time::sleep(context.keepalive_interval) => {
                if session.last_tx.elapsed() >= context.keepalive_interval {
                    send_offer_files_advertisement(
                        &mut session,
                        &context.shared_catalog,
                        context.hello_identity.tcp_port,
                    )
                    .await?;
                    if session.last_tx.elapsed() >= context.keepalive_interval {
                        session.send_packet(OP_OFFERFILES, &0u32.to_le_bytes()).await?;
                        debug!("sent ED2K server keepalive to {}", server.base_endpoint());
                    }
                }
                if let Some(socket) = server_udp_socket.as_ref()
                    && let Err(error) = send_server_udp_status_request(socket, server).await
                {
                    warn!(
                        "failed to send ED2K server UDP status request to {}: {error}",
                        server.base_endpoint()
                    );
                }
            }
        }
    }
}

async fn maybe_send_probe_search(
    session: &mut ServerSession,
    context: &ServerSessionContext,
) -> Result<()> {
    if !session.login_accepted || session.probe_search_sent {
        return Ok(());
    }
    let Some(term) = context.probe_search_term.as_deref() else {
        return Ok(());
    };
    let search_payload = encode_search_request(term)?;
    if search_payload.is_empty() {
        return Ok(());
    }
    wait_for_offer_files_settle(session).await;
    session.set_phase(
        ServerSessionPhase::SearchActive,
        format!("dispatching probe keyword search term={term:?}"),
    );
    session
        .send_packet(OP_SEARCHREQUEST, &search_payload)
        .await?;
    session.probe_search_sent = true;
    info!(
        "sent ED2K server search probe term={term:?} endpoint={}",
        session.endpoint
    );
    Ok(())
}

async fn handle_server_packet(
    session: &mut ServerSession,
    packet: Ed2kPacket,
    context: &ServerSessionContext,
    allow_probe_search: bool,
) -> Result<()> {
    match packet.opcode {
        OP_IDCHANGE => {
            if packet.payload.len() < 4 {
                anyhow::bail!("short OP_IDCHANGE payload from {}", session.endpoint);
            }
            let client_id = u32::from_le_bytes(packet.payload[..4].try_into().unwrap());
            let server_flags = (packet.payload.len() >= 8)
                .then(|| u32::from_le_bytes(packet.payload[4..8].try_into().unwrap()));
            let reported_client_ip = (packet.payload.len() >= 16).then(|| {
                ipv4_from_client_id(u32::from_le_bytes(
                    packet.payload[12..16].try_into().unwrap(),
                ))
            });
            {
                let mut guard = session.state.write().await;
                guard.connected = true;
                guard.client_id = Some(client_id);
                guard.server_flags = server_flags;
            }
            info!(
                "ED2K server assigned client_id={} high_id={} server_flags={} reported_client_ip={}",
                client_id,
                !is_low_id(client_id),
                format_server_flags(server_flags.unwrap_or_default()),
                reported_client_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            session.assigned_client_id = Some(client_id);
            session.server_flags = server_flags;
            session.login_accepted = true;
            send_connected_server_startup(
                session,
                &context.shared_catalog,
                context.hello_identity.tcp_port,
            )
            .await?;
            if allow_probe_search {
                maybe_send_probe_search(session, context).await?;
            }
        }
        OP_SEARCHRESULT => {
            let page = decode_search_result_page(&packet.payload)?;
            log_search_result_page(session.endpoint, &page.files);
            if page.more_results_available {
                session.set_phase(
                    ServerSessionPhase::AwaitingMore,
                    "probe search reported more results; requesting another page",
                );
                session.send_packet(OP_QUERY_MORE_RESULT, &[]).await?;
            } else if session.probe_search_sent {
                session.set_phase(
                    ServerSessionPhase::Completed,
                    "probe search completed without additional pages",
                );
            }
        }
        OP_SERVERSTATUS => {
            if packet.payload.len() >= 8 {
                let users = u32::from_le_bytes(packet.payload[..4].try_into().unwrap());
                let files = u32::from_le_bytes(packet.payload[4..8].try_into().unwrap());
                {
                    let mut guard = session.state.write().await;
                    guard.server_users = Some(users);
                    guard.server_files = Some(files);
                }
                info!(
                    "ED2K server status from {}: users={} files={}",
                    session.endpoint, users, files
                );
            }
        }
        OP_SERVERIDENT => {
            let (name, description) = decode_server_ident(&packet.payload)?;
            {
                let mut guard = session.state.write().await;
                if let Some(name) = &name {
                    guard.server_name = Some(name.clone());
                }
                if let Some(description) = &description {
                    guard.server_description = Some(description.clone());
                }
            }
            debug!(
                "ED2K server ident from {}: name={} description={}",
                session.endpoint,
                name.as_deref().unwrap_or("-"),
                description.as_deref().unwrap_or("-")
            );
            if allow_probe_search {
                maybe_send_probe_search(session, context).await?;
            }
        }
        OP_SERVERLIST => {
            let count = packet.payload.first().copied().unwrap_or_default();
            debug!(
                "ED2K server {} returned {} server list entries",
                session.endpoint, count
            );
            if allow_probe_search {
                maybe_send_probe_search(session, context).await?;
            }
        }
        OP_SERVERMESSAGE => {
            if let Some(message) = decode_ed2k_string(&packet.payload)? {
                info!("ED2K server message from {}: {}", session.endpoint, message);
            }
            if allow_probe_search {
                maybe_send_probe_search(session, context).await?;
            }
        }
        OP_CALLBACKREQUESTED => {
            if let Some(callback) = decode_callback_request(&packet.payload)? {
                info!(
                    "ED2K server requested callback from peer {} transport_hint={} payload_len={}",
                    callback.peer_addr,
                    callback
                        .connect_options
                        .map(format_connect_options)
                        .unwrap_or_else(|| "plaintext".to_string()),
                    packet.payload.len()
                );
                let bind_ip = context.bind_ip;
                let hello_identity = enrich_hello_identity(
                    context.hello_identity,
                    &context.state,
                    &context.kad_firewall,
                )
                .await;
                let connect_timeout = context.connect_timeout;
                tokio::spawn(async move {
                    match connect_callback_peer(
                        bind_ip,
                        callback.peer_addr,
                        hello_identity,
                        callback.user_hash,
                        callback.connect_options,
                        connect_timeout,
                    )
                    .await
                    {
                        Ok(mode) => {
                            info!(
                                "ED2K callback peer connect completed peer={} transport={}",
                                callback.peer_addr,
                                mode.as_str()
                            );
                        }
                        Err(error) => {
                            debug!(
                                "ED2K callback peer connect failed peer={}: {error}",
                                callback.peer_addr
                            );
                        }
                    }
                });
            }
        }
        OP_CALLBACK_FAIL => {
            debug!(
                "ED2K server callback failed notification from {}",
                session.endpoint
            );
        }
        OP_REJECT => {
            anyhow::bail!("ED2K server {} rejected the last command", session.endpoint);
        }
        opcode => {
            debug!(
                "ignoring unsupported ED2K server opcode=0x{:02X} from {} payload_len={}",
                opcode,
                session.endpoint,
                packet.payload.len()
            );
        }
    }
    Ok(())
}

fn decode_callback_request(payload: &[u8]) -> Result<Option<CallbackRequest>> {
    if payload.len() < 6 {
        return Ok(None);
    }
    let ip = ipv4_from_client_id(u32::from_le_bytes(payload[..4].try_into().unwrap()));
    let port = u16::from_le_bytes(payload[4..6].try_into().unwrap());
    let connect_options = payload.get(6).copied();
    let user_hash = (payload.len() >= 23).then(|| {
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&payload[7..23]);
        hash
    });
    Ok(Some(CallbackRequest {
        peer_addr: SocketAddr::new(IpAddr::V4(ip), port),
        connect_options,
        user_hash,
    }))
}

pub(super) fn annotate_found_sources_server(
    mut results: Vec<Ed2kFoundSource>,
    server_endpoint: SocketAddr,
) -> Vec<Ed2kFoundSource> {
    for source in &mut results {
        source.source_server = Some(server_endpoint);
    }
    results
}

pub(super) fn ipv4_from_client_id(client_id: u32) -> Ipv4Addr {
    Ipv4Addr::from(client_id.to_le_bytes())
}

pub(super) fn validate_found_sources(
    results: &[Ed2kFoundSource],
    expected_file_hash: Ed2kHash,
) -> Result<()> {
    for source in results {
        if source.file_hash != expected_file_hash {
            anyhow::bail!(
                "ED2K found-sources reply referenced unexpected file hash {} expected {}",
                source.file_hash,
                expected_file_hash
            );
        }
    }
    Ok(())
}

pub(super) fn merge_found_sources(
    aggregated_results: &mut Vec<Ed2kFoundSource>,
    new_results: Vec<Ed2kFoundSource>,
) {
    for source in new_results {
        if let Some(existing) = aggregated_results.iter_mut().find(|existing| {
            existing.ip == source.ip
                && existing.tcp_port == source.tcp_port
                && existing.obfuscation_options == source.obfuscation_options
                && existing.user_hash == source.user_hash
        }) {
            if existing.source_server.is_none() && source.source_server.is_some() {
                existing.source_server = source.source_server;
            }
            continue;
        }
        aggregated_results.push(source);
    }
}

async fn clear_server_connection_state(state: &Arc<RwLock<Ed2kServerState>>) {
    let mut guard = state.write().await;
    guard.connected = false;
    guard.endpoint = None;
    guard.client_id = None;
    guard.server_flags = None;
}

pub(super) fn decode_server_ident(payload: &[u8]) -> Result<(Option<String>, Option<String>)> {
    if payload.len() < 26 {
        return Ok((None, None));
    }
    let tag_count = u32::from_le_bytes(payload[22..26].try_into().unwrap());
    let mut cursor = &payload[26..];
    let mut name = None;
    let mut description = None;
    for _ in 0..tag_count {
        let (tag_name, tag_value, rest) = decode_tag(cursor)?;
        cursor = rest;
        match tag_name {
            Some(ST_SERVERNAME) => name = tag_value,
            Some(ST_DESCRIPTION) => description = tag_value,
            _ => {}
        }
    }
    Ok((name, description))
}
