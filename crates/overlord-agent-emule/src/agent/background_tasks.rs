use super::*;

impl OverlordAgentEmule {
    pub(super) async fn spawn_background_tasks(
        &self,
        runtime: &AgentNetworkRuntime,
        config: &EmuleAgentConfig,
    ) {
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let state_paths = self.state_paths.clone();
        let routing_refresh_interval =
            Duration::from_secs(config.p2p.kad.routing_refresh_interval_secs.max(1));
        let nodes_dat_refresh_interval =
            Duration::from_secs(config.p2p.kad.nodes_dat_refresh_interval_secs.max(1));
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut last_nodes_dat_persist = Instant::now();
            let mut last_persisted_contact_count = dht.routing_contacts().await.len();
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(routing_refresh_interval).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }

                let target = random_routing_refresh_target();
                let started_at = Instant::now();
                let contacts_before = dht.routing_contacts().await.len();
                match dht
                    .lookup_nodes_with_class(&target, RpcWorkClass::Maintenance)
                    .await
                {
                    Ok(closest) => {
                        let contacts_after = dht.routing_contacts().await.len();
                        info!(
                            "kad routing refresh target={} closest={} contacts_before={} contacts_after={} elapsed_ms={}",
                            target,
                            closest.len(),
                            contacts_before,
                            contacts_after,
                            started_at.elapsed().as_millis()
                        );

                        let snapshot_due =
                            last_nodes_dat_persist.elapsed() >= nodes_dat_refresh_interval;
                        if contacts_after != last_persisted_contact_count || snapshot_due {
                            if let Err(error) = persist_nodes_dat_for(&dht, &state_paths).await {
                                warn!("failed to persist nodes.dat after routing refresh: {error}");
                            } else {
                                last_nodes_dat_persist = Instant::now();
                                last_persisted_contact_count = contacts_after;
                            }
                        }
                    }
                    Err(error) => debug!("kad routing refresh failed target={target}: {error}"),
                }
            }
        }));

        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let state_paths = self.state_paths.clone();
        let coordinator = self.coordinator.clone();
        let local_store = Arc::clone(&self.local_store);
        let publish_batch_gate = Arc::clone(&self.publish_batch_gate);
        let publish_observability = Arc::clone(&self.publish_observability);
        let agent_activity = Arc::clone(&self.agent_activity);
        let ed2k_shared_catalog = Arc::clone(&runtime.ed2k_shared_catalog);
        let source_publish_identity = source_publish_client_hash(self.ed2k_user_hash);
        let source_publish_settings = SourcePublishSettings {
            tcp_port: config.p2p.ed2k.listen_port,
            obfuscation_enabled: config.p2p.ed2k.obfuscation_enabled,
        };
        let notes_publish_enabled = config.p2p.kad.seed_notes_publish_enabled;
        let publish_contact_fanout = config.p2p.kad.publish_contact_fanout;
        let synthetic_publish_interval_secs = config.p2p.kad.synthetic_publish_interval_secs;
        let synthetic_publish_batch_items = config.p2p.kad.synthetic_publish_batch_items;
        let synthetic_publish_contact_fanout = config.p2p.kad.synthetic_publish_contact_fanout;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let bootstrap_started_at = Utc::now();
            let mut bootstrap_snapshot =
                new_activity_snapshot(AgentActivityState::Bootstrapping, bootstrap_started_at);
            bootstrap_snapshot.query_or_target = Some("kad dht".to_string());
            begin_agent_activity(
                &agent_activity,
                ACTIVITY_KEY_BOOTSTRAPPING.to_string(),
                bootstrap_snapshot,
            )
            .await;
            while !shutdown.load(Ordering::Relaxed) && !dht.is_bootstrapped() {
                match dht.bootstrap_with_class(RpcWorkClass::Maintenance).await {
                    Ok(()) => {
                        if let Err(error) = persist_nodes_dat_for(&dht, &state_paths).await {
                            warn!("failed to persist nodes.dat after bootstrap: {error}");
                        }
                        if let Err(error) = seed_coordinator_popular_if_available(
                            &dht,
                            source_publish_identity,
                            source_publish_settings,
                            &coordinator,
                            &ed2k_shared_catalog,
                            PublishExecutionContext {
                                local_store: &local_store,
                                publish_batch_gate: &publish_batch_gate,
                                publish_observability: &publish_observability,
                                agent_activity: &agent_activity,
                                activity_key: None,
                                notes_publish_enabled,
                                work_class: RpcWorkClass::Publish,
                                publish_contact_fanout,
                            },
                        )
                        .await
                        {
                            debug!("post-bootstrap coordinator seeding failed: {error}");
                        }
                        set_synthetic_publish_queue_depth(
                            &publish_observability,
                            SYNTHETIC_POPULAR_SEEDS.len(),
                        )
                        .await;
                        finish_agent_activity(
                            &agent_activity,
                            ACTIVITY_KEY_BOOTSTRAPPING,
                            Utc::now(),
                        )
                        .await;
                        clear_agent_degraded_activity(&agent_activity).await;
                        break;
                    }
                    Err(error) => {
                        let error_message = error.to_string();
                        debug!("bootstrap retry failed: {error_message}");
                        update_agent_activity_error(
                            &agent_activity,
                            ACTIVITY_KEY_BOOTSTRAPPING,
                            error_message,
                            Utc::now(),
                        )
                        .await;
                    }
                }
                tokio::time::sleep(Duration::from_secs(BOOTSTRAP_RETRY_SECS)).await;
            }
            finish_agent_activity(&agent_activity, ACTIVITY_KEY_BOOTSTRAPPING, Utc::now()).await;
        }));

        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let snoop_queue = Arc::clone(&self.snoop_queue);
        let observed_snoop_events = Arc::clone(&self.observed_snoop_events);
        let local_store = Arc::clone(&self.local_store);
        let harvest_observability = Arc::clone(&self.harvest_observability);
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let ed2k_listener = Arc::clone(&runtime.ed2k_listener);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let ed2k_user_hash = self.ed2k_user_hash;
        let ed2k_obfuscation_enabled = config.p2p.ed2k.obfuscation_enabled;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut packets = dht.subscribe_packets();
            while !shutdown.load(Ordering::Relaxed) {
                match packets.recv().await {
                    Ok(received) => {
                        if let Err(error) = handle_unsolicited_packet(
                            &dht,
                            UnsolicitedPacketContext {
                                snoop_queue: &snoop_queue,
                                observed_snoop_events: &observed_snoop_events,
                                local_store: &local_store,
                                harvest_observability: &harvest_observability,
                                kad_firewall: &kad_firewall,
                                ed2k_listener: &ed2k_listener,
                                ed2k_server_state: &ed2k_server_state,
                                ed2k_user_hash: Ed2kHash::from_bytes(ed2k_user_hash),
                                ed2k_obfuscation_enabled,
                            },
                            received,
                        )
                        .await
                        {
                            debug!("unsolicited packet handling failed: {error}");
                        }
                    }
                    Err(error) => {
                        debug!("packet subscription closed: {error}");
                        break;
                    }
                }
            }
        }));

        self.spawn_ed2k_background_tasks(runtime, config).await;
        let dht = runtime.dht.clone();
        let nat = Arc::clone(&runtime.nat);
        let shutdown = Arc::clone(&runtime.shutdown);
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let ed2k_secure_ident = Arc::clone(&runtime.ed2k_secure_ident);
        let udp_firewall_check_enabled = config.p2p.kad.udp_firewall_check_enabled;
        let udp_firewall_recheck_interval =
            Duration::from_secs(config.p2p.kad.udp_firewall_recheck_interval_secs.max(1));
        let udp_firewall_check_timeout =
            Duration::from_secs(config.p2p.kad.udp_firewall_check_timeout_secs.max(1));
        let udp_firewall_check_contact_count = config.p2p.kad.udp_firewall_check_contact_count;
        let ed2k_user_hash = self.ed2k_user_hash;
        let ed2k_hello_identity = Ed2kHelloIdentity {
            user_hash: ed2k_user_hash,
            client_id: 0,
            tcp_port: config.p2p.ed2k.listen_port,
            udp_port: config.p2p.kad.listen_port,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(config.p2p.ed2k.obfuscation_enabled),
            direct_udp_callback: false,
        };
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            if !udp_firewall_check_enabled {
                return;
            }

            while !shutdown.load(Ordering::Relaxed) {
                if !dht.is_bootstrapped() {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    continue;
                }

                let bind_addr = match dht.bind_addr() {
                    Ok(bind_addr) => bind_addr,
                    Err(error) => {
                        debug!("kad firewall-check skipped: failed to resolve bind addr: {error}");
                        continue;
                    }
                };
                let helper_hello_identity = enrich_hello_identity(
                    ed2k_hello_identity,
                    &ed2k_server_state,
                    &kad_firewall,
                )
                .await;
                if helper_hello_identity.client_id == 0
                    || helper_hello_identity.server_ip == 0
                    || helper_hello_identity.server_port == 0
                {
                    debug!(
                        "kad firewall-check skipped: ED2K helper hello not ready client_id={} server_ip={} server_port={}",
                        helper_hello_identity.client_id,
                        Ipv4Addr::from(helper_hello_identity.server_ip.to_le_bytes()),
                        helper_hello_identity.server_port
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                let helper_contacts = match select_udp_firewall_helpers(
                    &dht,
                    udp_firewall_check_contact_count
                        .saturating_mul(UDP_FIREWALL_HELPER_CANDIDATE_MULTIPLIER),
                )
                .await
                {
                    Ok(contacts) => contacts,
                    Err(error) => {
                        debug!("kad firewall-check helper selection failed: {error}");
                        continue;
                    }
                };
                if helper_contacts.is_empty() {
                    debug!("kad firewall-check skipped: no helper contacts available");
                    continue;
                }

                let bind_ip = match bind_addr.ip() {
                    IpAddr::V4(ip) => ip,
                    IpAddr::V6(_) => {
                        debug!("kad firewall-check skipped: IPv6 bind addr is not supported");
                        continue;
                    }
                };
                let active_ports =
                    active_udp_firewall_ports(&dht, &nat, &kad_firewall, bind_addr.port()).await;
                let expected_ports = active_ports.expected_ports();
                let started_at = Utc::now();
                {
                    let mut firewall = kad_firewall.lock().await;
                    if !firewall.begin_udp_check(
                        helper_contacts.iter().map(|contact| IpAddr::V4(contact.ip)),
                        expected_ports.iter().copied(),
                        started_at,
                    ) {
                        continue;
                    }
                }

                let internal_udp_port = active_ports.internal;
                let external_udp_port = active_ports.external;
                info!(
                    "starting kad udp firewall-check target_helpers={} candidate_helpers={} internal_port={} external_port={}",
                    udp_firewall_check_contact_count,
                    helper_contacts.len(),
                    internal_udp_port,
                    external_udp_port
                );
                debug!(
                    "kad udp firewall-check helper hello client_id={} server_ip={} server_port={} direct_udp_callback={}",
                    helper_hello_identity.client_id,
                    Ipv4Addr::from(helper_hello_identity.server_ip.to_le_bytes()),
                    helper_hello_identity.server_port,
                    helper_hello_identity.direct_udp_callback
                );

                let mut request_tasks = Vec::with_capacity(helper_contacts.len());
                for contact in helper_contacts {
                    let helper_addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.tcp_port);
                    let helper_ip = IpAddr::V4(contact.ip);
                    let request = FirewallCheckUdpRequest {
                        internal_udp_port,
                        external_udp_port,
                        sender_udp_key: dht.verify_key_for_ip(contact.ip),
                    };
                    let secure_ident = Arc::clone(&ed2k_secure_ident);
                    let helper_dht = dht.clone();
                    request_tasks.push(tokio::spawn(async move {
                        let result = request_udp_firewall_check(
                            Some(helper_dht),
                            bind_ip,
                            helper_addr,
                            helper_hello_identity,
                            secure_ident,
                            request,
                            udp_firewall_check_timeout,
                        )
                        .await;
                        (helper_ip, helper_addr, result)
                    }));
                }

                for task in request_tasks {
                    match task.await {
                        Ok((_helper_ip, helper_addr, Ok(()))) => {
                            debug!("sent OP_FWCHECKUDPREQ to helper {helper_addr}");
                        }
                        Ok((helper_ip, helper_addr, Err(error))) => {
                            let mut firewall = kad_firewall.lock().await;
                            firewall.record_helper_request_failed(helper_ip, &error.to_string());
                            debug!("failed to send OP_FWCHECKUDPREQ to helper {helper_addr}: {error}");
                        }
                        Err(error) => {
                            debug!("UDP firewall-check helper task failed: {error}");
                        }
                    }
                }

                tokio::time::sleep(udp_firewall_check_timeout).await;
                let summary = {
                    let mut firewall = kad_firewall.lock().await;
                    firewall.finish_udp_check(Utc::now())
                };
                if let Some(summary) = summary {
                    if summary.open {
                        info!(
                            "kad udp firewall-check completed open helpers_selected={} helpers_requested={} helpers_succeeded={} helpers_failed={} elapsed_ms={}",
                            summary.helpers_selected,
                            summary.helpers_requested,
                            summary.helpers_succeeded,
                            summary.helpers_failed,
                            (summary.completed_at - summary.started_at).num_milliseconds()
                        );
                    } else {
                        warn!(
                            "kad udp firewall-check completed firewalled helpers_selected={} helpers_requested={} helpers_succeeded={} helpers_failed={} elapsed_ms={}",
                            summary.helpers_selected,
                            summary.helpers_requested,
                            summary.helpers_succeeded,
                            summary.helpers_failed,
                            (summary.completed_at - summary.started_at).num_milliseconds()
                        );
                    }
                }
                tokio::time::sleep(udp_firewall_recheck_interval).await;
            }
        }));

        let dht = runtime.dht.clone();
        let ed2k_listener = Arc::clone(&runtime.ed2k_listener);
        let ed2k_server_state = Arc::clone(&runtime.ed2k_server_state);
        let kad_firewall = Arc::clone(&runtime.kad_firewall);
        let shutdown = Arc::clone(&runtime.shutdown);
        let hello_intro_interval_secs = config.p2p.kad.hello_intro_interval_secs;
        let hello_intro_fanout = config.p2p.kad.hello_intro_fanout;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut introduced = std::collections::HashSet::new();
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(hello_intro_interval_secs.max(1))).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }

                let local_ip = match dht.bind_addr() {
                    Ok(bind_addr) => bind_addr.ip(),
                    Err(error) => {
                        debug!("kad hello intro skipped: failed to resolve bind addr: {error}");
                        continue;
                    }
                };
                let mut contacts = dht
                    .routing_contacts()
                    .await
                    .into_iter()
                    .filter_map(|contact| {
                        let addr = SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port);
                        (contact.udp_port != 0
                            && contact.kad_version >= 6
                            && IpAddr::V4(contact.ip) != local_ip
                            && !introduced.contains(&addr))
                        .then_some((contact, addr))
                    })
                    .collect::<Vec<_>>();
                contacts.shuffle(&mut rand::thread_rng());

                for (contact, addr) in contacts.into_iter().take(hello_intro_fanout.max(1)) {
                    // eMule requests HELLO_RES_ACK from HELLO_RES, not from proactive HELLO_REQ.
                    let request_ack = false;
                    let hello = match build_hello_request(
                        &dht,
                        &ed2k_listener,
                        &ed2k_server_state,
                        &kad_firewall,
                        request_ack,
                    )
                    .await
                    {
                        Ok(hello) => hello,
                        Err(error) => {
                            debug!("failed to build Kad hello request for {addr}: {error}");
                            continue;
                        }
                    };
                    debug!(
                        "sending Kad hello request to={} contact_id={} contact_version={} request_ack={}",
                        addr,
                        contact.id,
                        contact.kad_version,
                        request_ack
                    );
                    if let Err(error) = dht
                        .send_packet_with_class(
                            addr,
                            &KadPacket::HelloReq(hello),
                            RpcWorkClass::Maintenance,
                        )
                        .await
                    {
                        debug!("failed to send Kad hello request to {addr}: {error}");
                        continue;
                    }
                    introduced.insert(addr);
                }
            }
        }));

        let coordinator = self.coordinator.clone();
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let snoop_queue = Arc::clone(&self.snoop_queue);
        let indexer_id = self.indexer_id;
        let passive_result_count = Arc::clone(&runtime.passive_result_count);
        let passive_replay_gate = Arc::clone(&runtime.passive_replay_gate);
        let harvest_observability = Arc::clone(&self.harvest_observability);
        let agent_activity = Arc::clone(&self.agent_activity);
        let passive_replay_phase2_fanout = config.p2p.kad.search_phase2_fanout;
        let passive_source_stop_after_results = config.p2p.snoop_queue.source_stop_after_results;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(PASSIVE_SOURCE_CRAWL_SECS)).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }
                let Some(_replay_permit) =
                    try_acquire_passive_replay_gate(&passive_replay_gate, "source-fast-path")
                else {
                    continue;
                };
                let Some(selected_request) =
                    next_passive_replay_request_for_family(&snoop_queue, HarvestFamily::Source)
                        .await
                else {
                    record_passive_replay_idle_for_worker(
                        &harvest_observability,
                        Some(HarvestFamily::Source),
                        Utc::now(),
                    )
                    .await;
                    continue;
                };
                match selected_request {
                    PassiveReplaySelection::Keyword(selected_request) => {
                        let request = selected_request.request;
                        let replay_started_at = Utc::now();
                        let replay_context = HarvestReplayContext {
                            replay_id: Uuid::new_v4(),
                            family: HarvestFamily::Keyword,
                            logical_key: selected_request.logical_key,
                            target: request.target.to_string(),
                            start_position: Some(request.start_position),
                            size: None,
                            restrictive_payload_hex: (!request.restrictive_payload.is_empty())
                                .then(|| hex::encode(&request.restrictive_payload)),
                        };
                        let activity_key = passive_replay_key(replay_context.replay_id);
                        let mut activity_snapshot = new_activity_snapshot(
                            AgentActivityState::PassiveHarvestReplay,
                            replay_started_at,
                        );
                        activity_snapshot.query_or_target = Some(
                            passive_replay_activity_context(
                                HarvestFamily::Keyword,
                                replay_context.target.as_str(),
                            ),
                        );
                        begin_agent_activity(
                            &agent_activity,
                            activity_key.clone(),
                            activity_snapshot.clone(),
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_start(
                                &mut observability,
                                HarvestFamily::Keyword,
                                request.target.to_string(),
                                Some(request.start_position),
                                Some(request.restrictive_payload.len() as u32),
                                replay_started_at,
                            );
                        }
                        info!(
                            "kad passive replay start target={} start_position={} restrictive_bytes={}",
                            request.target,
                            request.start_position,
                            request.restrictive_payload.len()
                        );
                        let outcome = run_passive_keyword_replay(
                            PassiveReplayContext {
                                dht: &dht,
                                coordinator: &coordinator,
                                indexer_id,
                                replay_context: &replay_context,
                                max_phase2_fanout: passive_replay_phase2_fanout,
                                source_stop_after_results: passive_source_stop_after_results,
                                passive_result_count: &passive_result_count,
                                harvest_observability: &harvest_observability,
                            },
                            &request,
                        )
                        .await;
                        let replay_completed_at = Utc::now();
                        record_passive_replay_outcome(
                            &snoop_queue,
                            &replay_context.logical_key,
                            replay_completed_at,
                            outcome.result_count,
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_complete(
                                &mut observability,
                                HarvestFamily::Keyword,
                                replay_completed_at,
                                outcome.result_count,
                                outcome.batch_count,
                                outcome.tier_summaries.clone(),
                            );
                        }
                        if let Err(error) = coordinator
                            .post_harvest_replay(&HarvestReplayRecord {
                                replay_id: replay_context.replay_id,
                                indexer_id,
                                family: replay_context.family,
                                logical_key: replay_context.logical_key.clone(),
                                target: replay_context.target.clone(),
                                start_position: replay_context.start_position,
                                size: replay_context.size,
                                restrictive_payload_hex: replay_context
                                    .restrictive_payload_hex
                                    .clone(),
                                started_at: replay_started_at,
                                completed_at: replay_completed_at,
                                result_count: outcome.result_count as u32,
                                batch_count: outcome.batch_count as u32,
                                error: outcome.last_post_error.clone(),
                            })
                            .await
                        {
                            debug!("failed to post harvest replay summary: {error}");
                        }
                        info!(
                            "kad passive replay done results={} batches_posted={}",
                            outcome.result_count, outcome.batch_count
                        );
                        finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                        if let Some(error) = outcome.last_post_error.clone() {
                            activity_snapshot.last_error = Some(error);
                            activity_snapshot.last_update_at = Utc::now();
                            record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
                        } else {
                            clear_agent_degraded_activity(&agent_activity).await;
                        }
                    }
                    PassiveReplaySelection::Source(selected_request) => {
                        let request = selected_request.request;
                        let replay_started_at = Utc::now();
                        let replay_context = HarvestReplayContext {
                            replay_id: Uuid::new_v4(),
                            family: HarvestFamily::Source,
                            logical_key: selected_request.logical_key,
                            target: request.target.to_string(),
                            start_position: Some(request.start_position),
                            size: Some(request.size),
                            restrictive_payload_hex: None,
                        };
                        let activity_key = passive_replay_key(replay_context.replay_id);
                        let mut activity_snapshot = new_activity_snapshot(
                            AgentActivityState::PassiveHarvestReplay,
                            replay_started_at,
                        );
                        activity_snapshot.query_or_target = Some(
                            passive_replay_activity_context(
                                HarvestFamily::Source,
                                replay_context.target.as_str(),
                            ),
                        );
                        begin_agent_activity(
                            &agent_activity,
                            activity_key.clone(),
                            activity_snapshot.clone(),
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_start(
                                &mut observability,
                                HarvestFamily::Source,
                                request.target.to_string(),
                                Some(request.start_position),
                                None,
                                replay_started_at,
                            );
                        }
                        debug!(
                            "kad passive source replay start target={} start_position={} size={}",
                            request.target, request.start_position, request.size
                        );
                        let outcome = run_passive_source_replay(
                            PassiveReplayContext {
                                dht: &dht,
                                coordinator: &coordinator,
                                indexer_id,
                                replay_context: &replay_context,
                                max_phase2_fanout: passive_replay_phase2_fanout,
                                source_stop_after_results: passive_source_stop_after_results,
                                passive_result_count: &passive_result_count,
                                harvest_observability: &harvest_observability,
                            },
                            &request,
                        )
                        .await;
                        let replay_completed_at = Utc::now();
                        record_passive_replay_outcome(
                            &snoop_queue,
                            &replay_context.logical_key,
                            replay_completed_at,
                            outcome.result_count,
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_complete(
                                &mut observability,
                                HarvestFamily::Source,
                                replay_completed_at,
                                outcome.result_count,
                                outcome.batch_count,
                                outcome.tier_summaries.clone(),
                            );
                        }
                        if let Err(error) = coordinator
                            .post_harvest_replay(&HarvestReplayRecord {
                                replay_id: replay_context.replay_id,
                                indexer_id,
                                family: replay_context.family,
                                logical_key: replay_context.logical_key.clone(),
                                target: replay_context.target.clone(),
                                start_position: replay_context.start_position,
                                size: replay_context.size,
                                restrictive_payload_hex: replay_context
                                    .restrictive_payload_hex
                                    .clone(),
                                started_at: replay_started_at,
                                completed_at: replay_completed_at,
                                result_count: outcome.result_count as u32,
                                batch_count: outcome.batch_count as u32,
                                error: outcome.last_post_error.clone(),
                            })
                            .await
                        {
                            debug!("failed to post source harvest replay summary: {error}");
                        }
                        debug!(
                            "kad passive source replay done results={} batches_posted={}",
                            outcome.result_count, outcome.batch_count
                        );
                        finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                        if let Some(error) = outcome.last_post_error.clone() {
                            activity_snapshot.last_error = Some(error);
                            activity_snapshot.last_update_at = Utc::now();
                            record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
                        } else {
                            clear_agent_degraded_activity(&agent_activity).await;
                        }
                    }
                    PassiveReplaySelection::Notes(selected_request) => {
                        let request = selected_request.request;
                        let replay_started_at = Utc::now();
                        let replay_context = HarvestReplayContext {
                            replay_id: Uuid::new_v4(),
                            family: HarvestFamily::Notes,
                            logical_key: selected_request.logical_key,
                            target: request.target.to_string(),
                            start_position: None,
                            size: Some(request.size),
                            restrictive_payload_hex: None,
                        };
                        let activity_key = passive_replay_key(replay_context.replay_id);
                        let mut activity_snapshot = new_activity_snapshot(
                            AgentActivityState::PassiveHarvestReplay,
                            replay_started_at,
                        );
                        activity_snapshot.query_or_target = Some(
                            passive_replay_activity_context(
                                HarvestFamily::Notes,
                                replay_context.target.as_str(),
                            ),
                        );
                        begin_agent_activity(
                            &agent_activity,
                            activity_key.clone(),
                            activity_snapshot.clone(),
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_start(
                                &mut observability,
                                HarvestFamily::Notes,
                                request.target.to_string(),
                                None,
                                None,
                                replay_started_at,
                            );
                        }
                        info!(
                            "kad passive notes replay start target={} size={}",
                            request.target, request.size
                        );
                        let outcome = run_passive_notes_replay(
                            PassiveReplayContext {
                                dht: &dht,
                                coordinator: &coordinator,
                                indexer_id,
                                replay_context: &replay_context,
                                max_phase2_fanout: passive_replay_phase2_fanout,
                                source_stop_after_results: passive_source_stop_after_results,
                                passive_result_count: &passive_result_count,
                                harvest_observability: &harvest_observability,
                            },
                            &request,
                        )
                        .await;
                        let replay_completed_at = Utc::now();
                        record_passive_replay_outcome(
                            &snoop_queue,
                            &replay_context.logical_key,
                            replay_completed_at,
                            outcome.result_count,
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_complete(
                                &mut observability,
                                HarvestFamily::Notes,
                                replay_completed_at,
                                outcome.result_count,
                                outcome.batch_count,
                                outcome.tier_summaries.clone(),
                            );
                        }
                        if let Err(error) = coordinator
                            .post_harvest_replay(&HarvestReplayRecord {
                                replay_id: replay_context.replay_id,
                                indexer_id,
                                family: replay_context.family,
                                logical_key: replay_context.logical_key.clone(),
                                target: replay_context.target.clone(),
                                start_position: replay_context.start_position,
                                size: replay_context.size,
                                restrictive_payload_hex: replay_context
                                    .restrictive_payload_hex
                                    .clone(),
                                started_at: replay_started_at,
                                completed_at: replay_completed_at,
                                result_count: outcome.result_count as u32,
                                batch_count: outcome.batch_count as u32,
                                error: outcome.last_post_error.clone(),
                            })
                            .await
                        {
                            debug!("failed to post notes harvest replay summary: {error}");
                        }
                        info!(
                            "kad passive notes replay done results={} batches_posted={}",
                            outcome.result_count, outcome.batch_count
                        );
                        finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                        if let Some(error) = outcome.last_post_error.clone() {
                            activity_snapshot.last_error = Some(error);
                            activity_snapshot.last_update_at = Utc::now();
                            record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
                        } else {
                            clear_agent_degraded_activity(&agent_activity).await;
                        }
                    }
                }
            }
        }));

        let coordinator = self.coordinator.clone();
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let snoop_queue = Arc::clone(&self.snoop_queue);
        let indexer_id = self.indexer_id;
        let passive_result_count = Arc::clone(&runtime.passive_result_count);
        let passive_replay_gate = Arc::clone(&runtime.passive_replay_gate);
        let harvest_observability = Arc::clone(&self.harvest_observability);
        let agent_activity = Arc::clone(&self.agent_activity);
        let passive_replay_phase2_fanout = config.p2p.kad.search_phase2_fanout;
        let passive_source_stop_after_results = config.p2p.snoop_queue.source_stop_after_results;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(PASSIVE_GENERAL_CRAWL_SECS)).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }
                let Some(_replay_permit) =
                    try_acquire_passive_replay_gate(&passive_replay_gate, "general")
                else {
                    continue;
                };
                let Some(selected_request) = next_passive_replay_request(&snoop_queue).await else {
                    record_passive_replay_idle_for_worker(
                        &harvest_observability,
                        None,
                        Utc::now(),
                    )
                    .await;
                    continue;
                };
                match selected_request {
                    PassiveReplaySelection::Keyword(selected_request) => {
                        let request = selected_request.request;
                        let replay_started_at = Utc::now();
                        let replay_context = HarvestReplayContext {
                            replay_id: Uuid::new_v4(),
                            family: HarvestFamily::Keyword,
                            logical_key: selected_request.logical_key,
                            target: request.target.to_string(),
                            start_position: Some(request.start_position),
                            size: None,
                            restrictive_payload_hex: (!request.restrictive_payload.is_empty())
                                .then(|| hex::encode(&request.restrictive_payload)),
                        };
                        let activity_key = passive_replay_key(replay_context.replay_id);
                        let mut activity_snapshot = new_activity_snapshot(
                            AgentActivityState::PassiveHarvestReplay,
                            replay_started_at,
                        );
                        activity_snapshot.query_or_target = Some(
                            passive_replay_activity_context(
                                HarvestFamily::Keyword,
                                replay_context.target.as_str(),
                            ),
                        );
                        begin_agent_activity(
                            &agent_activity,
                            activity_key.clone(),
                            activity_snapshot.clone(),
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_start(
                                &mut observability,
                                HarvestFamily::Keyword,
                                request.target.to_string(),
                                Some(request.start_position),
                                Some(request.restrictive_payload.len() as u32),
                                replay_started_at,
                            );
                        }
                        info!(
                            "kad passive replay start target={} start_position={} restrictive_bytes={}",
                            request.target,
                            request.start_position,
                            request.restrictive_payload.len()
                        );
                        let outcome = run_passive_keyword_replay(
                            PassiveReplayContext {
                                dht: &dht,
                                coordinator: &coordinator,
                                indexer_id,
                                replay_context: &replay_context,
                                max_phase2_fanout: passive_replay_phase2_fanout,
                                source_stop_after_results: passive_source_stop_after_results,
                                passive_result_count: &passive_result_count,
                                harvest_observability: &harvest_observability,
                            },
                            &request,
                        )
                        .await;
                        let replay_completed_at = Utc::now();
                        record_passive_replay_outcome(
                            &snoop_queue,
                            &replay_context.logical_key,
                            replay_completed_at,
                            outcome.result_count,
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_complete(
                                &mut observability,
                                HarvestFamily::Keyword,
                                replay_completed_at,
                                outcome.result_count,
                                outcome.batch_count,
                                outcome.tier_summaries.clone(),
                            );
                        }
                        if let Err(error) = coordinator
                            .post_harvest_replay(&HarvestReplayRecord {
                                replay_id: replay_context.replay_id,
                                indexer_id,
                                family: replay_context.family,
                                logical_key: replay_context.logical_key.clone(),
                                target: replay_context.target.clone(),
                                start_position: replay_context.start_position,
                                size: replay_context.size,
                                restrictive_payload_hex: replay_context
                                    .restrictive_payload_hex
                                    .clone(),
                                started_at: replay_started_at,
                                completed_at: replay_completed_at,
                                result_count: outcome.result_count as u32,
                                batch_count: outcome.batch_count as u32,
                                error: outcome.last_post_error.clone(),
                            })
                            .await
                        {
                            debug!("failed to post harvest replay summary: {error}");
                        }
                        info!(
                            "kad passive replay done results={} batches_posted={}",
                            outcome.result_count, outcome.batch_count
                        );
                        finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                        if let Some(error) = outcome.last_post_error.clone() {
                            activity_snapshot.last_error = Some(error);
                            activity_snapshot.last_update_at = Utc::now();
                            record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
                        } else {
                            clear_agent_degraded_activity(&agent_activity).await;
                        }
                    }
                    PassiveReplaySelection::Source(selected_request) => {
                        let request = selected_request.request;
                        let replay_started_at = Utc::now();
                        let replay_context = HarvestReplayContext {
                            replay_id: Uuid::new_v4(),
                            family: HarvestFamily::Source,
                            logical_key: selected_request.logical_key,
                            target: request.target.to_string(),
                            start_position: Some(request.start_position),
                            size: Some(request.size),
                            restrictive_payload_hex: None,
                        };
                        let activity_key = passive_replay_key(replay_context.replay_id);
                        let mut activity_snapshot = new_activity_snapshot(
                            AgentActivityState::PassiveHarvestReplay,
                            replay_started_at,
                        );
                        activity_snapshot.query_or_target = Some(
                            passive_replay_activity_context(
                                HarvestFamily::Source,
                                replay_context.target.as_str(),
                            ),
                        );
                        begin_agent_activity(
                            &agent_activity,
                            activity_key.clone(),
                            activity_snapshot.clone(),
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_start(
                                &mut observability,
                                HarvestFamily::Source,
                                request.target.to_string(),
                                Some(request.start_position),
                                None,
                                replay_started_at,
                            );
                        }
                        debug!(
                            "kad passive source replay start target={} start_position={} size={}",
                            request.target, request.start_position, request.size
                        );
                        let outcome = run_passive_source_replay(
                            PassiveReplayContext {
                                dht: &dht,
                                coordinator: &coordinator,
                                indexer_id,
                                replay_context: &replay_context,
                                max_phase2_fanout: passive_replay_phase2_fanout,
                                source_stop_after_results: passive_source_stop_after_results,
                                passive_result_count: &passive_result_count,
                                harvest_observability: &harvest_observability,
                            },
                            &request,
                        )
                        .await;
                        let replay_completed_at = Utc::now();
                        record_passive_replay_outcome(
                            &snoop_queue,
                            &replay_context.logical_key,
                            replay_completed_at,
                            outcome.result_count,
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_complete(
                                &mut observability,
                                HarvestFamily::Source,
                                replay_completed_at,
                                outcome.result_count,
                                outcome.batch_count,
                                outcome.tier_summaries.clone(),
                            );
                        }
                        if let Err(error) = coordinator
                            .post_harvest_replay(&HarvestReplayRecord {
                                replay_id: replay_context.replay_id,
                                indexer_id,
                                family: replay_context.family,
                                logical_key: replay_context.logical_key.clone(),
                                target: replay_context.target.clone(),
                                start_position: replay_context.start_position,
                                size: replay_context.size,
                                restrictive_payload_hex: replay_context
                                    .restrictive_payload_hex
                                    .clone(),
                                started_at: replay_started_at,
                                completed_at: replay_completed_at,
                                result_count: outcome.result_count as u32,
                                batch_count: outcome.batch_count as u32,
                                error: outcome.last_post_error.clone(),
                            })
                            .await
                        {
                            debug!("failed to post source harvest replay summary: {error}");
                        }
                        debug!(
                            "kad passive source replay done results={} batches_posted={}",
                            outcome.result_count, outcome.batch_count
                        );
                        finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                        if let Some(error) = outcome.last_post_error.clone() {
                            activity_snapshot.last_error = Some(error);
                            activity_snapshot.last_update_at = Utc::now();
                            record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
                        } else {
                            clear_agent_degraded_activity(&agent_activity).await;
                        }
                    }
                    PassiveReplaySelection::Notes(selected_request) => {
                        let request = selected_request.request;
                        let replay_started_at = Utc::now();
                        let replay_context = HarvestReplayContext {
                            replay_id: Uuid::new_v4(),
                            family: HarvestFamily::Notes,
                            logical_key: selected_request.logical_key,
                            target: request.target.to_string(),
                            start_position: None,
                            size: Some(request.size),
                            restrictive_payload_hex: None,
                        };
                        let activity_key = passive_replay_key(replay_context.replay_id);
                        let mut activity_snapshot = new_activity_snapshot(
                            AgentActivityState::PassiveHarvestReplay,
                            replay_started_at,
                        );
                        activity_snapshot.query_or_target = Some(
                            passive_replay_activity_context(
                                HarvestFamily::Notes,
                                replay_context.target.as_str(),
                            ),
                        );
                        begin_agent_activity(
                            &agent_activity,
                            activity_key.clone(),
                            activity_snapshot.clone(),
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_start(
                                &mut observability,
                                HarvestFamily::Notes,
                                request.target.to_string(),
                                None,
                                None,
                                replay_started_at,
                            );
                        }
                        info!(
                            "kad passive notes replay start target={} size={}",
                            request.target, request.size
                        );
                        let outcome = run_passive_notes_replay(
                            PassiveReplayContext {
                                dht: &dht,
                                coordinator: &coordinator,
                                indexer_id,
                                replay_context: &replay_context,
                                max_phase2_fanout: passive_replay_phase2_fanout,
                                source_stop_after_results: passive_source_stop_after_results,
                                passive_result_count: &passive_result_count,
                                harvest_observability: &harvest_observability,
                            },
                            &request,
                        )
                        .await;
                        let replay_completed_at = Utc::now();
                        record_passive_replay_outcome(
                            &snoop_queue,
                            &replay_context.logical_key,
                            replay_completed_at,
                            outcome.result_count,
                        )
                        .await;
                        {
                            let mut observability = harvest_observability.lock().await;
                            record_passive_replay_complete(
                                &mut observability,
                                HarvestFamily::Notes,
                                replay_completed_at,
                                outcome.result_count,
                                outcome.batch_count,
                                outcome.tier_summaries.clone(),
                            );
                        }
                        if let Err(error) = coordinator
                            .post_harvest_replay(&HarvestReplayRecord {
                                replay_id: replay_context.replay_id,
                                indexer_id,
                                family: replay_context.family,
                                logical_key: replay_context.logical_key.clone(),
                                target: replay_context.target.clone(),
                                start_position: replay_context.start_position,
                                size: replay_context.size,
                                restrictive_payload_hex: replay_context
                                    .restrictive_payload_hex
                                    .clone(),
                                started_at: replay_started_at,
                                completed_at: replay_completed_at,
                                result_count: outcome.result_count as u32,
                                batch_count: outcome.batch_count as u32,
                                error: outcome.last_post_error.clone(),
                            })
                            .await
                        {
                            debug!("failed to post notes harvest replay summary: {error}");
                        }
                        info!(
                            "kad passive notes replay done results={} batches_posted={}",
                            outcome.result_count, outcome.batch_count
                        );
                        finish_agent_activity(&agent_activity, &activity_key, Utc::now()).await;
                        if let Some(error) = outcome.last_post_error.clone() {
                            activity_snapshot.last_error = Some(error);
                            activity_snapshot.last_update_at = Utc::now();
                            record_agent_degraded_activity(&agent_activity, activity_snapshot).await;
                        } else {
                            clear_agent_degraded_activity(&agent_activity).await;
                        }
                    }
                }
            }
        }));

        let coordinator = self.coordinator.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let snoop_queue = Arc::clone(&self.snoop_queue);
        let observed_snoop_events = Arc::clone(&self.observed_snoop_events);
        let indexer_id = self.indexer_id;
        let agent_activity = Arc::clone(&self.agent_activity);
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(SNOOP_FLUSH_SECS)).await;
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                let flush_started_at = Utc::now();
                let mut flush_snapshot =
                    new_activity_snapshot(AgentActivityState::FlushingSnoops, flush_started_at);
                flush_snapshot.query_or_target = Some(format!("indexer={indexer_id}"));
                begin_agent_activity(
                    &agent_activity,
                    ACTIVITY_KEY_FLUSHING_SNOOPS.to_string(),
                    flush_snapshot,
                )
                .await;
                if let Err(error) = flush_snoop_queue(
                    &coordinator,
                    indexer_id,
                    &snoop_queue,
                    &observed_snoop_events,
                )
                .await
                {
                    let error_message = error.to_string();
                    debug!("snoop flush failed: {error_message}");
                    update_agent_activity_error(
                        &agent_activity,
                        ACTIVITY_KEY_FLUSHING_SNOOPS,
                        error_message.clone(),
                        Utc::now(),
                    )
                    .await;
                    let mut degraded_snapshot =
                        new_activity_snapshot(AgentActivityState::Degraded, Utc::now());
                    degraded_snapshot.query_or_target = Some("snoop flush".to_string());
                    degraded_snapshot.last_error = Some(error_message);
                    record_agent_degraded_activity(&agent_activity, degraded_snapshot).await;
                } else {
                    clear_agent_degraded_activity(&agent_activity).await;
                }
                finish_agent_activity(&agent_activity, ACTIVITY_KEY_FLUSHING_SNOOPS, Utc::now())
                    .await;
            }
        }));

        let coordinator = self.coordinator.clone();
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let local_store = Arc::clone(&self.local_store);
        let publish_batch_gate = Arc::clone(&self.publish_batch_gate);
        let publish_observability = Arc::clone(&self.publish_observability);
        let agent_activity = Arc::clone(&self.agent_activity);
        let ed2k_shared_catalog = Arc::clone(&runtime.ed2k_shared_catalog);
        let active_ed2k_downloads = Arc::clone(&self.active_ed2k_downloads);
        let source_publish_identity = source_publish_client_hash(self.ed2k_user_hash);
        let source_publish_settings = SourcePublishSettings {
            tcp_port: config.p2p.ed2k.listen_port,
            obfuscation_enabled: config.p2p.ed2k.obfuscation_enabled,
        };
        let notes_publish_enabled = config.p2p.kad.seed_notes_publish_enabled;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            let mut synthetic_cursor = 0usize;
            let mut deferred_active_download_ticks = 0u8;
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(synthetic_publish_interval_secs.max(1)))
                    .await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }
                if !active_ed2k_downloads.lock().await.is_empty() {
                    deferred_active_download_ticks =
                        deferred_active_download_ticks.saturating_add(1);
                    if deferred_active_download_ticks < 8 {
                        debug!("deferring synthetic publish drip while ED2K downloads are active");
                        continue;
                    }
                } else {
                    deferred_active_download_ticks = 0;
                }

                match fetch_coordinator_popular_hashes(&coordinator).await {
                    Ok(Some(_)) => {
                        set_synthetic_publish_queue_depth(
                            &publish_observability,
                            SYNTHETIC_POPULAR_SEEDS.len(),
                        )
                        .await;
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        debug!("synthetic publish drip coordinator fetch failed: {error}");
                    }
                }

                let batch = next_synthetic_publish_batch(
                    &mut synthetic_cursor,
                    synthetic_publish_batch_items,
                );
                let remaining_items = synthetic_publish_queue_depth(synthetic_cursor);
                set_synthetic_publish_queue_depth(&publish_observability, remaining_items).await;
                if batch.is_empty() {
                    continue;
                }
                if let Err(error) = seed_popular_with_activity(
                    &dht,
                    source_publish_identity,
                    source_publish_settings,
                    PublishSeedSource::SyntheticFallback,
                    batch,
                    &ed2k_shared_catalog,
                    PublishExecutionContext {
                        local_store: &local_store,
                        publish_batch_gate: &publish_batch_gate,
                        publish_observability: &publish_observability,
                        agent_activity: &agent_activity,
                        activity_key: None,
                        notes_publish_enabled,
                        work_class: RpcWorkClass::Publish,
                        publish_contact_fanout: synthetic_publish_contact_fanout,
                    },
                )
                .await
                {
                    debug!("synthetic publish drip failed: {error}");
                }
            }
        }));

        let coordinator = self.coordinator.clone();
        let dht = runtime.dht.clone();
        let shutdown = Arc::clone(&runtime.shutdown);
        let republish_secs = config.p2p.kad.republish_interval_secs;
        let local_store = Arc::clone(&self.local_store);
        let publish_batch_gate = Arc::clone(&self.publish_batch_gate);
        let publish_observability = Arc::clone(&self.publish_observability);
        let agent_activity = Arc::clone(&self.agent_activity);
        let ed2k_shared_catalog = Arc::clone(&runtime.ed2k_shared_catalog);
        let source_publish_identity = source_publish_client_hash(self.ed2k_user_hash);
        let source_publish_settings = SourcePublishSettings {
            tcp_port: config.p2p.ed2k.listen_port,
            obfuscation_enabled: config.p2p.ed2k.obfuscation_enabled,
        };
        let notes_publish_enabled = config.p2p.kad.seed_notes_publish_enabled;
        runtime.tasks.lock().await.push(tokio::spawn(async move {
            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(republish_secs)).await;
                if shutdown.load(Ordering::Relaxed) || !dht.is_bootstrapped() {
                    continue;
                }
                if let Err(error) = seed_coordinator_popular_if_available(
                    &dht,
                    source_publish_identity,
                    source_publish_settings,
                    &coordinator,
                    &ed2k_shared_catalog,
                    PublishExecutionContext {
                        local_store: &local_store,
                        publish_batch_gate: &publish_batch_gate,
                        publish_observability: &publish_observability,
                        agent_activity: &agent_activity,
                        activity_key: None,
                        notes_publish_enabled,
                        work_class: RpcWorkClass::Publish,
                        publish_contact_fanout,
                    },
                )
                .await
                {
                    debug!("coordinator republish cycle failed: {error}");
                }
            }
        }));
    }
}
