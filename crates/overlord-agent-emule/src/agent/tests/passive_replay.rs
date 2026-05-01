use super::*;

#[test]
fn apply_harvest_record_tracks_keyword_request_shape() {
    let mut observability = KadHarvestObservability::default();
    let entry = SnoopEntry::Keyword {
        logical_key: "keyword:00112233445566778899aabbccddeeff:8000:aabb".to_string(),
        target: "00112233445566778899aabbccddeeff".to_string(),
        start_position: 0x8000,
        restrictive_payload_hex: Some("aabb".to_string()),
        hit_count: 1,
        first_seen: Utc.with_ymd_and_hms(2026, 3, 22, 19, 58, 0).unwrap(),
        last_seen: Utc.with_ymd_and_hms(2026, 3, 22, 19, 58, 0).unwrap(),
        last_drained_at: None,
    };

    apply_harvest_record(
        &mut observability,
        "127.0.0.1:41000".parse().unwrap(),
        &entry,
        true,
    );

    assert_eq!(observability.keyword_requests.observed_requests, 1);
    assert_eq!(observability.keyword_requests.unique_shapes_observed, 1);
    assert_eq!(
        observability.keyword_requests.last_target.as_deref(),
        Some("00112233445566778899aabbccddeeff")
    );
    assert_eq!(
        observability.keyword_requests.last_start_position,
        Some(0x8000)
    );
    assert_eq!(
        observability.keyword_requests.last_restrictive_bytes,
        Some(2)
    );
    assert_eq!(
        observability.keyword_requests.last_from.as_deref(),
        Some("127.0.0.1:41000")
    );
}

#[test]
fn apply_queue_family_counts_updates_live_depths() {
    let mut observability = KadHarvestObservability::default();

    apply_queue_family_counts(
        &mut observability,
        SnoopQueueFamilyCounts {
            keyword: 2,
            source: 3,
            notes: 1,
        },
    );

    assert_eq!(observability.keyword_requests.queued_entries, 2);
    assert_eq!(observability.source_requests.queued_entries, 3);
    assert_eq!(observability.notes_requests.queued_entries, 1);
}

#[test]
fn passive_keyword_replay_observability_tracks_cycle_lifecycle() {
    let mut observability = KadHarvestObservability::default();
    let request = SearchKeyReq {
        target: "00112233445566778899aabbccddeeff".parse().unwrap(),
        start_position: 0x8000,
        restrictive_payload: vec![0xAA, 0xBB, 0xCC],
    };
    let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 20, 0, 0).unwrap();
    let idle_at = Utc.with_ymd_and_hms(2026, 3, 22, 20, 1, 0).unwrap();
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 22, 20, 2, 0).unwrap();
    let failed_at = Utc.with_ymd_and_hms(2026, 3, 22, 20, 3, 0).unwrap();
    let tier_summaries = vec![
        KadPassiveReplayTierSummary {
            responder_ceiling: 10,
            result_count: 2,
        },
        KadPassiveReplayTierSummary {
            responder_ceiling: 20,
            result_count: 5,
        },
    ];

    record_passive_replay_idle(&mut observability, HarvestFamily::Keyword, idle_at);
    record_passive_replay_start(
        &mut observability,
        HarvestFamily::Keyword,
        request.target.to_string(),
        Some(request.start_position),
        Some(request.restrictive_payload.len() as u32),
        started_at,
    );
    record_passive_replay_complete(
        &mut observability,
        HarvestFamily::Keyword,
        completed_at,
        7,
        2,
        tier_summaries.clone(),
    );
    record_passive_replay_post_failure(
        &mut observability,
        HarvestFamily::Keyword,
        failed_at,
        "post failed",
    );
    record_passive_replay_enqueue_wait(
        &mut observability,
        HarvestFamily::Keyword,
        Duration::from_millis(12),
        true,
    );
    record_passive_replay_post_latency(
        &mut observability,
        HarvestFamily::Keyword,
        Duration::from_millis(34),
    );

    assert_eq!(observability.passive_keyword_replay.idle_cycles, 1);
    assert_eq!(observability.passive_keyword_replay.started_cycles, 1);
    assert_eq!(observability.passive_keyword_replay.completed_cycles, 1);
    assert_eq!(observability.passive_keyword_replay.emitted_results, 7);
    assert_eq!(observability.passive_keyword_replay.widened_cycles, 1);
    assert_eq!(observability.passive_keyword_replay.posted_batches, 2);
    assert_eq!(observability.passive_keyword_replay.post_failures, 1);
    assert_eq!(
        observability
            .passive_keyword_replay
            .enqueue_backpressure_events,
        1
    );
    assert_eq!(observability.passive_keyword_replay.post_callbacks, 1);
    assert_eq!(observability.passive_keyword_replay.enqueue_wait_millis, 12);
    assert_eq!(observability.passive_keyword_replay.post_latency_millis, 34);
    assert_eq!(
        observability.passive_keyword_replay.last_target.as_deref(),
        Some("00112233445566778899aabbccddeeff")
    );
    assert_eq!(
        observability.passive_keyword_replay.last_start_position,
        Some(0x8000)
    );
    assert_eq!(
        observability.passive_keyword_replay.last_restrictive_bytes,
        Some(3)
    );
    assert_eq!(observability.passive_keyword_replay.last_result_count, 7);
    assert_eq!(observability.passive_keyword_replay.last_batches_posted, 2);
    assert_eq!(
        observability
            .passive_keyword_replay
            .last_enqueue_wait_millis,
        12
    );
    assert_eq!(
        observability
            .passive_keyword_replay
            .last_post_latency_millis,
        34
    );
    assert_eq!(observability.passive_keyword_replay.last_tiers_attempted, 2);
    assert_eq!(
        observability
            .passive_keyword_replay
            .last_widest_responder_ceiling,
        Some(20)
    );
    assert!(observability.passive_keyword_replay.last_widened);
    assert_eq!(
        observability.passive_keyword_replay.last_tiers,
        tier_summaries
    );
    assert_eq!(
        observability.passive_keyword_replay.last_error.as_deref(),
        Some("post failed")
    );
    assert_eq!(
        observability.passive_keyword_replay.last_completed_at,
        Some(completed_at)
    );
    assert_eq!(
        observability.passive_keyword_replay.last_error_at,
        Some(failed_at)
    );
}

#[test]
fn passive_source_replay_observability_tracks_tiered_cycle_lifecycle() {
    let mut observability = KadHarvestObservability::default();
    let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 21, 0, 0).unwrap();
    let idle_at = Utc.with_ymd_and_hms(2026, 3, 22, 21, 1, 0).unwrap();
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 22, 21, 2, 0).unwrap();
    let tier_summaries = vec![KadPassiveReplayTierSummary {
        responder_ceiling: 10,
        result_count: 4,
    }];

    record_passive_replay_idle(&mut observability, HarvestFamily::Source, idle_at);
    record_passive_replay_start(
        &mut observability,
        HarvestFamily::Source,
        "ffeeddccbbaa99887766554433221100".to_string(),
        Some(0),
        None,
        started_at,
    );
    record_passive_replay_complete(
        &mut observability,
        HarvestFamily::Source,
        completed_at,
        4,
        1,
        tier_summaries.clone(),
    );

    assert_eq!(observability.passive_source_replay.idle_cycles, 1);
    assert_eq!(observability.passive_source_replay.started_cycles, 1);
    assert_eq!(observability.passive_source_replay.completed_cycles, 1);
    assert_eq!(observability.passive_source_replay.emitted_results, 4);
    assert_eq!(observability.passive_source_replay.posted_batches, 1);
    assert_eq!(
        observability.passive_source_replay.last_target.as_deref(),
        Some("ffeeddccbbaa99887766554433221100")
    );
    assert_eq!(
        observability.passive_source_replay.last_start_position,
        Some(0)
    );
    assert_eq!(
        observability.passive_source_replay.last_restrictive_bytes,
        None
    );
    assert_eq!(observability.passive_source_replay.last_tiers_attempted, 1);
    assert_eq!(
        observability
            .passive_source_replay
            .last_widest_responder_ceiling,
        Some(10)
    );
    assert!(!observability.passive_source_replay.last_widened);
    assert_eq!(
        observability.passive_source_replay.last_tiers,
        tier_summaries
    );
    assert_eq!(
        observability.passive_source_replay.last_completed_at,
        Some(completed_at)
    );
}

#[test]
fn passive_notes_replay_observability_uses_dedicated_bucket() {
    let mut observability = KadHarvestObservability::default();
    let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 0, 0).unwrap();
    let idle_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 1, 0).unwrap();
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 2, 0).unwrap();
    let tier_summaries = vec![KadPassiveReplayTierSummary {
        responder_ceiling: 10,
        result_count: 2,
    }];

    record_passive_replay_idle(&mut observability, HarvestFamily::Notes, idle_at);
    record_passive_replay_start(
        &mut observability,
        HarvestFamily::Notes,
        "1234567890abcdef1234567890abcdef".to_string(),
        None,
        None,
        started_at,
    );
    record_passive_replay_complete(
        &mut observability,
        HarvestFamily::Notes,
        completed_at,
        2,
        1,
        tier_summaries.clone(),
    );

    assert_eq!(observability.passive_notes_replay.idle_cycles, 1);
    assert_eq!(observability.passive_notes_replay.started_cycles, 1);
    assert_eq!(observability.passive_notes_replay.completed_cycles, 1);
    assert_eq!(observability.passive_notes_replay.emitted_results, 2);
    assert_eq!(observability.passive_notes_replay.posted_batches, 1);
    assert_eq!(
        observability.passive_notes_replay.last_target.as_deref(),
        Some("1234567890abcdef1234567890abcdef")
    );
    assert_eq!(observability.passive_notes_replay.last_start_position, None);
    assert_eq!(
        observability.passive_notes_replay.last_restrictive_bytes,
        None
    );
    assert_eq!(
        observability.passive_notes_replay.last_tiers,
        tier_summaries
    );
    assert_eq!(
        observability.passive_notes_replay.last_completed_at,
        Some(completed_at)
    );
    assert_eq!(observability.passive_keyword_replay.started_cycles, 0);
}

#[tokio::test]
async fn next_passive_replay_request_prefers_source_when_backlog_is_heavier() {
    let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 60,
        general_max_queries_per_600s: 10,
        general_drain_cooldown_secs: 30,
        source_max_queries_per_600s: 10,
        source_drain_cooldown_secs: 30,
        source_stop_after_results: 2,
    })));
    let now = Utc.with_ymd_and_hms(2026, 3, 24, 15, 12, 0).unwrap();
    {
        let mut guard = queue.lock().await;
        guard.record(build_keyword_snoop_entry(
            &SearchKeyReq {
                target: NodeId::from_bytes([0x11; 16]),
                start_position: 0,
                restrictive_payload: Vec::new(),
            },
            now,
        ));
        guard.record(build_source_snoop_entry(
            &SearchSourceReq {
                target: NodeId::from_bytes([0x22; 16]),
                start_position: 0,
                size: 1_024,
            },
            now,
        ));
        guard.record(build_source_snoop_entry(
            &SearchSourceReq {
                target: NodeId::from_bytes([0x33; 16]),
                start_position: 0,
                size: 2_048,
            },
            now,
        ));
        guard.record(build_source_snoop_entry(
            &SearchSourceReq {
                target: NodeId::from_bytes([0x33; 16]),
                start_position: 0,
                size: 2_048,
            },
            now,
        ));
    }

    let selected = next_passive_replay_request(&queue).await;
    assert!(matches!(selected, Some(PassiveReplaySelection::Source(_))));
}

#[tokio::test]
async fn next_passive_replay_request_selects_notes_when_only_notes_are_queued() {
    let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 60,
        general_max_queries_per_600s: 10,
        general_drain_cooldown_secs: 30,
        source_max_queries_per_600s: 10,
        source_drain_cooldown_secs: 30,
        source_stop_after_results: 2,
    })));
    let now = Utc.with_ymd_and_hms(2026, 3, 24, 15, 14, 0).unwrap();
    {
        let mut guard = queue.lock().await;
        guard.record(build_notes_snoop_entry(
            &SearchNotesReq {
                target: NodeId::from_bytes([0x44; 16]),
                size: 4_096,
            },
            now,
        ));
    }

    let selected = next_passive_replay_request(&queue).await;
    assert!(matches!(selected, Some(PassiveReplaySelection::Notes(_))));
}

#[tokio::test]
async fn passive_replay_gate_allows_two_workers_but_blocks_a_third() {
    let gate = Arc::new(Semaphore::new(PASSIVE_REPLAY_CONCURRENCY));
    let first = try_acquire_passive_replay_gate(&gate, "source-fast-path");
    assert!(first.is_some());
    let second = try_acquire_passive_replay_gate(&gate, "general");
    assert!(second.is_some());
    assert!(try_acquire_passive_replay_gate(&gate, "overflow").is_none());
    drop(first);
    assert!(try_acquire_passive_replay_gate(&gate, "overflow").is_some());
}

#[tokio::test]
async fn source_fast_path_prefers_source_replays() {
    let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 600,
        general_max_queries_per_600s: 10,
        general_drain_cooldown_secs: 30,
        source_max_queries_per_600s: 10,
        source_drain_cooldown_secs: 30,
        source_stop_after_results: 2,
    })));
    let now = Utc::now();
    queue.lock().await.record(build_keyword_snoop_entry(
        &SearchKeyReq {
            target: "00112233445566778899aabbccddeeff".parse().unwrap(),
            start_position: 0,
            restrictive_payload: Vec::new(),
        },
        now,
    ));
    queue.lock().await.record(build_source_snoop_entry(
        &SearchSourceReq {
            target: "11112222333344445555666677778888".parse().unwrap(),
            start_position: 0,
            size: 4096,
        },
        now,
    ));
    queue.lock().await.record(build_source_snoop_entry(
        &SearchSourceReq {
            target: "11112222333344445555666677778888".parse().unwrap(),
            start_position: 0,
            size: 4096,
        },
        now,
    ));

    let selected = next_passive_replay_request_for_family(&queue, HarvestFamily::Source).await;

    assert!(matches!(selected, Some(PassiveReplaySelection::Source(_))));
}

#[tokio::test]
async fn source_fast_path_stays_idle_without_source_backlog() {
    let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 600,
        general_max_queries_per_600s: 10,
        general_drain_cooldown_secs: 30,
        source_max_queries_per_600s: 10,
        source_drain_cooldown_secs: 30,
        source_stop_after_results: 2,
    })));
    queue.lock().await.record(build_keyword_snoop_entry(
        &SearchKeyReq {
            target: "00112233445566778899aabbccddeeff".parse().unwrap(),
            start_position: 0,
            restrictive_payload: Vec::new(),
        },
        Utc::now(),
    ));

    let selected = next_passive_replay_request_for_family(&queue, HarvestFamily::Source).await;

    assert!(selected.is_none());
}
