use super::*;

#[tokio::test]
async fn restore_and_flush_preserve_last_drained_at() {
    let restored_entry = SnoopEntry::Keyword {
        logical_key: "keyword:00112233445566778899aabbccddeeff:8000:aabb".to_string(),
        target: "00112233445566778899aabbccddeeff".to_string(),
        start_position: 0x8000,
        restrictive_payload_hex: Some("aabb".to_string()),
        hit_count: 4,
        first_seen: Utc.with_ymd_and_hms(2026, 3, 21, 10, 0, 0).unwrap(),
        last_seen: Utc.with_ymd_and_hms(2026, 3, 21, 10, 5, 0).unwrap(),
        last_drained_at: Some(Utc.with_ymd_and_hms(2026, 3, 21, 10, 6, 0).unwrap()),
    };
    let (addr, flushed_entries) = spawn_mock_coordinator(vec![restored_entry.clone()]).await;
    let coordinator = CoordinatorClient::new(&format!("http://{addr}")).unwrap();
    let queue = Arc::new(Mutex::new(SnoopQueue::new(SnoopQueueConfig::default())));
    let observed_snoop_events = Arc::new(Mutex::new(Vec::new()));
    let indexer_id = Uuid::from_u128(0x22222222222222222222222222222222);

    restore_snoop_queue(&coordinator, indexer_id, &queue).await;
    flush_snoop_queue(&coordinator, indexer_id, &queue, &observed_snoop_events)
        .await
        .unwrap();

    let flushed_entries = flushed_entries.lock().await.clone();
    assert_eq!(flushed_entries, vec![restored_entry]);
}
