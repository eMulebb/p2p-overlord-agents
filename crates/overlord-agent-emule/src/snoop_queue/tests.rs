use chrono::{TimeZone, Utc};
use overlord_agent_common::SnoopEntry;
use overlord_kad_proto::{SearchKeyReq, SearchNotesReq, SearchSourceReq};

use super::{ScheduledSnoopRequest, SnoopQueue, SnoopQueueFamilyCounts};
use crate::config::SnoopQueueConfig;

fn queue() -> SnoopQueue {
    SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 60,
        general_max_queries_per_600s: 2,
        general_drain_cooldown_secs: 30,
        source_max_queries_per_600s: 2,
        source_drain_cooldown_secs: 30,
        source_stop_after_results: 2,
    })
}

fn ts(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().unwrap()
}

fn keyword_entry(
    logical_key: &str,
    target: &str,
    start_position: u16,
    restrictive_payload_hex: Option<&str>,
    seen_at: i64,
) -> SnoopEntry {
    SnoopEntry::Keyword {
        logical_key: logical_key.to_string(),
        target: target.to_string(),
        start_position,
        restrictive_payload_hex: restrictive_payload_hex.map(str::to_string),
        hit_count: 1,
        first_seen: ts(seen_at),
        last_seen: ts(seen_at),
        last_drained_at: None,
    }
}

fn source_entry(
    logical_key: &str,
    target: &str,
    start_position: u16,
    size: u64,
    seen_at: i64,
) -> SnoopEntry {
    SnoopEntry::Source {
        logical_key: logical_key.to_string(),
        target: target.to_string(),
        start_position,
        size,
        hit_count: 1,
        first_seen: ts(seen_at),
        last_seen: ts(seen_at),
        last_drained_at: None,
    }
}

fn notes_entry(logical_key: &str, target: &str, size: u64, seen_at: i64) -> SnoopEntry {
    SnoopEntry::Notes {
        logical_key: logical_key.to_string(),
        target: target.to_string(),
        size,
        hit_count: 1,
        first_seen: ts(seen_at),
        last_seen: ts(seen_at),
        last_drained_at: None,
    }
}

#[test]
fn repeated_hits_merge_and_preserve_first_seen() {
    let mut queue = queue();
    let entry = keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        100,
    );
    queue.record(entry.clone());
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        140,
    ));

    let snapshot = queue.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].hit_count(), 2);
    assert_eq!(snapshot[0].first_seen(), ts(100));
    assert_eq!(snapshot[0].last_seen(), ts(140));
}

#[test]
fn source_and_notes_entries_are_not_selected_for_keyword_drain() {
    let mut queue = queue();
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(notes_entry(
        "notes:00112233445566778899aabbccddeeff:4096",
        "00112233445566778899aabbccddeeff",
        4096,
        110,
    ));
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        120,
    ));

    let selected = queue.select_next_keyword_request(ts(130));
    assert!(selected.is_some());
}

#[test]
fn source_drain_selects_source_entries_without_keyword_shapes() {
    let mut queue = queue();
    queue.record(notes_entry(
        "notes:00112233445566778899aabbccddeeff:4096",
        "00112233445566778899aabbccddeeff",
        4096,
        100,
    ));
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:8000:4096",
        "00112233445566778899aabbccddeeff",
        0x8000,
        4096,
        110,
    ));
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:8000:4096",
        "00112233445566778899aabbccddeeff",
        0x8000,
        4096,
        111,
    ));

    let selected = queue.select_next_source_request(ts(130));
    assert_eq!(
        selected,
        Some(ScheduledSnoopRequest {
            logical_key: "source:00112233445566778899aabbccddeeff:8000:4096".to_string(),
            request: SearchSourceReq {
                target: "00112233445566778899aabbccddeeff".parse().unwrap(),
                start_position: 0x8000,
                size: 4096,
            },
        })
    );
}

#[test]
fn notes_drain_selects_notes_entries_with_size_shape() {
    let mut queue = queue();
    queue.record(notes_entry(
        "notes:00112233445566778899aabbccddeeff:4096",
        "00112233445566778899aabbccddeeff",
        4096,
        110,
    ));

    let selected = queue.select_next_notes_request(ts(130));
    assert_eq!(
        selected,
        Some(ScheduledSnoopRequest {
            logical_key: "notes:00112233445566778899aabbccddeeff:4096".to_string(),
            request: SearchNotesReq {
                target: "00112233445566778899aabbccddeeff".parse().unwrap(),
                size: 4096,
            },
        })
    );
}

#[test]
fn source_drain_skips_zero_sized_requests() {
    let mut queue = queue();
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:0",
        "00112233445566778899aabbccddeeff",
        0,
        0,
        100,
    ));
    queue.record(source_entry(
        "source:11112222333344445555666677778888:0000:8192",
        "11112222333344445555666677778888",
        0,
        8192,
        110,
    ));
    queue.record(source_entry(
        "source:11112222333344445555666677778888:0000:8192",
        "11112222333344445555666677778888",
        0,
        8192,
        111,
    ));

    let selected = queue.select_next_source_request(ts(130));
    assert_eq!(
        selected,
        Some(ScheduledSnoopRequest {
            logical_key: "source:11112222333344445555666677778888:0000:8192".to_string(),
            request: SearchSourceReq {
                target: "11112222333344445555666677778888".parse().unwrap(),
                start_position: 0,
                size: 8192,
            },
        })
    );
}

#[test]
fn different_keyword_payloads_do_not_collapse() {
    let mut queue = queue();
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:8000:aabb",
        "00112233445566778899aabbccddeeff",
        0x8000,
        Some("aabb"),
        100,
    ));
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:8000:ccdd",
        "00112233445566778899aabbccddeeff",
        0x8000,
        Some("ccdd"),
        110,
    ));

    let snapshot = queue.snapshot();
    assert_eq!(snapshot.len(), 2);
}

#[test]
fn cooldown_blocks_immediate_reselection_and_later_allows_retry() {
    let mut queue = queue();
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        100,
    ));

    assert!(queue.select_next_keyword_request(ts(110)).is_some());
    assert!(queue.select_next_keyword_request(ts(120)).is_none());
    assert!(queue.select_next_keyword_request(ts(141)).is_some());
}

#[test]
fn rate_limit_caps_drains_within_ten_minutes() {
    let mut queue = queue();
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        100,
    ));
    queue.record(keyword_entry(
        "keyword:11112222333344445555666677778888:0000",
        "11112222333344445555666677778888",
        0,
        None,
        101,
    ));
    queue.record(keyword_entry(
        "keyword:9999aaaabbbbccccddddeeeeffff0000:0000",
        "9999aaaabbbbccccddddeeeeffff0000",
        0,
        None,
        102,
    ));

    assert!(queue.select_next_keyword_request(ts(110)).is_some());
    assert!(queue.select_next_keyword_request(ts(150)).is_some());
    assert!(queue.select_next_keyword_request(ts(200)).is_none());
    assert!(queue.select_next_keyword_request(ts(711)).is_some());
}

#[test]
fn snapshot_merge_round_trips_last_drained_at_and_payload() {
    let mut queue = queue();
    let entry = SnoopEntry::Keyword {
        logical_key: "keyword:00112233445566778899aabbccddeeff:8000:aabb".to_string(),
        target: "00112233445566778899aabbccddeeff".to_string(),
        start_position: 0x8000,
        restrictive_payload_hex: Some("aabb".to_string()),
        hit_count: 5,
        first_seen: ts(100),
        last_seen: ts(120),
        last_drained_at: Some(ts(130)),
    };

    queue.merge_snapshot(vec![entry.clone()]);
    let snapshot = queue.snapshot();
    assert_eq!(snapshot, vec![entry.clone()]);

    let selected = queue.select_next_keyword_request(ts(1000)).unwrap();
    assert_eq!(
        selected,
        ScheduledSnoopRequest {
            logical_key: "keyword:00112233445566778899aabbccddeeff:8000:aabb".to_string(),
            request: SearchKeyReq {
                target: "00112233445566778899aabbccddeeff".parse().unwrap(),
                start_position: 0x8000,
                restrictive_payload: vec![0xAA, 0xBB],
            },
        }
    );
}

#[test]
fn zero_result_replays_back_off_until_fresh_demand_reappears() {
    let mut queue = queue();
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        101,
    ));

    let selected = queue.select_next_source_request(ts(110)).unwrap();
    assert_eq!(
        selected.logical_key,
        "source:00112233445566778899aabbccddeeff:0000:4096"
    );
    queue.record_replay_outcome(&selected.logical_key, ts(120), 0);

    assert!(queue.select_next_source_request(ts(151)).is_none());

    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        170,
    ));
    assert!(queue.select_next_source_request(ts(171)).is_some());
}

#[test]
fn zero_result_history_is_deprioritized_behind_unseen_candidates() {
    let mut queue = queue();
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        101,
    ));
    let selected = queue.select_next_source_request(ts(110)).unwrap();
    queue.record_replay_outcome(&selected.logical_key, ts(120), 0);

    queue.record(source_entry(
        "source:11112222333344445555666677778888:0000:8192",
        "11112222333344445555666677778888",
        0,
        8192,
        121,
    ));
    queue.record(source_entry(
        "source:11112222333344445555666677778888:0000:8192",
        "11112222333344445555666677778888",
        0,
        8192,
        122,
    ));

    let next_selected = queue.select_next_source_request(ts(160)).unwrap();
    assert_eq!(
        next_selected.logical_key,
        "source:11112222333344445555666677778888:0000:8192"
    );
}

#[test]
fn successful_replay_evicts_drained_entry() {
    let mut queue = queue();
    let logical_key = "source:00112233445566778899aabbccddeeff:0000:4096";
    queue.record(source_entry(
        logical_key,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));

    queue.record_replay_outcome(logical_key, ts(120), 3);

    assert!(queue.snapshot().is_empty());
    assert_eq!(queue.family_counts(), SnoopQueueFamilyCounts::default());
}

#[test]
fn repeated_zero_yield_source_entry_is_evicted() {
    let mut queue = queue();
    let logical_key = "source:00112233445566778899aabbccddeeff:0000:4096";
    queue.record(source_entry(
        logical_key,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(source_entry(
        logical_key,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        101,
    ));

    let selected = queue.select_next_source_request(ts(110)).unwrap();
    queue.record_replay_outcome(&selected.logical_key, ts(120), 0);
    let selected = queue.select_next_source_request(ts(200)).unwrap();
    queue.record_replay_outcome(&selected.logical_key, ts(210), 0);

    assert!(queue.snapshot().is_empty());
}

#[test]
fn source_drain_uses_dedicated_rate_budget() {
    let mut queue = SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 60,
        general_max_queries_per_600s: 1,
        general_drain_cooldown_secs: 30,
        source_max_queries_per_600s: 2,
        source_drain_cooldown_secs: 30,
        source_stop_after_results: 2,
    });
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        100,
    ));
    queue.record(source_entry(
        "source:11112222333344445555666677778888:0000:4096",
        "11112222333344445555666677778888",
        0,
        4096,
        101,
    ));
    queue.record(source_entry(
        "source:11112222333344445555666677778888:0000:4096",
        "11112222333344445555666677778888",
        0,
        4096,
        102,
    ));

    assert!(queue.select_next_keyword_request(ts(110)).is_some());
    assert!(queue.select_next_source_request(ts(111)).is_some());
}

#[test]
fn source_drain_uses_shorter_dedicated_cooldown() {
    let mut queue = SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 60,
        general_max_queries_per_600s: 4,
        general_drain_cooldown_secs: 90,
        source_max_queries_per_600s: 4,
        source_drain_cooldown_secs: 20,
        source_stop_after_results: 2,
    });
    let logical_key = "source:00112233445566778899aabbccddeeff:0000:4096";
    queue.record(source_entry(
        logical_key,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(source_entry(
        logical_key,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        101,
    ));

    let selected = queue.select_next_source_request(ts(110)).unwrap();
    queue.record_replay_outcome(&selected.logical_key, ts(111), 0);
    queue.record(source_entry(
        logical_key,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        131,
    ));

    assert!(queue.select_next_source_request(ts(132)).is_some());
}

#[test]
fn source_drain_prefers_repeated_hot_entries() {
    let mut queue = queue();
    let repeated = "source:00112233445566778899aabbccddeeff:0000:4096";
    let fresh = "source:11112222333344445555666677778888:0000:8192";
    queue.record(source_entry(
        repeated,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(source_entry(
        repeated,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        101,
    ));
    queue.record(source_entry(
        fresh,
        "11112222333344445555666677778888",
        0,
        8192,
        110,
    ));

    let selected = queue.select_next_source_request(ts(130)).unwrap();

    assert_eq!(selected.logical_key, repeated);
}

#[test]
fn one_off_source_entries_backfill_source_drain_when_queue_would_idle() {
    let mut queue = queue();
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));

    assert!(queue.select_next_source_request(ts(130)).is_some());
}

#[test]
fn second_hit_promotes_probationary_source_entry() {
    let mut queue = queue();
    let logical_key = "source:00112233445566778899aabbccddeeff:0000:4096";
    queue.record(source_entry(
        logical_key,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(source_entry(
        logical_key,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        101,
    ));

    let selected = queue.select_next_source_request(ts(130)).unwrap();

    assert_eq!(selected.logical_key, logical_key);
}

#[test]
fn repeated_source_entries_still_beat_one_off_backfill() {
    let mut queue = queue();
    let repeated = "source:00112233445566778899aabbccddeeff:0000:4096";
    let one_off = "source:11112222333344445555666677778888:0000:8192";
    queue.record(source_entry(
        repeated,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(source_entry(
        repeated,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        101,
    ));
    queue.record(source_entry(
        one_off,
        "11112222333344445555666677778888",
        0,
        8192,
        110,
    ));

    let selected = queue.select_next_source_request(ts(130)).unwrap();

    assert_eq!(selected.logical_key, repeated);
}

#[test]
fn restore_skips_drained_source_entries_without_fresh_demand() {
    let mut queue = queue();
    queue.merge_snapshot(vec![
        SnoopEntry::Source {
            logical_key: "source:00112233445566778899aabbccddeeff:0000:4096".to_string(),
            target: "00112233445566778899aabbccddeeff".to_string(),
            start_position: 0,
            size: 4096,
            hit_count: 3,
            first_seen: ts(100),
            last_seen: ts(120),
            last_drained_at: Some(ts(130)),
        },
        SnoopEntry::Source {
            logical_key: "source:11112222333344445555666677778888:0000:8192".to_string(),
            target: "11112222333344445555666677778888".to_string(),
            start_position: 0,
            size: 8192,
            hit_count: 2,
            first_seen: ts(100),
            last_seen: ts(140),
            last_drained_at: Some(ts(130)),
        },
    ]);

    let snapshot = queue.snapshot();

    assert_eq!(snapshot.len(), 1);
    assert_eq!(
        snapshot[0].logical_key(),
        "source:11112222333344445555666677778888:0000:8192"
    );
}

#[test]
fn restore_skips_probationary_one_off_source_entries() {
    let mut queue = queue();
    queue.merge_snapshot(vec![
        SnoopEntry::Source {
            logical_key: "source:00112233445566778899aabbccddeeff:0000:4096".to_string(),
            target: "00112233445566778899aabbccddeeff".to_string(),
            start_position: 0,
            size: 4096,
            hit_count: 1,
            first_seen: ts(100),
            last_seen: ts(120),
            last_drained_at: None,
        },
        SnoopEntry::Source {
            logical_key: "source:11112222333344445555666677778888:0000:8192".to_string(),
            target: "11112222333344445555666677778888".to_string(),
            start_position: 0,
            size: 8192,
            hit_count: 2,
            first_seen: ts(100),
            last_seen: ts(121),
            last_drained_at: None,
        },
    ]);

    let snapshot = queue.snapshot();

    assert_eq!(snapshot.len(), 1);
    assert_eq!(
        snapshot[0].logical_key(),
        "source:11112222333344445555666677778888:0000:8192"
    );
}

#[test]
fn family_counts_report_each_variant_depth() {
    let mut queue = queue();
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        100,
    ));
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        110,
    ));
    queue.record(notes_entry(
        "notes:00112233445566778899aabbccddeeff:4096",
        "00112233445566778899aabbccddeeff",
        4096,
        120,
    ));

    assert_eq!(
        queue.family_counts(),
        SnoopQueueFamilyCounts {
            keyword: 1,
            source: 1,
            notes: 1,
        }
    );
}
