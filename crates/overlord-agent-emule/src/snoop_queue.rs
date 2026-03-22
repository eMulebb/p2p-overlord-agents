use std::collections::{HashMap, VecDeque};
use std::str::FromStr;

use chrono::{DateTime, TimeDelta, Utc};
use overlord_agent_common::SnoopEntry;
use overlord_kad_proto::{NodeId, SearchKeyReq};

use crate::config::SnoopQueueConfig;

/// In-memory scheduler state for harvested KAD search requests.
#[derive(Debug, Clone)]
pub struct SnoopQueue {
    config: SnoopQueueConfig,
    entries: HashMap<String, SnoopEntry>,
    recent_drains: VecDeque<DateTime<Utc>>,
}

/// Outcome of recording one harvested search shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnoopRecordOutcome {
    pub is_new: bool,
    pub hit_count: u32,
    pub queue_depth: usize,
}

impl SnoopQueue {
    /// Creates an empty snoop queue with the provided scheduling settings.
    pub fn new(config: SnoopQueueConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            recent_drains: VecDeque::new(),
        }
    }

    /// Restores persisted entries into the in-memory queue.
    pub fn merge_snapshot(&mut self, entries: Vec<SnoopEntry>) {
        for entry in entries {
            self.merge_entry(entry);
        }
    }

    /// Returns a snapshot suitable for flush/persistence calls.
    pub fn snapshot(&self) -> Vec<SnoopEntry> {
        let mut entries = self.entries.values().cloned().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.logical_key().cmp(right.logical_key()));
        entries
    }

    /// Returns the number of unique harvested search shapes currently tracked.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Records a harvested search request occurrence.
    pub fn record(&mut self, entry: SnoopEntry) -> SnoopRecordOutcome {
        let (is_new, hit_count) = self.merge_entry(entry);
        SnoopRecordOutcome {
            is_new,
            hit_count,
            queue_depth: self.entries.len(),
        }
    }

    /// Selects the next keyword request eligible for passive drain and marks it as drained.
    pub fn select_next_keyword_request(&mut self, now: DateTime<Utc>) -> Option<SearchKeyReq> {
        self.prune_recent_drains(now);
        if self.recent_drains.len() >= self.config.max_queries_per_600s as usize {
            return None;
        }

        let dedup_cutoff = now - seconds(self.config.dedup_window_secs);
        let cooldown_cutoff = now - seconds(self.config.drain_cooldown_secs);
        let mut recent = Vec::new();
        let mut stale = Vec::new();

        for entry in self.entries.values() {
            let Some(request) = keyword_request(entry) else {
                continue;
            };
            if entry
                .last_drained_at()
                .is_some_and(|last_drained_at| last_drained_at > cooldown_cutoff)
            {
                continue;
            }
            let candidate = (
                request,
                entry.hit_count(),
                entry.last_seen(),
                entry.logical_key().to_string(),
            );
            if entry.last_seen() >= dedup_cutoff {
                recent.push(candidate);
            } else {
                stale.push(candidate);
            }
        }

        recent.sort_by(candidate_cmp);
        stale.sort_by(candidate_cmp);
        let selected = recent
            .into_iter()
            .next()
            .or_else(|| stale.into_iter().next())?;
        if let Some(entry) = self.entries.get_mut(&selected.3) {
            entry.set_last_drained_at(Some(now));
        }
        self.recent_drains.push_back(now);
        Some(selected.0)
    }

    fn merge_entry(&mut self, entry: SnoopEntry) -> (bool, u32) {
        let logical_key = entry.logical_key().to_string();
        if let Some(existing) = self.entries.get_mut(&logical_key) {
            let next_hit_count = existing.hit_count().saturating_add(entry.hit_count());
            existing.set_hit_count(next_hit_count);
            existing.set_last_seen(existing.last_seen().max(entry.last_seen()));
            existing.set_first_seen(existing.first_seen().min(entry.first_seen()));
            existing.set_last_drained_at(
                match (existing.last_drained_at(), entry.last_drained_at()) {
                    (Some(left), Some(right)) => Some(left.max(right)),
                    (Some(left), None) => Some(left),
                    (None, right) => right,
                },
            );
            return (false, next_hit_count);
        }
        self.entries.insert(logical_key, entry);
        (true, 1)
    }

    fn prune_recent_drains(&mut self, now: DateTime<Utc>) {
        let cutoff = now - TimeDelta::minutes(10);
        while self
            .recent_drains
            .front()
            .is_some_and(|drained_at| drained_at < &cutoff)
        {
            self.recent_drains.pop_front();
        }
    }
}

fn keyword_request(entry: &SnoopEntry) -> Option<SearchKeyReq> {
    let SnoopEntry::Keyword {
        target,
        start_position,
        restrictive_payload_hex,
        ..
    } = entry
    else {
        return None;
    };
    let target = NodeId::from_str(target).ok()?;
    let restrictive_payload = restrictive_payload_hex
        .as_deref()
        .map(hex::decode)
        .transpose()
        .ok()?
        .unwrap_or_default();
    Some(SearchKeyReq {
        target,
        start_position: *start_position,
        restrictive_payload,
    })
}

fn seconds(value: u64) -> TimeDelta {
    TimeDelta::seconds(i64::try_from(value).unwrap_or(i64::MAX))
}

fn candidate_cmp(
    left: &(SearchKeyReq, u32, DateTime<Utc>, String),
    right: &(SearchKeyReq, u32, DateTime<Utc>, String),
) -> std::cmp::Ordering {
    right
        .1
        .cmp(&left.1)
        .then_with(|| right.2.cmp(&left.2))
        .then_with(|| left.3.cmp(&right.3))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use overlord_agent_common::SnoopEntry;
    use overlord_kad_proto::SearchKeyReq;

    use super::SnoopQueue;
    use crate::config::SnoopQueueConfig;

    fn queue() -> SnoopQueue {
        SnoopQueue::new(SnoopQueueConfig {
            dedup_window_secs: 60,
            max_queries_per_600s: 2,
            drain_cooldown_secs: 30,
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
            SearchKeyReq {
                target: "00112233445566778899aabbccddeeff".parse().unwrap(),
                start_position: 0x8000,
                restrictive_payload: vec![0xAA, 0xBB],
            }
        );
    }
}
