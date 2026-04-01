use std::collections::{HashMap, VecDeque};
use std::str::FromStr;

use chrono::{DateTime, TimeDelta, Utc};
use overlord_agent_common::SnoopEntry;
use overlord_kad_proto::{NodeId, SearchKeyReq, SearchNotesReq, SearchSourceReq};

use crate::config::SnoopQueueConfig;

/// In-memory scheduler state for harvested KAD search requests.
#[derive(Debug, Clone)]
pub struct SnoopQueue {
    config: SnoopQueueConfig,
    entries: HashMap<String, SnoopEntry>,
    replay_feedback: HashMap<String, ReplayFeedback>,
    recent_general_drains: VecDeque<DateTime<Utc>>,
    recent_source_drains: VecDeque<DateTime<Utc>>,
}

/// Outcome of recording one harvested search shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnoopRecordOutcome {
    pub is_new: bool,
    pub hit_count: u32,
    pub queue_depth: usize,
    pub family_queue_depth: usize,
}

/// Current queue depth by harvested Kad search family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SnoopQueueFamilyCounts {
    pub keyword: usize,
    pub source: usize,
    pub notes: usize,
}

/// One queued snoop entry selected for an active passive replay cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledSnoopRequest<Request> {
    pub logical_key: String,
    pub request: Request,
}

/// In-memory replay feedback used to bias the next passive replay choice.
///
/// This state is intentionally process-local: it helps the scheduler avoid
/// spending every crawl cycle on the same zero-yield shape, but it should not
/// become persisted queue metadata yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ReplayFeedback {
    zero_result_streak: u32,
    last_result_count: u32,
    last_outcome_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayCandidate<Request> {
    scheduled: ScheduledSnoopRequest<Request>,
    hit_count: u32,
    last_seen: DateTime<Utc>,
    zero_result_streak: u32,
    last_result_count: u32,
    observed_after_outcome: bool,
}

impl SnoopQueue {
    /// Creates an empty snoop queue with the provided scheduling settings.
    pub fn new(config: SnoopQueueConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            replay_feedback: HashMap::new(),
            recent_general_drains: VecDeque::new(),
            recent_source_drains: VecDeque::new(),
        }
    }

    /// Restores persisted entries into the in-memory queue.
    pub fn merge_snapshot(&mut self, entries: Vec<SnoopEntry>) {
        for entry in entries {
            if should_skip_restored_entry(&entry) {
                continue;
            }
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
        let family = entry_family(&entry);
        let (is_new, hit_count) = self.merge_entry(entry);
        SnoopRecordOutcome {
            is_new,
            hit_count,
            queue_depth: self.entries.len(),
            family_queue_depth: self.family_count(family),
        }
    }

    /// Returns the current queue depth for each harvested search family.
    pub fn family_counts(&self) -> SnoopQueueFamilyCounts {
        let mut counts = SnoopQueueFamilyCounts::default();
        for entry in self.entries.values() {
            match entry_family(entry) {
                SnoopFamily::Keyword => counts.keyword += 1,
                SnoopFamily::Source => counts.source += 1,
                SnoopFamily::Notes => counts.notes += 1,
            }
        }
        counts
    }

    /// Selects the next keyword request eligible for passive drain and marks it as drained.
    pub fn select_next_keyword_request(
        &mut self,
        now: DateTime<Utc>,
    ) -> Option<ScheduledSnoopRequest<SearchKeyReq>> {
        let family = SnoopFamily::Keyword;
        self.prune_recent_drains(now, family);
        if self.recent_drain_len(family) >= self.family_max_queries_per_600s(family) as usize {
            return None;
        }

        let dedup_cutoff = now - seconds(self.config.dedup_window_secs);
        let cooldown_secs = self.family_drain_cooldown_secs(family);
        let cooldown_cutoff = now - seconds(cooldown_secs);
        let mut recent = Vec::new();
        let mut stale = Vec::new();

        for entry in self.entries.values() {
            let Some(request) = keyword_request(entry) else {
                continue;
            };
            let logical_key = entry.logical_key().to_string();
            let feedback = self
                .replay_feedback
                .get(&logical_key)
                .copied()
                .unwrap_or_default();
            if entry.last_drained_at().is_some_and(|last_drained_at| {
                last_drained_at
                    > replay_cooldown_cutoff(cooldown_cutoff, now, cooldown_secs, entry, feedback)
            }) {
                continue;
            }
            let candidate = ReplayCandidate {
                scheduled: ScheduledSnoopRequest {
                    logical_key,
                    request,
                },
                hit_count: entry.hit_count(),
                last_seen: entry.last_seen(),
                zero_result_streak: feedback.zero_result_streak,
                last_result_count: feedback.last_result_count,
                observed_after_outcome: feedback
                    .last_outcome_at
                    .is_none_or(|last_outcome_at| entry.last_seen() > last_outcome_at),
            };
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
        if let Some(entry) = self.entries.get_mut(&selected.scheduled.logical_key) {
            entry.set_last_drained_at(Some(now));
        }
        self.recent_drains_mut(family).push_back(now);
        Some(selected.scheduled)
    }

    /// Selects the next source request eligible for passive drain and marks it as drained.
    pub fn select_next_source_request(
        &mut self,
        now: DateTime<Utc>,
    ) -> Option<ScheduledSnoopRequest<SearchSourceReq>> {
        let family = SnoopFamily::Source;
        self.prune_recent_drains(now, family);
        if self.recent_drain_len(family) >= self.family_max_queries_per_600s(family) as usize {
            return None;
        }

        let dedup_cutoff = now - seconds(self.config.dedup_window_secs);
        let cooldown_secs = self.family_drain_cooldown_secs(family);
        let cooldown_cutoff = now - seconds(cooldown_secs);
        let mut recent = Vec::new();
        let mut stale = Vec::new();

        for entry in self.entries.values() {
            let Some(request) = source_request(entry) else {
                continue;
            };
            let logical_key = entry.logical_key().to_string();
            let feedback = self
                .replay_feedback
                .get(&logical_key)
                .copied()
                .unwrap_or_default();
            if entry.last_drained_at().is_some_and(|last_drained_at| {
                last_drained_at
                    > replay_cooldown_cutoff(cooldown_cutoff, now, cooldown_secs, entry, feedback)
            }) {
                continue;
            }
            let candidate = ReplayCandidate {
                scheduled: ScheduledSnoopRequest {
                    logical_key,
                    request,
                },
                hit_count: entry.hit_count(),
                last_seen: entry.last_seen(),
                zero_result_streak: feedback.zero_result_streak,
                last_result_count: feedback.last_result_count,
                observed_after_outcome: feedback
                    .last_outcome_at
                    .is_none_or(|last_outcome_at| entry.last_seen() > last_outcome_at),
            };
            if entry.last_seen() >= dedup_cutoff {
                recent.push(candidate);
            } else {
                stale.push(candidate);
            }
        }

        let selected = select_best_source_candidate(recent, stale)?;
        if let Some(entry) = self.entries.get_mut(&selected.scheduled.logical_key) {
            entry.set_last_drained_at(Some(now));
        }
        self.recent_drains_mut(family).push_back(now);
        Some(selected.scheduled)
    }

    /// Selects the next notes request eligible for passive drain and marks it as drained.
    pub fn select_next_notes_request(
        &mut self,
        now: DateTime<Utc>,
    ) -> Option<ScheduledSnoopRequest<SearchNotesReq>> {
        let family = SnoopFamily::Notes;
        self.prune_recent_drains(now, family);
        if self.recent_drain_len(family) >= self.family_max_queries_per_600s(family) as usize {
            return None;
        }

        let dedup_cutoff = now - seconds(self.config.dedup_window_secs);
        let cooldown_secs = self.family_drain_cooldown_secs(family);
        let cooldown_cutoff = now - seconds(cooldown_secs);
        let mut recent = Vec::new();
        let mut stale = Vec::new();

        for entry in self.entries.values() {
            let Some(request) = notes_request(entry) else {
                continue;
            };
            let logical_key = entry.logical_key().to_string();
            let feedback = self
                .replay_feedback
                .get(&logical_key)
                .copied()
                .unwrap_or_default();
            if entry.last_drained_at().is_some_and(|last_drained_at| {
                last_drained_at
                    > replay_cooldown_cutoff(cooldown_cutoff, now, cooldown_secs, entry, feedback)
            }) {
                continue;
            }
            let candidate = ReplayCandidate {
                scheduled: ScheduledSnoopRequest {
                    logical_key,
                    request,
                },
                hit_count: entry.hit_count(),
                last_seen: entry.last_seen(),
                zero_result_streak: feedback.zero_result_streak,
                last_result_count: feedback.last_result_count,
                observed_after_outcome: feedback
                    .last_outcome_at
                    .is_none_or(|last_outcome_at| entry.last_seen() > last_outcome_at),
            };
            if entry.last_seen() >= dedup_cutoff {
                recent.push(candidate);
            } else {
                stale.push(candidate);
            }
        }

        recent.sort_by(notes_candidate_cmp);
        stale.sort_by(notes_candidate_cmp);
        let selected = recent
            .into_iter()
            .next()
            .or_else(|| stale.into_iter().next())?;
        if let Some(entry) = self.entries.get_mut(&selected.scheduled.logical_key) {
            entry.set_last_drained_at(Some(now));
        }
        self.recent_drains_mut(family).push_back(now);
        Some(selected.scheduled)
    }

    /// Records the result density of one completed passive replay cycle.
    pub fn record_replay_outcome(
        &mut self,
        logical_key: &str,
        completed_at: DateTime<Utc>,
        result_count: usize,
    ) {
        if result_count > 0 {
            // Successful passive replays are demand-driven one-shots. Remove the drained
            // shape so fresh observations immediately reclaim scheduling priority instead of
            // keeping a growing backlog of already-served requests across sessions.
            self.entries.remove(logical_key);
            self.replay_feedback.remove(logical_key);
            return;
        }
        let feedback = self
            .replay_feedback
            .entry(logical_key.to_string())
            .or_default();
        feedback.last_result_count = result_count as u32;
        feedback.last_outcome_at = Some(completed_at);
        if result_count == 0 {
            feedback.zero_result_streak = feedback.zero_result_streak.saturating_add(1);
            if feedback.zero_result_streak >= 2
                && self
                    .entries
                    .get(logical_key)
                    .is_some_and(should_evict_zero_yield_source_entry)
            {
                self.entries.remove(logical_key);
                self.replay_feedback.remove(logical_key);
            }
        } else {
            feedback.zero_result_streak = 0;
        }
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

    fn prune_recent_drains(&mut self, now: DateTime<Utc>, family: SnoopFamily) {
        let cutoff = now - TimeDelta::minutes(10);
        let recent_drains = self.recent_drains_mut(family);
        while recent_drains
            .front()
            .is_some_and(|drained_at| drained_at < &cutoff)
        {
            recent_drains.pop_front();
        }
    }

    fn family_count(&self, family: SnoopFamily) -> usize {
        self.entries
            .values()
            .filter(|entry| entry_family(entry) == family)
            .count()
    }

    fn family_max_queries_per_600s(&self, family: SnoopFamily) -> u32 {
        match family {
            SnoopFamily::Keyword | SnoopFamily::Notes => self.config.general_max_queries_per_600s,
            SnoopFamily::Source => self.config.source_max_queries_per_600s,
        }
    }

    fn family_drain_cooldown_secs(&self, family: SnoopFamily) -> u64 {
        match family {
            SnoopFamily::Keyword | SnoopFamily::Notes => self.config.general_drain_cooldown_secs,
            SnoopFamily::Source => self.config.source_drain_cooldown_secs,
        }
    }

    fn recent_drain_len(&self, family: SnoopFamily) -> usize {
        match family {
            SnoopFamily::Keyword | SnoopFamily::Notes => self.recent_general_drains.len(),
            SnoopFamily::Source => self.recent_source_drains.len(),
        }
    }

    fn recent_drains_mut(&mut self, family: SnoopFamily) -> &mut VecDeque<DateTime<Utc>> {
        match family {
            SnoopFamily::Keyword | SnoopFamily::Notes => &mut self.recent_general_drains,
            SnoopFamily::Source => &mut self.recent_source_drains,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnoopFamily {
    Keyword,
    Source,
    Notes,
}

fn entry_family(entry: &SnoopEntry) -> SnoopFamily {
    match entry {
        SnoopEntry::Keyword { .. } => SnoopFamily::Keyword,
        SnoopEntry::Source { .. } => SnoopFamily::Source,
        SnoopEntry::Notes { .. } => SnoopFamily::Notes,
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

fn source_request(entry: &SnoopEntry) -> Option<SearchSourceReq> {
    let SnoopEntry::Source {
        target,
        start_position,
        size,
        ..
    } = entry
    else {
        return None;
    };
    if *size == 0 {
        return None;
    }
    Some(SearchSourceReq {
        target: NodeId::from_str(target).ok()?,
        start_position: *start_position,
        size: *size,
    })
}

fn notes_request(entry: &SnoopEntry) -> Option<SearchNotesReq> {
    let SnoopEntry::Notes { target, size, .. } = entry else {
        return None;
    };
    if *size == 0 {
        return None;
    }
    Some(SearchNotesReq {
        target: NodeId::from_str(target).ok()?,
        size: *size,
    })
}

fn seconds(value: u64) -> TimeDelta {
    TimeDelta::seconds(i64::try_from(value).unwrap_or(i64::MAX))
}

fn candidate_cmp(
    left: &ReplayCandidate<SearchKeyReq>,
    right: &ReplayCandidate<SearchKeyReq>,
) -> std::cmp::Ordering {
    right
        .observed_after_outcome
        .cmp(&left.observed_after_outcome)
        .then_with(|| left.zero_result_streak.cmp(&right.zero_result_streak))
        .then_with(|| right.last_result_count.cmp(&left.last_result_count))
        .then_with(|| right.hit_count.cmp(&left.hit_count))
        .then_with(|| right.last_seen.cmp(&left.last_seen))
        .then_with(|| left.scheduled.logical_key.cmp(&right.scheduled.logical_key))
}

fn source_candidate_cmp(
    left: &ReplayCandidate<SearchSourceReq>,
    right: &ReplayCandidate<SearchSourceReq>,
) -> std::cmp::Ordering {
    right
        .observed_after_outcome
        .cmp(&left.observed_after_outcome)
        .then_with(|| {
            source_candidate_is_high_quality(right).cmp(&source_candidate_is_high_quality(left))
        })
        .then_with(|| left.zero_result_streak.cmp(&right.zero_result_streak))
        .then_with(|| right.last_result_count.cmp(&left.last_result_count))
        .then_with(|| right.hit_count.cmp(&left.hit_count))
        .then_with(|| right.last_seen.cmp(&left.last_seen))
        .then_with(|| left.scheduled.logical_key.cmp(&right.scheduled.logical_key))
}

fn source_candidate_is_high_quality(candidate: &ReplayCandidate<SearchSourceReq>) -> bool {
    candidate.hit_count >= 2 || candidate.last_result_count > 0
}

fn select_best_source_candidate(
    recent: Vec<ReplayCandidate<SearchSourceReq>>,
    stale: Vec<ReplayCandidate<SearchSourceReq>>,
) -> Option<ReplayCandidate<SearchSourceReq>> {
    // Prefer repeated or previously successful source demand, but do not let the
    // source worker go idle while fresh one-off requests accumulate on the real network.
    let promoted = recent
        .iter()
        .chain(stale.iter())
        .any(source_candidate_is_high_quality);
    let mut recent = recent;
    let mut stale = stale;
    if promoted {
        recent.retain(source_candidate_is_high_quality);
        stale.retain(source_candidate_is_high_quality);
    }
    recent.sort_by(source_candidate_cmp);
    stale.sort_by(source_candidate_cmp);
    recent
        .into_iter()
        .next()
        .or_else(|| stale.into_iter().next())
}

fn notes_candidate_cmp(
    left: &ReplayCandidate<SearchNotesReq>,
    right: &ReplayCandidate<SearchNotesReq>,
) -> std::cmp::Ordering {
    right
        .observed_after_outcome
        .cmp(&left.observed_after_outcome)
        .then_with(|| left.zero_result_streak.cmp(&right.zero_result_streak))
        .then_with(|| right.last_result_count.cmp(&left.last_result_count))
        .then_with(|| right.hit_count.cmp(&left.hit_count))
        .then_with(|| right.last_seen.cmp(&left.last_seen))
        .then_with(|| left.scheduled.logical_key.cmp(&right.scheduled.logical_key))
}

fn replay_cooldown_cutoff(
    default_cutoff: DateTime<Utc>,
    now: DateTime<Utc>,
    drain_cooldown_secs: u64,
    entry: &SnoopEntry,
    feedback: ReplayFeedback,
) -> DateTime<Utc> {
    let Some(last_outcome_at) = feedback.last_outcome_at else {
        return default_cutoff;
    };
    if feedback.zero_result_streak == 0 || entry.last_seen() > last_outcome_at {
        return default_cutoff;
    }
    let zero_backoff_multiplier = u64::from(feedback.zero_result_streak.saturating_add(1)).min(4);
    let cooldown_secs = drain_cooldown_secs.saturating_mul(zero_backoff_multiplier);
    now - seconds(cooldown_secs)
}

fn should_skip_restored_entry(entry: &SnoopEntry) -> bool {
    match entry {
        SnoopEntry::Source { .. } => {
            entry
                .last_drained_at()
                .is_some_and(|last_drained_at| entry.last_seen() <= last_drained_at)
                || entry.hit_count() <= 1
        }
        _ => false,
    }
}

fn should_evict_zero_yield_source_entry(entry: &SnoopEntry) -> bool {
    matches!(entry, SnoopEntry::Source { .. })
        && entry
            .last_drained_at()
            .is_some_and(|last_drained_at| entry.last_seen() <= last_drained_at)
}

#[cfg(test)]
mod tests {
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
}
