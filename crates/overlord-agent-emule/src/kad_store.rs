use std::{net::Ipv4Addr, time::Duration};

use chrono::{DateTime, Utc};
use overlord_kad_proto::{
    Ed2kHash, NodeId, PublishEntry, SearchKeyReq, SearchNotesReq, SearchRes, SearchResultEntry,
    SearchSourceReq, Tag, TagName, TagValue, tag_name,
};

use crate::config::KadConfig;

/// Runtime policy for the local Kad publish cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KadLocalStoreConfig {
    pub enabled: bool,
    pub keyword_ttl: Duration,
    pub source_ttl: Duration,
    pub notes_ttl: Duration,
    pub keyword_capacity: usize,
    pub source_capacity: usize,
    pub notes_capacity: usize,
}

impl KadLocalStoreConfig {
    #[must_use]
    pub(crate) fn from_kad_config(config: &KadConfig) -> Self {
        Self {
            enabled: config.local_store_enabled,
            keyword_ttl: Duration::from_secs(config.local_store_keyword_ttl_secs.max(1)),
            source_ttl: Duration::from_secs(config.local_store_source_ttl_secs.max(1)),
            notes_ttl: Duration::from_secs(config.local_store_notes_ttl_secs.max(1)),
            keyword_capacity: config.local_store_keyword_capacity.max(1),
            source_capacity: config.local_store_source_capacity.max(1),
            notes_capacity: config.local_store_notes_capacity.max(1),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct StoredKeywordPublish {
    observed_at: DateTime<Utc>,
    target: NodeId,
    file_hash: Ed2kHash,
    tags: Vec<Tag>,
    dedup_key: String,
}

#[derive(Debug, Clone, PartialEq)]
struct StoredSourcePublish {
    observed_at: DateTime<Utc>,
    target: NodeId,
    publisher_id: NodeId,
    source_ip: Ipv4Addr,
    tags: Vec<Tag>,
    dedup_key: String,
}

#[derive(Debug, Clone, PartialEq)]
struct StoredNotesPublish {
    observed_at: DateTime<Utc>,
    target: NodeId,
    note_hash: Ed2kHash,
    tags: Vec<Tag>,
    dedup_key: String,
}

/// In-memory Kad publish cache used to answer inbound search traffic.
#[derive(Debug, Clone)]
pub(crate) struct KadLocalStore {
    config: KadLocalStoreConfig,
    keyword_entries: Vec<StoredKeywordPublish>,
    source_entries: Vec<StoredSourcePublish>,
    notes_entries: Vec<StoredNotesPublish>,
}

impl KadLocalStore {
    #[must_use]
    pub(crate) fn new(config: KadLocalStoreConfig) -> Self {
        Self {
            config,
            keyword_entries: Vec::new(),
            source_entries: Vec::new(),
            notes_entries: Vec::new(),
        }
    }

    pub(crate) fn record_keyword_publish_batch(
        &mut self,
        target: NodeId,
        entries: &[PublishEntry],
        observed_at: DateTime<Utc>,
    ) {
        if !self.config.enabled {
            return;
        }
        purge_expired(
            &mut self.keyword_entries,
            self.config.keyword_ttl,
            observed_at,
        );
        for entry in entries {
            let dedup_key = keyword_dedup_key(target, entry.hash, &entry.tags);
            upsert_entry(
                &mut self.keyword_entries,
                self.config.keyword_capacity,
                dedup_key.clone(),
                StoredKeywordPublish {
                    observed_at,
                    target,
                    file_hash: entry.hash,
                    tags: entry.tags.clone(),
                    dedup_key,
                },
            );
        }
    }

    pub(crate) fn record_source_publish(
        &mut self,
        target: NodeId,
        publisher_id: NodeId,
        source_ip: Ipv4Addr,
        tags: &[Tag],
        observed_at: DateTime<Utc>,
    ) {
        if !self.config.enabled {
            return;
        }
        purge_expired(
            &mut self.source_entries,
            self.config.source_ttl,
            observed_at,
        );
        let dedup_key = source_dedup_key(target, publisher_id, source_ip, tags);
        upsert_entry(
            &mut self.source_entries,
            self.config.source_capacity,
            dedup_key.clone(),
            StoredSourcePublish {
                observed_at,
                target,
                publisher_id,
                source_ip,
                tags: tags.to_vec(),
                dedup_key,
            },
        );
    }

    pub(crate) fn record_notes_publish(
        &mut self,
        target: NodeId,
        note_hash: Ed2kHash,
        tags: &[Tag],
        observed_at: DateTime<Utc>,
    ) {
        if !self.config.enabled {
            return;
        }
        purge_expired(&mut self.notes_entries, self.config.notes_ttl, observed_at);
        let dedup_key = notes_dedup_key(target, note_hash, tags);
        upsert_entry(
            &mut self.notes_entries,
            self.config.notes_capacity,
            dedup_key.clone(),
            StoredNotesPublish {
                observed_at,
                target,
                note_hash,
                tags: tags.to_vec(),
                dedup_key,
            },
        );
    }

    pub(crate) fn keyword_search_response(
        &mut self,
        sender_id: NodeId,
        request: &SearchKeyReq,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Option<SearchRes> {
        if !self.config.enabled || !request.restrictive_payload.is_empty() || limit == 0 {
            return None;
        }

        purge_expired(&mut self.keyword_entries, self.config.keyword_ttl, now);
        let offset = usize::from(request.start_position & 0x7FFF);
        let results = self
            .keyword_entries
            .iter()
            .filter(|entry| entry.target == request.target)
            .skip(offset)
            .take(limit)
            .map(|entry| SearchResultEntry {
                hash: entry.file_hash,
                tags: entry.tags.clone(),
            })
            .collect::<Vec<_>>();
        search_response(sender_id, request.target, results)
    }

    pub(crate) fn source_search_response(
        &mut self,
        sender_id: NodeId,
        request: &SearchSourceReq,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Option<SearchRes> {
        if !self.config.enabled || limit == 0 {
            return None;
        }

        purge_expired(&mut self.source_entries, self.config.source_ttl, now);
        let offset = usize::from(request.start_position & 0x7FFF);
        let file_hash = Ed2kHash::from_bytes(request.target.0);
        let results = self
            .source_entries
            .iter()
            .filter(|entry| entry.target == request.target)
            .filter(|entry| {
                stored_file_size(&entry.tags)
                    .map(|size| size == request.size)
                    .unwrap_or(true)
            })
            .skip(offset)
            .take(limit)
            .map(|entry| SearchResultEntry {
                hash: file_hash,
                tags: source_result_tags(entry),
            })
            .collect::<Vec<_>>();
        search_response(sender_id, request.target, results)
    }

    pub(crate) fn notes_search_response(
        &mut self,
        sender_id: NodeId,
        request: &SearchNotesReq,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Option<SearchRes> {
        if !self.config.enabled || limit == 0 {
            return None;
        }

        purge_expired(&mut self.notes_entries, self.config.notes_ttl, now);
        let results = self
            .notes_entries
            .iter()
            .filter(|entry| entry.target == request.target)
            .filter(|entry| {
                stored_file_size(&entry.tags)
                    .map(|size| size == request.size)
                    .unwrap_or(true)
            })
            .take(limit)
            .map(|entry| SearchResultEntry {
                hash: entry.note_hash,
                tags: entry.tags.clone(),
            })
            .collect::<Vec<_>>();
        search_response(sender_id, request.target, results)
    }

    #[cfg(test)]
    fn keyword_entry_count(&self) -> usize {
        self.keyword_entries.len()
    }

    #[cfg(test)]
    fn source_entry_count(&self) -> usize {
        self.source_entries.len()
    }

    #[cfg(test)]
    fn notes_entry_count(&self) -> usize {
        self.notes_entries.len()
    }
}

fn search_response(
    sender_id: NodeId,
    target: NodeId,
    results: Vec<SearchResultEntry>,
) -> Option<SearchRes> {
    if results.is_empty() {
        None
    } else {
        Some(SearchRes {
            sender_id,
            keyword_id: target,
            results,
        })
    }
}

fn source_result_tags(entry: &StoredSourcePublish) -> Vec<Tag> {
    let mut saw_source_ip = false;
    let mut tags = entry
        .tags
        .iter()
        .cloned()
        .map(|mut tag| {
            match (&tag.name, &tag.value) {
                (TagName::Short(name), TagValue::UInt(value))
                    if *name == tag_name::SOURCEPORT && u32::try_from(*value).is_ok() =>
                {
                    tag.value = TagValue::U32(*value as u32);
                }
                (TagName::Short(name), TagValue::UInt(value))
                    if *name == tag_name::SOURCEUPORT && u16::try_from(*value).is_ok() =>
                {
                    tag.value = TagValue::U16(*value as u16);
                }
                (TagName::Short(name), _) if *name == tag_name::SOURCEIP => {
                    saw_source_ip = true;
                }
                _ => {}
            }
            tag
        })
        .collect::<Vec<_>>();
    if !saw_source_ip {
        tags.push(Tag::new_short(
            tag_name::SOURCEIP,
            TagValue::U32(u32::from_be_bytes(entry.source_ip.octets())),
        ));
    }
    tags
}

fn stored_file_size(tags: &[Tag]) -> Option<u64> {
    let mut size = None;
    let mut size_low = None;
    let mut size_high = None;

    for tag in tags {
        match &tag.name {
            TagName::Short(name) if *name == tag_name::FILESIZE => match &tag.value {
                TagValue::UInt(value) => size = Some(*value),
                TagValue::U64(value) => size = Some(*value),
                TagValue::U32(value) => size_low = Some(*value),
                TagValue::U16(value) => size_low = Some(u32::from(*value)),
                TagValue::U8(value) => size_low = Some(u32::from(*value)),
                _ => {}
            },
            TagName::Short(name) if *name == tag_name::FILESIZE_HI => match &tag.value {
                TagValue::UInt(value) if u32::try_from(*value).is_ok() => {
                    size_high = Some(*value as u32)
                }
                TagValue::U32(value) => size_high = Some(*value),
                TagValue::U16(value) => size_high = Some(u32::from(*value)),
                TagValue::U8(value) => size_high = Some(u32::from(*value)),
                _ => {}
            },
            _ => {}
        }
    }

    size.or_else(|| {
        size_low.map(|low| {
            let high = size_high.unwrap_or(0);
            (u64::from(high) << 32) | u64::from(low)
        })
    })
}

fn purge_expired<T>(entries: &mut Vec<T>, ttl: Duration, now: DateTime<Utc>)
where
    T: TimedEntry,
{
    entries.retain(|entry| entry.observed_at() + ttl > now);
}

fn upsert_entry<T>(entries: &mut Vec<T>, capacity: usize, dedup_key: String, entry: T)
where
    T: TimedEntry + DedupEntry,
{
    if let Some(existing) = entries
        .iter_mut()
        .find(|candidate| candidate.dedup_key() == dedup_key)
    {
        *existing = entry;
        return;
    }

    if entries.len() >= capacity
        && let Some((oldest_index, _)) = entries
            .iter()
            .enumerate()
            .min_by_key(|(_, candidate)| candidate.observed_at())
    {
        entries.remove(oldest_index);
    }
    entries.push(entry);
}

trait TimedEntry {
    fn observed_at(&self) -> DateTime<Utc>;
}

trait DedupEntry {
    fn dedup_key(&self) -> &str;
}

impl TimedEntry for StoredKeywordPublish {
    fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

impl DedupEntry for StoredKeywordPublish {
    fn dedup_key(&self) -> &str {
        &self.dedup_key
    }
}

impl TimedEntry for StoredSourcePublish {
    fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

impl DedupEntry for StoredSourcePublish {
    fn dedup_key(&self) -> &str {
        &self.dedup_key
    }
}

impl TimedEntry for StoredNotesPublish {
    fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

impl DedupEntry for StoredNotesPublish {
    fn dedup_key(&self) -> &str {
        &self.dedup_key
    }
}

fn keyword_dedup_key(target: NodeId, file_hash: Ed2kHash, tags: &[Tag]) -> String {
    format!("keyword:{target}:{file_hash}:{}", tag_fingerprint(tags))
}

fn source_dedup_key(
    target: NodeId,
    publisher_id: NodeId,
    source_ip: Ipv4Addr,
    tags: &[Tag],
) -> String {
    format!(
        "source:{target}:{publisher_id}:{source_ip}:{}",
        tag_fingerprint(tags)
    )
}

fn notes_dedup_key(target: NodeId, note_hash: Ed2kHash, tags: &[Tag]) -> String {
    format!("notes:{target}:{note_hash}:{}", tag_fingerprint(tags))
}

fn tag_fingerprint(tags: &[Tag]) -> String {
    tags.iter()
        .map(|tag| {
            let name = match &tag.name {
                TagName::Short(value) => format!("short:{value}"),
                TagName::Long(value) => format!("long:{value}"),
            };
            let value = match &tag.value {
                TagValue::Hash(value) => format!("hash:{value}"),
                TagValue::String(value) => format!("string:{value}"),
                TagValue::UInt(value) => format!("uint:{value}"),
                TagValue::U64(value) => format!("u64:{value}"),
                TagValue::U32(value) => format!("u32:{value}"),
                TagValue::U16(value) => format!("u16:{value}"),
                TagValue::U8(value) => format!("u8:{value}"),
                TagValue::Float(value) => format!("float:{value:?}"),
                TagValue::Bool(value) => format!("bool:{value}"),
                TagValue::Blob(value) => format!("blob:{}", hex::encode(value)),
                TagValue::SmallBlob(value) => format!("small_blob:{}", hex::encode(value)),
            };
            format!("{name}={value}")
        })
        .collect::<Vec<_>>()
        .join("|")
}

#[cfg(test)]
mod tests {
    use super::{KadLocalStore, KadLocalStoreConfig, stored_file_size};
    use chrono::{DateTime, TimeZone, Utc};
    use overlord_kad_proto::{
        Ed2kHash, NodeId, PublishEntry, SearchKeyReq, SearchNotesReq, SearchSourceReq, Tag,
        TagName, TagValue, tag_name,
    };
    use std::{net::Ipv4Addr, time::Duration};

    fn config() -> KadLocalStoreConfig {
        KadLocalStoreConfig {
            enabled: true,
            keyword_ttl: Duration::from_secs(60),
            source_ttl: Duration::from_secs(60),
            notes_ttl: Duration::from_secs(60),
            keyword_capacity: 2,
            source_capacity: 2,
            notes_capacity: 2,
        }
    }

    fn ts(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).single().unwrap()
    }

    #[test]
    fn keyword_store_dedupes_and_expires_entries() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([1; 16]);
        let entry = PublishEntry {
            hash: Ed2kHash::from_bytes([2; 16]),
            tags: vec![Tag::filename("ubuntu linux.iso"), Tag::filesize(123)],
        };

        store.record_keyword_publish_batch(target, std::slice::from_ref(&entry), ts(0));
        store.record_keyword_publish_batch(target, std::slice::from_ref(&entry), ts(5));
        assert_eq!(store.keyword_entry_count(), 1);

        let response = store
            .keyword_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
                10,
                ts(30),
            )
            .expect("keyword response");
        assert_eq!(response.results.len(), 1);

        let expired = store.keyword_search_response(
            NodeId::from_bytes([9; 16]),
            &SearchKeyReq {
                target,
                start_position: 0,
                restrictive_payload: Vec::new(),
            },
            10,
            ts(70),
        );
        assert!(expired.is_none());
        assert_eq!(store.keyword_entry_count(), 0);
    }

    #[test]
    fn source_store_eviction_keeps_newest_entries() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let publisher_one = NodeId::from_bytes([4; 16]);
        let publisher_two = NodeId::from_bytes([5; 16]);
        let publisher_three = NodeId::from_bytes([6; 16]);
        let tags = vec![
            Tag::filesize(456),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
        ];

        store.record_source_publish(
            target,
            publisher_one,
            Ipv4Addr::new(1, 1, 1, 1),
            &tags,
            ts(1),
        );
        store.record_source_publish(
            target,
            publisher_two,
            Ipv4Addr::new(2, 2, 2, 2),
            &tags,
            ts(2),
        );
        store.record_source_publish(
            target,
            publisher_three,
            Ipv4Addr::new(3, 3, 3, 3),
            &tags,
            ts(3),
        );

        assert_eq!(store.source_entry_count(), 2);
        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 0,
                    size: 456,
                },
                10,
                ts(3),
            )
            .expect("source response");
        assert_eq!(response.results.len(), 2);
        assert_eq!(response.results[0].hash, Ed2kHash::from_bytes(target.0));
        assert!(response.results.iter().all(|entry| {
            entry
                .tags
                .iter()
                .any(|tag| matches!(&tag.name, TagName::Short(name) if *name == tag_name::SOURCEIP))
        }));
    }

    #[test]
    fn notes_store_filters_by_size_when_available() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([7; 16]);
        let note_hash = Ed2kHash::from_bytes([8; 16]);
        let tags = vec![
            Tag::filesize(900),
            Tag::new_short(tag_name::DESCRIPTION, TagValue::String("good".into())),
        ];

        store.record_notes_publish(target, note_hash, &tags, ts(1));

        let response = store
            .notes_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchNotesReq { target, size: 900 },
                10,
                ts(10),
            )
            .expect("notes response");
        assert_eq!(store.notes_entry_count(), 1);
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].hash, note_hash);

        let missing = store.notes_search_response(
            NodeId::from_bytes([9; 16]),
            &SearchNotesReq { target, size: 901 },
            10,
            ts(10),
        );
        assert!(missing.is_none());
    }

    #[test]
    fn restrictive_keyword_searches_do_not_emit_local_results() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([1; 16]);
        store.record_keyword_publish_batch(
            target,
            &[PublishEntry {
                hash: Ed2kHash::from_bytes([2; 16]),
                tags: vec![Tag::filename("ubuntu linux.iso"), Tag::filesize(123)],
            }],
            ts(1),
        );

        let response = store.keyword_search_response(
            NodeId::from_bytes([9; 16]),
            &SearchKeyReq {
                target,
                start_position: 0x8000,
                restrictive_payload: vec![0xAA],
            },
            10,
            ts(2),
        );
        assert!(response.is_none());
    }

    #[test]
    fn stored_file_size_combines_low_and_high_parts() {
        let size = stored_file_size(&[
            Tag::new_short(tag_name::FILESIZE, TagValue::U32(1)),
            Tag::new_short(tag_name::FILESIZE_HI, TagValue::U32(2)),
        ]);
        assert_eq!(size, Some((2_u64 << 32) | 1));
    }
}
