use std::{fs, net::SocketAddr, path::Path, sync::Arc};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use md4::{Digest, Md4};
use overlord_agent_common::{
    HashType, KadPublishObservability, PopularHash, PublishBatchSummary, PublishCounters,
    PublishSeedSource,
};
use overlord_kad_dht::PublishAttemptStats;
use overlord_kad_proto::{Ed2kHash, NodeId, Tag, TagValue, tag_name};
use rand::RngCore;
use sha1::Sha1;
use tokio::sync::Mutex;
use tracing::info;

use crate::ed2k_tcp::emule_connect_options;
use crate::ed2k_transfer::{Ed2kSharedCatalog, Ed2kSharedEntry};

use super::EMULE_LARGE_FILE_SIZE_THRESHOLD;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SyntheticPopularSeed {
    title: &'static str,
    size: u64,
    source_count: u32,
}

pub(super) const SYNTHETIC_POPULAR_SEEDS: [SyntheticPopularSeed; 40] = [
    SyntheticPopularSeed {
        title: "ubuntu linux 24.04 desktop amd64.iso",
        size: 734_003_200,
        source_count: 31,
    },
    SyntheticPopularSeed {
        title: "mario paint quorlith orchestra live at the moon.avi",
        size: 1_417_965_568,
        source_count: 24,
    },
    SyntheticPopularSeed {
        title: "10 hours of nyan cat.mp4",
        size: 92_381_184,
        source_count: 19,
    },
    SyntheticPopularSeed {
        title: "laser dolphin documentary 1997.mkv",
        size: 2_486_124_544,
        source_count: 16,
    },
    SyntheticPopularSeed {
        title: "cat-powered data center walkthrough.iso",
        size: 4_597_211_136,
        source_count: 11,
    },
    SyntheticPopularSeed {
        title: "unofficial windows 98 vaporwave patch.zip",
        size: 803_471_360,
        source_count: 27,
    },
    SyntheticPopularSeed {
        title: "beep test but every beep is a fax machine.flac",
        size: 558_366_720,
        source_count: 14,
    },
    SyntheticPopularSeed {
        title: "office 2010 professional plus x86.iso",
        size: 128_661_504,
        source_count: 22,
    },
    SyntheticPopularSeed {
        title: "retro hamster workstation benchmark.mov",
        size: 1_934_155_776,
        source_count: 17,
    },
    SyntheticPopularSeed {
        title: "flying toaster championship finals.mp4",
        size: 1_215_102_976,
        source_count: 29,
    },
    SyntheticPopularSeed {
        title: "synthwave aquarium screensaver collection.rar",
        size: 677_478_400,
        source_count: 13,
    },
    SyntheticPopularSeed {
        title: "ubuntu linux server 24.04 live amd64.iso",
        size: 18_456_321,
        source_count: 18,
    },
    SyntheticPopularSeed {
        title: "very long train horn ambience.wav",
        size: 2_812_747_776,
        source_count: 12,
    },
    SyntheticPopularSeed {
        title: "adobe photoshop cs6 portable.rar",
        size: 943_128_576,
        source_count: 15,
    },
    SyntheticPopularSeed {
        title: "windows 7 ultimate sp1 x64 dvd.iso",
        size: 421_388_288,
        source_count: 9,
    },
    SyntheticPopularSeed {
        title: "museum of broken gamepads.pdf",
        size: 67_210_240,
        source_count: 21,
    },
    SyntheticPopularSeed {
        title: "game of thrones season 1 complete 720p.mkv",
        size: 44_992_610,
        source_count: 10,
    },
    SyntheticPopularSeed {
        title: "the office us season 2 dvdrip xvid.avi",
        size: 134_742_016,
        source_count: 8,
    },
    SyntheticPopularSeed {
        title: "midnight subway cat rave.mkv",
        size: 3_288_334_336,
        source_count: 26,
    },
    SyntheticPopularSeed {
        title: "top 100 dance hits 2009.mp3",
        size: 77_414_400,
        source_count: 23,
    },
    SyntheticPopularSeed {
        title: "vhs rip of the internet weather channel.ts",
        size: 5_188_911_104,
        source_count: 14,
    },
    SyntheticPopularSeed {
        title: "ubuntu linux 22.04 desktop amd64.iso",
        size: 1_104_199_680,
        source_count: 28,
    },
    SyntheticPopularSeed {
        title: "the lord of the rings extended trilogy 1080p.mkv",
        size: 612_892_672,
        source_count: 20,
    },
    SyntheticPopularSeed {
        title: "microsoft office 2007 enterprise.iso",
        size: 695_205_888,
        source_count: 17,
    },
    SyntheticPopularSeed {
        title: "grand theft auto vice city full rip.iso",
        size: 1_544_269_824,
        source_count: 12,
    },
    SyntheticPopularSeed {
        title: "breaking bad season 3 complete 720p.mkv",
        size: 88_199_168,
        source_count: 25,
    },
    SyntheticPopularSeed {
        title: "ubuntu linux 20.04.6 live server amd64.iso",
        size: 3_964_108_800,
        source_count: 16,
    },
    SyntheticPopularSeed {
        title: "top gear complete specials collection x264.mp4",
        size: 233_308_160,
        source_count: 13,
    },
    SyntheticPopularSeed {
        title: "the beatles abbey road remastered.flac",
        size: 1_572_864,
        source_count: 7,
    },
    SyntheticPopularSeed {
        title: "harry potter complete 1080p bluray x264.mkv",
        size: 376_877_056,
        source_count: 11,
    },
    SyntheticPopularSeed {
        title: "visual studio 2010 professional.iso",
        size: 190_513_152,
        source_count: 9,
    },
    SyntheticPopularSeed {
        title: "ubuntu linux 18.04 desktop amd64.iso",
        size: 1_672_331_264,
        source_count: 18,
    },
    SyntheticPopularSeed {
        title: "pink floyd the wall remastered.flac",
        size: 49_283_072,
        source_count: 15,
    },
    SyntheticPopularSeed {
        title: "friends complete season 5 dvdrip xvid.avi",
        size: 2_965_983_232,
        source_count: 19,
    },
    SyntheticPopularSeed {
        title: "ubuntu linux handbook 2026.pdf",
        size: 821_051_392,
        source_count: 24,
    },
    SyntheticPopularSeed {
        title: "windows xp professional sp3 corporate.iso",
        size: 1_281_286_144,
        source_count: 17,
    },
    SyntheticPopularSeed {
        title: "portable rave lighthouse screensaver.scr",
        size: 28_311_552,
        source_count: 12,
    },
    SyntheticPopularSeed {
        title: "greatest floppy disk solos anthology.flac",
        size: 607_518_720,
        source_count: 20,
    },
    SyntheticPopularSeed {
        title: "galactic sandwich emulator setup.exe",
        size: 509_607_936,
        source_count: 14,
    },
    SyntheticPopularSeed {
        title: "vintage webcam ghost sightings collection.mkv",
        size: 2_118_541_312,
        source_count: 22,
    },
];

/// Static settings that make source publishes look like a stable eMule-style
/// high-ID client on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SourcePublishSettings {
    pub(super) tcp_port: u16,
    pub(super) obfuscation_enabled: bool,
}

pub(super) fn build_publish_batch_summary(
    seed_source: PublishSeedSource,
    published_items: usize,
    stats: PublishAttemptStats,
    completed_at: DateTime<Utc>,
) -> PublishBatchSummary {
    PublishBatchSummary {
        seed_source,
        published_items: published_items as u32,
        closest_contacts_considered: stats.closest_contacts_considered,
        attempted_contacts: stats.attempted_contacts,
        acked_contacts: stats.acked_contacts,
        failed_contacts: stats.failed_contacts(),
        timed_out_contacts: stats.timed_out_contacts,
        completed_at,
        last_success_at: (stats.acked_contacts > 0).then_some(completed_at),
    }
}

pub(super) fn apply_publish_summary(counters: &mut PublishCounters, summary: &PublishBatchSummary) {
    counters.batches += 1;
    counters.published_items += u64::from(summary.published_items);
    counters.closest_contacts_considered += u64::from(summary.closest_contacts_considered);
    counters.attempted_contacts += u64::from(summary.attempted_contacts);
    counters.acked_contacts += u64::from(summary.acked_contacts);
    counters.failed_contacts += u64::from(summary.failed_contacts);
    counters.timed_out_contacts += u64::from(summary.timed_out_contacts);
    counters.last_batch_at = Some(summary.completed_at);
    if summary.last_success_at.is_some() {
        counters.last_success_at = summary.last_success_at;
    }
}

/// Returns whether the current batch snapshot reflects any observable seeding progress yet.
fn publish_summary_has_progress(summary: &PublishBatchSummary) -> bool {
    summary.published_items > 0
        || summary.closest_contacts_considered > 0
        || summary.attempted_contacts > 0
        || summary.acked_contacts > 0
        || summary.failed_contacts > 0
        || summary.timed_out_contacts > 0
}

/// Projects the counters that operators should see right now.
///
/// The stored counters only advance once a batch has fully finished. During long live
/// runs, however, `/api/internal/stats` should still reflect the current in-flight batch
/// so the roll-up totals stay aligned with the latest per-batch snapshot.
pub(super) fn effective_publish_counters(
    counters: &PublishCounters,
    latest_batch: Option<&PublishBatchSummary>,
    last_seed_at: Option<DateTime<Utc>>,
) -> PublishCounters {
    let mut effective = counters.clone();
    let Some(summary) = latest_batch else {
        return effective;
    };

    let batch_committed = counters.last_batch_at == Some(summary.completed_at);
    let batch_in_flight = match (last_seed_at, counters.last_batch_at) {
        (Some(observed_at), Some(committed_at)) => observed_at > committed_at,
        (Some(_), None) => true,
        (None, _) => false,
    };

    if batch_in_flight && !batch_committed && publish_summary_has_progress(summary) {
        apply_publish_summary(&mut effective, summary);
    }

    effective
}

fn log_publish_summary(family: &str, summary: &PublishBatchSummary) {
    let other_failures = summary
        .failed_contacts
        .saturating_sub(summary.timed_out_contacts);
    info!(
        "kad publish family={} seed_source={} items={} closest={} attempted={} acked={} failed={} timed_out={} other_failures={}",
        family,
        summary.seed_source.label(),
        summary.published_items,
        summary.closest_contacts_considered,
        summary.attempted_contacts,
        summary.acked_contacts,
        summary.failed_contacts,
        summary.timed_out_contacts,
        other_failures
    );
}

pub(super) async fn record_publish_summaries(
    publish_observability: &Arc<Mutex<KadPublishObservability>>,
    seed_source: PublishSeedSource,
    published_items: usize,
    keyword_stats: PublishAttemptStats,
    source_stats: PublishAttemptStats,
    notes_stats: Option<PublishAttemptStats>,
    completed_at: DateTime<Utc>,
) {
    let keyword_summary =
        build_publish_batch_summary(seed_source, published_items, keyword_stats, completed_at);
    let source_summary =
        build_publish_batch_summary(seed_source, published_items, source_stats, completed_at);
    let notes_summary = notes_stats.map(|stats| {
        build_publish_batch_summary(seed_source, published_items, stats, completed_at)
    });

    log_publish_summary("keyword", &keyword_summary);
    log_publish_summary("source", &source_summary);
    if let Some(summary) = notes_summary.as_ref() {
        log_publish_summary("notes", summary);
    }

    let mut observability = publish_observability.lock().await;
    observability.last_seed_source = Some(seed_source);
    observability.last_seed_at = Some(completed_at);
    observability.latest_keyword_batch = Some(keyword_summary.clone());
    observability.latest_source_batch = Some(source_summary.clone());
    observability.latest_notes_batch = notes_summary.clone();
    apply_publish_summary(&mut observability.keyword_counters, &keyword_summary);
    apply_publish_summary(&mut observability.source_counters, &source_summary);
    if let Some(summary) = notes_summary.as_ref() {
        apply_publish_summary(&mut observability.notes_counters, summary);
    }
}

/// Refreshes the live publish snapshot while a long seed batch is still running.
///
/// The cumulative counters are only committed once the whole batch completes, but
/// the latest batch snapshots are updated continuously so operators can tell that
/// startup seeding is still making progress.
pub(super) async fn update_publish_progress(
    publish_observability: &Arc<Mutex<KadPublishObservability>>,
    seed_source: PublishSeedSource,
    processed_items: usize,
    keyword_stats: PublishAttemptStats,
    source_stats: PublishAttemptStats,
    notes_stats: Option<PublishAttemptStats>,
    observed_at: DateTime<Utc>,
) {
    let mut observability = publish_observability.lock().await;
    observability.last_seed_source = Some(seed_source);
    observability.last_seed_at = Some(observed_at);
    observability.latest_keyword_batch = Some(build_publish_batch_summary(
        seed_source,
        processed_items,
        keyword_stats,
        observed_at,
    ));
    observability.latest_source_batch = Some(build_publish_batch_summary(
        seed_source,
        processed_items,
        source_stats,
        observed_at,
    ));
    if let Some(stats) = notes_stats {
        observability.latest_notes_batch = Some(build_publish_batch_summary(
            seed_source,
            processed_items,
            stats,
            observed_at,
        ));
    }
}

pub(super) async fn set_synthetic_publish_queue_depth(
    publish_observability: &Arc<Mutex<KadPublishObservability>>,
    remaining_items: usize,
) {
    let mut observability = publish_observability.lock().await;
    observability.synthetic_drip_queue_depth = Some(remaining_items as u32);
}

/// Infer the oracle-style eD2k search term for a filename's published file type.
///
/// eMule publishes keyword `FILETYPE` tags using a compact search vocabulary:
/// `Audio`, `Video`, `Image`, `Doc`, `Pro`, or `EmuleCollection`.
/// Archives, programs, and CD-image style extensions all collapse to `Pro`.
#[must_use]
pub(super) fn ed2k_file_type_search_term(file_name: &str) -> Option<&'static str> {
    let extension = file_name.rsplit('.').next()?;
    if extension == file_name {
        return None;
    }

    match extension.to_ascii_lowercase().as_str() {
        "mp3" | "aac" | "ac3" | "flac" | "m4a" | "ogg" | "wav" | "wma" => Some("Audio"),
        "avi" | "mkv" | "mov" | "mp4" | "mpeg" | "mpg" | "wmv" => Some("Video"),
        "bmp" | "gif" | "jpeg" | "jpg" | "png" | "tif" | "tiff" | "webp" => Some("Image"),
        "chm" | "csv" | "doc" | "docx" | "epub" | "htm" | "html" | "odt" | "pdf" | "pps"
        | "ppt" | "pptx" | "rtf" | "txt" | "xls" | "xlsx" => Some("Doc"),
        "7z" | "ace" | "apk" | "bat" | "bin" | "bz2" | "cab" | "cmd" | "com" | "dll" | "dmg"
        | "exe" | "gz" | "img" | "iso" | "jar" | "msi" | "pkg" | "rar" | "sh" | "tar" | "tgz"
        | "xz" | "zip" => Some("Pro"),
        "emulecollection" => Some("EmuleCollection"),
        _ => None,
    }
}

/// Derive a stable synthetic AICH root for seeded publishes.
///
/// Seeded hashes do not have a real AICH tree behind them, but eMule adds an
/// AICH root on keyword publishes to Kad v9+ peers. A deterministic SHA-1 over
/// the advertised file identity keeps our wire shape stable across runs and
/// lets the publish fanout mirror the oracle's version-gated tag branch.
#[must_use]
pub(super) fn synthetic_publish_aich_hash(
    file_hash: &Ed2kHash,
    file_name: &str,
    file_size: u64,
) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(file_hash.0);
    hasher.update(file_size.to_le_bytes());
    hasher.update(file_name.as_bytes());
    let digest = hasher.finalize();
    let mut aich_hash = [0u8; 20];
    aich_hash.copy_from_slice(&digest);
    aich_hash
}

/// Builds the fixed synthetic seed list used when the coordinator has no popular hashes yet.
pub(super) fn synthetic_popular_hashes() -> Vec<PopularHash> {
    SYNTHETIC_POPULAR_SEEDS
        .iter()
        .enumerate()
        .map(|(index, seed)| synthetic_popular_hash(index, seed))
        .collect()
}

/// Produces a deterministic fake Ed2k hash so the synthetic seed set is stable across restarts.
pub(super) fn synthetic_file_hash(index: usize, seed: &SyntheticPopularSeed) -> Ed2kHash {
    let mut hasher = Md4::new();
    hasher.update(
        format!(
            "overlord-synthetic-kad-seed|{index}|{}|{}|{}",
            seed.title, seed.size, seed.source_count
        )
        .as_bytes(),
    );
    let digest: [u8; 16] = hasher.finalize().into();
    Ed2kHash::from_bytes(digest)
}

pub(super) fn synthetic_popular_hash(index: usize, seed: &SyntheticPopularSeed) -> PopularHash {
    PopularHash {
        hash: HashType::Ed2k(hex::encode(synthetic_file_hash(index, seed).0)),
        canonical_name: seed.title.to_string(),
        size: seed.size,
        source_count: seed.source_count,
    }
}

pub(super) async fn refresh_ed2k_shared_catalog(
    shared_catalog: &Ed2kSharedCatalog,
    hashes: &[PopularHash],
) {
    let mut guard = shared_catalog.write().await;
    guard.retain(|entry| !entry.compatibility_hint);
    let replacements = if hashes.is_empty() {
        synthetic_popular_hashes()
    } else {
        hashes.to_vec()
    };
    guard.extend(
        replacements
            .iter()
            .filter_map(Ed2kSharedEntry::from_popular_hash),
    );
}

pub(super) fn synthetic_publish_queue_depth(cursor: usize) -> usize {
    let total = SYNTHETIC_POPULAR_SEEDS.len();
    if total == 0 {
        return 0;
    }
    let normalized = cursor % total;
    if normalized == 0 {
        total
    } else {
        total - normalized
    }
}

pub(super) fn next_synthetic_publish_batch(
    cursor: &mut usize,
    batch_items: usize,
) -> Vec<PopularHash> {
    if SYNTHETIC_POPULAR_SEEDS.is_empty() {
        return Vec::new();
    }

    let total = SYNTHETIC_POPULAR_SEEDS.len();
    let start = *cursor % total;
    let batch_len = batch_items.max(1).min(total);
    let batch = (0..batch_len)
        .map(|offset| {
            let index = (start + offset) % total;
            synthetic_popular_hash(index, &SYNTHETIC_POPULAR_SEEDS[index])
        })
        .collect::<Vec<_>>();
    *cursor = (start + batch_len) % total;
    batch
}

/// Returns the eMule high-ID source type used for source publishes in the non-firewalled case.
pub(super) fn emule_high_id_source_type(file_size: u64) -> u32 {
    if file_size > EMULE_LARGE_FILE_SIZE_THRESHOLD {
        4
    } else {
        1
    }
}

/// eMule Kad carries 128-bit search/source entry IDs in 32-bit little-endian
/// chunk order rather than raw MD4 byte order.
fn emule_kad_chunk_order(bytes: [u8; 16]) -> [u8; 16] {
    let mut ordered = [0u8; 16];
    for (dst, src) in ordered.chunks_exact_mut(4).zip(bytes.chunks_exact(4)) {
        dst.copy_from_slice(&[src[3], src[2], src[1], src[0]]);
    }
    ordered
}

/// Reuse the persisted eD2k user hash as the Kad source-publish identity.
///
/// The oracle source-publish path sends the eMule client hash rather than the
/// Kad node ID in the second `KADEMLIA2_PUBLISH_SOURCE_REQ` field.
pub(super) fn source_publish_client_hash(ed2k_user_hash: [u8; 16]) -> NodeId {
    NodeId::from_bytes(emule_kad_chunk_order(ed2k_user_hash))
}

/// Applies the classic eMule client marker bytes to an ED2K user hash.
pub(super) fn normalize_ed2k_user_hash_markers(mut user_hash: [u8; 16]) -> [u8; 16] {
    user_hash[5] = 0x0E;
    user_hash[14] = 0x6F;
    user_hash
}

/// Mirrors the oracle `isbadhash` check for persisted ED2K user hashes.
fn ed2k_user_hash_is_bad(user_hash: &[u8; 16]) -> bool {
    let lo = u64::from_le_bytes(user_hash[..8].try_into().expect("slice has 8 bytes"));
    let hi = u64::from_le_bytes(user_hash[8..].try_into().expect("slice has 8 bytes"));
    (lo & 0xffff_00ff_ffff_ffff) == 0 && (hi & 0xff00_ffff_ffff_ffff) == 0
}

/// Creates a fresh eMule-style ED2K user hash.
fn create_ed2k_user_hash() -> [u8; 16] {
    loop {
        let mut user_hash = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut user_hash);
        let user_hash = normalize_ed2k_user_hash_markers(user_hash);
        if !ed2k_user_hash_is_bad(&user_hash) {
            return user_hash;
        }
    }
}

/// Loads the persisted ED2K user hash, or creates one that mirrors eMule semantics.
pub(super) fn load_or_create_ed2k_user_hash(path: &Path) -> Result<[u8; 16]> {
    if path.exists() {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read ED2K user hash from {}", path.display()))?;
        if bytes.len() == 16 {
            let mut user_hash = [0u8; 16];
            user_hash.copy_from_slice(&bytes);
            let normalized = normalize_ed2k_user_hash_markers(user_hash);
            if !ed2k_user_hash_is_bad(&normalized) {
                if normalized != user_hash {
                    fs::write(path, normalized).with_context(|| {
                        format!("failed to normalize ED2K user hash at {}", path.display())
                    })?;
                }
                return Ok(normalized);
            }
        }
    }

    let user_hash = create_ed2k_user_hash();
    fs::write(path, user_hash)
        .with_context(|| format!("failed to persist ED2K user hash to {}", path.display()))?;
    Ok(user_hash)
}

/// Return the eMule-style `TAG_ENCRYPTION` bits for the current non-firewalled agent.
///
/// This mirrors the oracle `GetMyConnectOptions(true, false)` shape we also expose over TCP hello.
fn emule_source_encryption_options(obfuscation_enabled: bool) -> u8 {
    emule_connect_options(obfuscation_enabled)
}

/// Builds the oracle-style source publish tag set for one file announcement.
pub(super) fn build_source_publish_tags(
    bind_addr: SocketAddr,
    source_publish_settings: SourcePublishSettings,
    file_size: u64,
) -> Vec<Tag> {
    let mut tags = vec![
        Tag::new_short(
            tag_name::SOURCETYPE,
            TagValue::UInt(u64::from(emule_high_id_source_type(file_size))),
        ),
        // Mirror the oracle: SOURCEPORT carries the ED2K TCP listener while
        // SOURCEUPORT carries the Kad UDP listener.
        Tag::new_short(
            tag_name::SOURCEPORT,
            TagValue::UInt(u64::from(source_publish_settings.tcp_port)),
        ),
    ];
    if let SocketAddr::V4(addr) = bind_addr {
        tags.push(Tag::new_short(
            tag_name::SOURCEIP,
            TagValue::U32(u32::from_be_bytes(addr.ip().octets())),
        ));
    }
    tags.push(Tag::new_short(
        tag_name::SOURCEUPORT,
        TagValue::U16(bind_addr.port()),
    ));
    tags.push(Tag::filesize(file_size));
    tags.push(Tag::new_short(
        tag_name::ENCRYPTION,
        TagValue::U8(emule_source_encryption_options(
            source_publish_settings.obfuscation_enabled,
        )),
    ));
    tags
}

/// Builds a deterministic notes-publish payload for controlled live validation.
///
/// The notes-seeding path remains opt-in so the runtime can exercise notes
/// publish parity without making synthetic notes part of the default behavior.
pub(super) fn build_notes_publish_tags(canonical_name: &str, file_size: u64) -> Vec<Tag> {
    vec![
        Tag::filename(canonical_name.to_string()),
        Tag::filesize(file_size),
        Tag::new_short(tag_name::FILERATING, TagValue::U8(4)),
        Tag::new_short(
            tag_name::DESCRIPTION,
            TagValue::String(format!("overlord validation note for {canonical_name}")),
        ),
    ]
}
