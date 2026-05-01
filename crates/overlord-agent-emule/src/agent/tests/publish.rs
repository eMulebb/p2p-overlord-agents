use super::*;

#[test]
fn synthetic_dataset_contains_expected_entry_count() {
    assert_eq!(SYNTHETIC_POPULAR_SEEDS.len(), 40);
}

#[test]
fn synthetic_hashes_are_deterministic() {
    let seed = &SYNTHETIC_POPULAR_SEEDS[0];
    assert_eq!(synthetic_file_hash(0, seed), synthetic_file_hash(0, seed));
}

#[test]
fn synthetic_hashes_are_unique() {
    let hashes = synthetic_popular_hashes();
    let unique = hashes
        .iter()
        .map(|entry| match &entry.hash {
            HashType::Ed2k(hash) => hash.clone(),
        })
        .collect::<HashSet<_>>();
    assert_eq!(unique.len(), hashes.len());
}

#[test]
fn synthetic_publish_queue_depth_tracks_remaining_rotation_window() {
    assert_eq!(
        synthetic_publish_queue_depth(0),
        SYNTHETIC_POPULAR_SEEDS.len()
    );
    assert_eq!(
        synthetic_publish_queue_depth(1),
        SYNTHETIC_POPULAR_SEEDS.len() - 1
    );
    assert_eq!(
        synthetic_publish_queue_depth(SYNTHETIC_POPULAR_SEEDS.len()),
        SYNTHETIC_POPULAR_SEEDS.len()
    );
}

#[test]
fn synthetic_publish_batch_wraps_and_advances_cursor() {
    let total = SYNTHETIC_POPULAR_SEEDS.len();
    let mut cursor = total - 1;

    let batch = next_synthetic_publish_batch(&mut cursor, 3);

    assert_eq!(batch.len(), 3);
    assert_eq!(
        batch[0],
        synthetic_popular_hash(total - 1, &SYNTHETIC_POPULAR_SEEDS[total - 1])
    );
    assert_eq!(
        batch[1],
        synthetic_popular_hash(0, &SYNTHETIC_POPULAR_SEEDS[0])
    );
    assert_eq!(
        batch[2],
        synthetic_popular_hash(1, &SYNTHETIC_POPULAR_SEEDS[1])
    );
    assert_eq!(cursor, 2);
}

#[test]
fn synthetic_publish_batch_treats_zero_request_as_single_item_drip() {
    let mut cursor = 0;

    let batch = next_synthetic_publish_batch(&mut cursor, 0);

    assert_eq!(batch.len(), 1);
    assert_eq!(
        batch[0],
        synthetic_popular_hash(0, &SYNTHETIC_POPULAR_SEEDS[0])
    );
    assert_eq!(cursor, 1);
}

#[test]
fn emule_source_type_matches_large_file_convention() {
    assert_eq!(emule_high_id_source_type(123), 1);
    assert_eq!(
        emule_high_id_source_type(EMULE_LARGE_FILE_SIZE_THRESHOLD + 1),
        4
    );
}

#[test]
fn build_publish_batch_summary_marks_success_timestamp_when_acked() {
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 0, 0).unwrap();
    let summary = build_publish_batch_summary(
        PublishSeedSource::Coordinator,
        40,
        PublishAttemptStats {
            closest_contacts_considered: 10,
            attempted_contacts: 10,
            acked_contacts: 6,
            timed_out_contacts: 3,
        },
        completed_at,
    );

    assert_eq!(summary.failed_contacts, 4);
    assert_eq!(summary.last_success_at, Some(completed_at));
}

#[test]
fn apply_publish_summary_accumulates_counters() {
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 5, 0).unwrap();
    let summary = build_publish_batch_summary(
        PublishSeedSource::SyntheticFallback,
        40,
        PublishAttemptStats {
            closest_contacts_considered: 8,
            attempted_contacts: 8,
            acked_contacts: 5,
            timed_out_contacts: 2,
        },
        completed_at,
    );
    let mut counters = PublishCounters::default();

    apply_publish_summary(&mut counters, &summary);

    assert_eq!(counters.batches, 1);
    assert_eq!(counters.published_items, 40);
    assert_eq!(counters.attempted_contacts, 8);
    assert_eq!(counters.acked_contacts, 5);
    assert_eq!(counters.failed_contacts, 3);
    assert_eq!(counters.timed_out_contacts, 2);
    assert_eq!(counters.last_batch_at, Some(completed_at));
    assert_eq!(counters.last_success_at, Some(completed_at));
}

#[test]
fn effective_publish_counters_include_in_flight_batch_progress() {
    let previous_completed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 5, 0).unwrap();
    let live_observed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 10, 0).unwrap();
    let committed_summary = build_publish_batch_summary(
        PublishSeedSource::Coordinator,
        10,
        PublishAttemptStats {
            closest_contacts_considered: 6,
            attempted_contacts: 6,
            acked_contacts: 4,
            timed_out_contacts: 1,
        },
        previous_completed_at,
    );
    let live_summary = build_publish_batch_summary(
        PublishSeedSource::SyntheticFallback,
        7,
        PublishAttemptStats {
            closest_contacts_considered: 5,
            attempted_contacts: 5,
            acked_contacts: 2,
            timed_out_contacts: 2,
        },
        live_observed_at,
    );
    let mut committed_counters = PublishCounters::default();
    apply_publish_summary(&mut committed_counters, &committed_summary);

    let effective = effective_publish_counters(
        &committed_counters,
        Some(&live_summary),
        Some(live_observed_at),
    );

    assert_eq!(effective.batches, 2);
    assert_eq!(effective.published_items, 17);
    assert_eq!(effective.closest_contacts_considered, 11);
    assert_eq!(effective.attempted_contacts, 11);
    assert_eq!(effective.acked_contacts, 6);
    assert_eq!(effective.failed_contacts, 5);
    assert_eq!(effective.timed_out_contacts, 3);
    assert_eq!(effective.last_batch_at, Some(live_observed_at));
    assert_eq!(effective.last_success_at, Some(live_observed_at));
}

#[test]
fn effective_publish_counters_do_not_double_count_committed_batch() {
    let completed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 5, 0).unwrap();
    let summary = build_publish_batch_summary(
        PublishSeedSource::SyntheticFallback,
        40,
        PublishAttemptStats {
            closest_contacts_considered: 8,
            attempted_contacts: 8,
            acked_contacts: 5,
            timed_out_contacts: 2,
        },
        completed_at,
    );
    let mut counters = PublishCounters::default();
    apply_publish_summary(&mut counters, &summary);

    let effective = effective_publish_counters(&counters, Some(&summary), Some(completed_at));

    assert_eq!(effective, counters);
}

#[tokio::test]
async fn record_publish_summaries_tracks_notes_family_when_enabled() {
    let completed_at = Utc.with_ymd_and_hms(2026, 4, 25, 10, 0, 0).unwrap();
    let observability = Arc::new(Mutex::new(KadPublishObservability::default()));

    record_publish_summaries(
        &observability,
        PublishSeedSource::ManualApi,
        2,
        PublishAttemptStats {
            closest_contacts_considered: 3,
            attempted_contacts: 3,
            acked_contacts: 2,
            timed_out_contacts: 0,
        },
        PublishAttemptStats {
            closest_contacts_considered: 4,
            attempted_contacts: 4,
            acked_contacts: 3,
            timed_out_contacts: 1,
        },
        Some(PublishAttemptStats {
            closest_contacts_considered: 5,
            attempted_contacts: 5,
            acked_contacts: 4,
            timed_out_contacts: 1,
        }),
        completed_at,
    )
    .await;

    let snapshot = observability.lock().await;
    let latest_notes = snapshot
        .latest_notes_batch
        .as_ref()
        .expect("notes publish batch summary");
    assert_eq!(latest_notes.seed_source, PublishSeedSource::ManualApi);
    assert_eq!(latest_notes.published_items, 2);
    assert_eq!(latest_notes.attempted_contacts, 5);
    assert_eq!(latest_notes.acked_contacts, 4);
    assert_eq!(snapshot.notes_counters.batches, 1);
    assert_eq!(snapshot.notes_counters.published_items, 2);
    assert_eq!(snapshot.notes_counters.attempted_contacts, 5);
    assert_eq!(snapshot.notes_counters.last_success_at, Some(completed_at));
}

#[test]
fn effective_publish_counters_ignore_empty_initial_snapshot() {
    let observed_at = Utc.with_ymd_and_hms(2026, 3, 21, 11, 0, 0).unwrap();
    let empty_summary = build_publish_batch_summary(
        PublishSeedSource::Coordinator,
        0,
        PublishAttemptStats::default(),
        observed_at,
    );

    let effective = effective_publish_counters(
        &PublishCounters::default(),
        Some(&empty_summary),
        Some(observed_at),
    );

    assert_eq!(effective, PublishCounters::default());
}

#[test]
fn source_publish_tags_match_oracle_plaintext_shape() {
    let tags = build_source_publish_tags(
        "10.54.206.206:41000".parse().unwrap(),
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: false,
        },
        2_097_152,
    );

    assert_eq!(
        tags,
        vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(41001)),
            Tag::new_short(tag_name::SOURCEIP, TagValue::U32(0x0A36_CECE)),
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::filesize(2_097_152),
            Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0)),
        ]
    );
}

#[test]
fn source_publish_tags_set_obfuscated_encryption_bits() {
    let tags = build_source_publish_tags(
        "10.54.206.206:41000".parse().unwrap(),
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: true,
        },
        2_097_152,
    );

    assert_eq!(
        tags.last(),
        Some(&Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(3)))
    );
}

#[test]
fn source_publish_identity_uses_emule_kad_chunk_order() {
    let user_hash = [
        0xB4, 0x22, 0xCF, 0x1A, 0x44, 0x0E, 0x71, 0x6B, 0xD2, 0xE1, 0xDD, 0x6E, 0x77, 0x21, 0x6F,
        0xE4,
    ];

    let publisher_id = source_publish_client_hash(user_hash);

    assert_eq!(
        publisher_id.0,
        [
            0x1A, 0xCF, 0x22, 0xB4, 0x6B, 0x71, 0x0E, 0x44, 0x6E, 0xDD, 0xE1, 0xD2, 0xE4, 0x6F,
            0x21, 0x77,
        ]
    );
    assert_eq!(publisher_id.to_be_bytes(), user_hash);
}

#[test]
fn notes_publish_tags_are_deterministic_and_note_shaped() {
    let tags = build_notes_publish_tags("ubuntu linux.iso", 2_097_152);

    assert_eq!(
        tags,
        vec![
            Tag::filename("ubuntu linux.iso"),
            Tag::filesize(2_097_152),
            Tag::new_short(tag_name::FILERATING, TagValue::U8(4)),
            Tag::new_short(
                tag_name::DESCRIPTION,
                TagValue::String("overlord validation note for ubuntu linux.iso".to_string()),
            ),
        ]
    );
}

#[test]
fn ed2k_file_type_search_term_matches_oracle_program_family() {
    assert_eq!(
        ed2k_file_type_search_term("ubuntu-linux-oracle-sample.iso"),
        Some("Pro")
    );
    assert_eq!(ed2k_file_type_search_term("archive.7z"), Some("Pro"));
}

#[test]
fn ed2k_file_type_search_term_matches_common_media_families() {
    assert_eq!(ed2k_file_type_search_term("album.flac"), Some("Audio"));
    assert_eq!(ed2k_file_type_search_term("movie.mkv"), Some("Video"));
    assert_eq!(ed2k_file_type_search_term("scan.png"), Some("Image"));
    assert_eq!(ed2k_file_type_search_term("manual.pdf"), Some("Doc"));
    assert_eq!(
        ed2k_file_type_search_term("bundle.emulecollection"),
        Some("EmuleCollection")
    );
    assert_eq!(ed2k_file_type_search_term("README"), None);
}

#[test]
fn synthetic_publish_aich_hash_is_stable_for_same_file_identity() {
    let file_hash = Ed2kHash::from_bytes([0xAB; 16]);
    let first = synthetic_publish_aich_hash(&file_hash, "ubuntu.iso", 734_003_200);
    let second = synthetic_publish_aich_hash(&file_hash, "ubuntu.iso", 734_003_200);
    assert_eq!(first, second);
    assert_eq!(first.len(), 20);
}

#[test]
fn synthetic_publish_aich_hash_changes_when_file_identity_changes() {
    let file_hash = Ed2kHash::from_bytes([0xAB; 16]);
    let first = synthetic_publish_aich_hash(&file_hash, "ubuntu.iso", 734_003_200);
    let second = synthetic_publish_aich_hash(&file_hash, "ubuntu.iso", 734_003_201);
    assert_ne!(first, second);
}
