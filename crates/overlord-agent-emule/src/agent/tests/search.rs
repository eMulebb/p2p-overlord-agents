use super::*;

#[test]
fn significant_words_ignore_short_tokens() {
    assert_eq!(
        significant_keyword_words("A torino x train"),
        vec!["torino".to_string(), "train".to_string()]
    );
}

#[test]
fn keyword_target_is_stable() {
    assert_eq!(
        hex::encode(keyword_target("Torino Train").0),
        "b2bc3aa39f375069e7c27eb83ce6baf3"
    );
}

#[test]
fn exact_ed2k_hash_query_token_extracts_hash_only_queries() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    assert_eq!(
        exact_ed2k_hash_query_token(&format!("ed2k::{exact_hash}")),
        Some(exact_hash.clone())
    );
    assert_eq!(
        exact_ed2k_hash_query_token(&exact_hash.to_ascii_uppercase()),
        Some(exact_hash)
    );
    assert_eq!(exact_ed2k_hash_query_token("ed2k::torino train"), None);
}

#[test]
fn keyword_target_uses_hash_token_for_exact_ed2k_hash_queries() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    assert_eq!(
        keyword_target(&format!("ed2k::{exact_hash}")),
        keyword_target(&exact_hash.to_ascii_uppercase())
    );
}

#[test]
fn exact_ed2k_hash_queries_use_configured_server_budgets() {
    let mut config = EmuleAgentConfig::default();
    config.p2p.ed2k.server_endpoints = vec![
        "1.1.1.1:4661".to_string(),
        "2.2.2.2:4661".to_string(),
        "3.3.3.3:4661".to_string(),
        "4.4.4.4:4661".to_string(),
        "5.5.5.5:4661".to_string(),
    ];
    config.p2p.ed2k.keyword_server_attempt_budget = 2;
    config.p2p.ed2k.exact_hash_keyword_server_attempt_budget = 4;
    config.p2p.ed2k.source_server_attempt_budget = 3;
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]).to_string();

    assert_eq!(
        ed2k_keyword_server_attempt_budget(&config.p2p.ed2k, &format!("ed2k::{exact_hash}")),
        4
    );
    assert_eq!(
        ed2k_keyword_server_attempt_budget(&config.p2p.ed2k, "ubuntu linux"),
        2
    );
    assert_eq!(
        ed2k_download_source_server_attempt_budget(&config.p2p.ed2k),
        3
    );
}

#[test]
fn select_ed2k_keyword_metadata_prefers_exact_hash_with_size_and_name() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]);
    let other_hash = Ed2kHash::from_bytes([0xAA; 16]);
    let metadata = select_ed2k_keyword_metadata(
        &[
            Ed2kSearchFile {
                file_hash: exact_hash,
                file_name: Some("".to_string()),
                file_size: Some(0),
                file_type: None,
                source_count: Some(100),
            },
            Ed2kSearchFile {
                file_hash: other_hash,
                file_name: Some("wrong.bin".to_string()),
                file_size: Some(123),
                file_type: None,
                source_count: Some(5),
            },
            Ed2kSearchFile {
                file_hash: exact_hash,
                file_name: Some("resolved.bin".to_string()),
                file_size: Some(4_294_967_299),
                file_type: Some("Pro".to_string()),
                source_count: Some(12),
            },
        ],
        exact_hash,
    )
    .unwrap();

    assert_eq!(metadata.canonical_name.as_deref(), Some("resolved.bin"));
    assert_eq!(metadata.file_size, Some(4_294_967_299));
}

#[test]
fn kad_search_result_exposes_exact_hash_metadata() {
    let exact_hash = Ed2kHash::from_bytes([0x44; 16]);
    let metadata = select_kad_keyword_metadata(
        &SearchResult {
            hash: exact_hash,
            names: vec!["resolved.bin".to_string()],
            size: Some(5_000),
            source_count: Some(3),
            tags: Vec::new(),
        },
        exact_hash,
    )
    .unwrap();

    assert_eq!(metadata.canonical_name.as_deref(), Some("resolved.bin"));
    assert_eq!(metadata.file_size, Some(5_000));
}

#[test]
fn ed2k_user_hash_uses_oracle_emule_markers() {
    let user_hash = normalize_ed2k_user_hash_markers([0xAA; 16]);

    assert_eq!(user_hash[5], 0x0E);
    assert_eq!(user_hash[14], 0x6F);
}
