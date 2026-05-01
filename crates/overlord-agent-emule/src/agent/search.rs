use std::str::FromStr;

use anyhow::{Context, Result};
use overlord_agent_common::{
    ContentType, CoordinatorClient, FileRecord, HashType, Protocol, ResultBatch, SearchEvent,
    SearchEventStatus, SearchJob, Source, TagEntry,
};
use overlord_kad_dht::{DhtNode, NoteResult, RpcWorkClass, SearchResult, SourceResult};
use overlord_kad_proto::{Ed2kHash, Tag, TagName, TagValue};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{ACTIVE_BATCH_SIZE, keyword_target};

#[derive(Default)]
pub(super) struct SearchRunStats {
    pub(super) result_count: u32,
    pub(super) batch_count: u32,
}

pub(super) async fn emit_search_event(
    callback_client: &CoordinatorClient,
    job_id: Uuid,
    indexer_id: Uuid,
    status: SearchEventStatus,
    stats: &SearchRunStats,
    error: Option<String>,
) -> Result<()> {
    callback_client
        .post_search_event(&SearchEvent {
            job_id,
            indexer_id,
            status,
            result_count: Some(stats.result_count),
            batch_count: Some(stats.batch_count),
            error,
        })
        .await
}

pub(super) async fn post_search_batch(
    callback_client: &CoordinatorClient,
    job_id: Uuid,
    indexer_id: Uuid,
    protocol: Protocol,
    files: Vec<FileRecord>,
    stats: &mut SearchRunStats,
) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    stats.result_count += files.len() as u32;
    stats.batch_count += 1;
    callback_client
        .post_results(&ResultBatch {
            job_id: Some(job_id),
            indexer_id,
            protocol,
            harvest_context: None,
            files,
        })
        .await?;
    emit_search_event(
        callback_client,
        job_id,
        indexer_id,
        SearchEventStatus::BatchReceived,
        stats,
        None,
    )
    .await
}

pub(super) fn search_query(job: &SearchJob) -> Result<&str> {
    job.query
        .as_deref()
        .filter(|query| !query.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("search job is missing query text"))
}

pub(super) fn search_file_hash(job: &SearchJob) -> Result<Ed2kHash> {
    let Some(HashType::Ed2k(value)) = job.file_hash.as_ref() else {
        anyhow::bail!("search job is missing ed2k file hash");
    };
    Ed2kHash::from_str(value).with_context(|| format!("invalid Ed2k hash {value}"))
}

pub(super) fn search_file_size(job: &SearchJob) -> Result<u64> {
    job.file_size
        .filter(|size| *size > 0)
        .ok_or_else(|| anyhow::anyhow!("search job is missing file size"))
}

pub(super) fn map_source_result(result: &SourceResult, file_size: u64) -> FileRecord {
    FileRecord {
        hashes: vec![HashType::Ed2k(result.file_hash.to_string())],
        names: Vec::new(),
        size: Some(file_size),
        content_type: None,
        tags: Vec::new(),
        sources: vec![Source {
            protocol: Protocol::Kad2,
            address: format!("{}:{}", result.ip, result.tcp_port),
            extra: serde_json::json!({
                "udp_port": result.udp_port,
                "search_mode": "source"
            }),
        }],
    }
}

pub(super) fn map_note_result(result: &NoteResult, file_size: u64) -> FileRecord {
    FileRecord {
        hashes: vec![HashType::Ed2k(result.file_hash.to_string())],
        names: Vec::new(),
        size: Some(file_size),
        content_type: None,
        tags: vec![TagEntry {
            key: "kad_note".to_string(),
            value: serde_json::json!({
                "source_id": result.source_id.to_string(),
                "rating": result.rating,
                "comment": result.comment,
            }),
        }],
        sources: Vec::new(),
    }
}

pub(super) async fn do_active_keyword_search(
    dht: &DhtNode,
    indexer_id: Uuid,
    job: &SearchJob,
    enable_mock_results: bool,
    cancel: CancellationToken,
) -> Result<SearchRunStats> {
    let target = keyword_target(search_query(job)?);
    let mut stream = dht.search_keywords_with_cancel_and_class(
        target,
        cancel.clone(),
        RpcWorkClass::Interactive,
    );
    let callback_client = CoordinatorClient::new(&job.callback_url)?;
    let mut files = Vec::new();
    let mut seen = 0usize;
    let mut stats = SearchRunStats::default();

    while let Some(result) = stream.next().await {
        seen += 1;
        files.push(map_search_result_for(dht, &result)?);
        if files.len() >= ACTIVE_BATCH_SIZE {
            post_search_batch(
                &callback_client,
                job.job_id,
                indexer_id,
                Protocol::Kad2,
                std::mem::take(&mut files),
                &mut stats,
            )
            .await?;
        }
    }

    post_search_batch(
        &callback_client,
        job.job_id,
        indexer_id,
        Protocol::Kad2,
        files,
        &mut stats,
    )
    .await?;

    if seen == 0 && !cancel.is_cancelled() && enable_mock_results {
        post_search_batch(
            &callback_client,
            job.job_id,
            indexer_id,
            Protocol::Kad2,
            vec![mock_file_record(
                search_query(job)?,
                dht.bind_addr()?.to_string(),
            )],
            &mut stats,
        )
        .await?;
    }

    Ok(stats)
}

pub(super) async fn do_active_source_search(
    dht: &DhtNode,
    indexer_id: Uuid,
    job: &SearchJob,
    cancel: CancellationToken,
) -> Result<SearchRunStats> {
    let file_hash = search_file_hash(job)?;
    let file_size = search_file_size(job)?;
    let callback_client = CoordinatorClient::new(&job.callback_url)?;
    let mut stream = dht.search_sources_with_cancel_and_class(
        file_hash,
        file_size,
        cancel,
        RpcWorkClass::Interactive,
    );
    let mut files = Vec::new();
    let mut stats = SearchRunStats::default();

    while let Some(result) = stream.next().await {
        files.push(map_source_result(&result, file_size));
        if files.len() >= ACTIVE_BATCH_SIZE {
            post_search_batch(
                &callback_client,
                job.job_id,
                indexer_id,
                Protocol::Kad2,
                std::mem::take(&mut files),
                &mut stats,
            )
            .await?;
        }
    }

    post_search_batch(
        &callback_client,
        job.job_id,
        indexer_id,
        Protocol::Kad2,
        files,
        &mut stats,
    )
    .await?;
    Ok(stats)
}

pub(super) async fn do_active_notes_search(
    dht: &DhtNode,
    indexer_id: Uuid,
    job: &SearchJob,
    cancel: CancellationToken,
) -> Result<SearchRunStats> {
    let file_hash = search_file_hash(job)?;
    let file_size = search_file_size(job)?;
    let callback_client = CoordinatorClient::new(&job.callback_url)?;
    let mut stream = dht.search_notes_with_cancel_and_class(
        file_hash,
        file_size,
        cancel,
        RpcWorkClass::Interactive,
    );
    let mut files = Vec::new();
    let mut stats = SearchRunStats::default();

    while let Some(result) = stream.next().await {
        files.push(map_note_result(&result, file_size));
        if files.len() >= ACTIVE_BATCH_SIZE {
            post_search_batch(
                &callback_client,
                job.job_id,
                indexer_id,
                Protocol::Kad2,
                std::mem::take(&mut files),
                &mut stats,
            )
            .await?;
        }
    }

    post_search_batch(
        &callback_client,
        job.job_id,
        indexer_id,
        Protocol::Kad2,
        files,
        &mut stats,
    )
    .await?;
    Ok(stats)
}

fn guess_content_type(name: Option<&String>) -> Option<ContentType> {
    let Some(name) = name else {
        return Some(ContentType::Unknown);
    };
    let lower = name.to_lowercase();
    let value = if [".mkv", ".mp4", ".avi", ".mov"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        ContentType::Video
    } else if [".mp3", ".flac", ".wav", ".ogg"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        ContentType::Audio
    } else if [".pdf", ".epub", ".txt", ".doc", ".docx"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        ContentType::Document
    } else if [".zip", ".rar", ".7z", ".tar"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        ContentType::Archive
    } else if [".exe", ".msi", ".iso"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        ContentType::Software
    } else {
        ContentType::Unknown
    };
    Some(value)
}

fn mock_file_record(query: &str, bind_addr: String) -> FileRecord {
    FileRecord {
        hashes: vec![HashType::Ed2k(hex::encode(
            keyword_target(query).to_be_bytes(),
        ))],
        names: vec![format!(
            "{}.bin",
            query.trim().replace(' ', "_").to_lowercase()
        )],
        size: Some(1_048_576),
        content_type: Some(ContentType::Unknown),
        tags: vec![TagEntry {
            key: "origin".into(),
            value: serde_json::json!("mock_fallback"),
        }],
        sources: vec![Source {
            protocol: Protocol::Kad2,
            address: bind_addr,
            extra: serde_json::json!({ "search_mode": "mock" }),
        }],
    }
}

fn tag_to_entry(tag: &Tag) -> TagEntry {
    let key = match &tag.name {
        TagName::Short(value) => format!("tag_{value:02x}"),
        TagName::Long(value) => value.clone(),
    };
    let value = match &tag.value {
        TagValue::Hash(value) => serde_json::json!(value.to_string()),
        TagValue::String(value) => serde_json::json!(value),
        TagValue::UInt(value) => serde_json::json!(value),
        TagValue::U64(value) => serde_json::json!(value),
        TagValue::U32(value) => serde_json::json!(value),
        TagValue::U16(value) => serde_json::json!(value),
        TagValue::U8(value) => serde_json::json!(value),
        TagValue::Float(value) => serde_json::json!(value),
        TagValue::Bool(value) => serde_json::json!(value),
        TagValue::Blob(value) => serde_json::json!(hex::encode(value)),
        TagValue::SmallBlob(value) => serde_json::json!(hex::encode(value)),
    };
    TagEntry { key, value }
}

pub(super) fn map_search_result_for(dht: &DhtNode, result: &SearchResult) -> Result<FileRecord> {
    Ok(FileRecord {
        hashes: vec![HashType::Ed2k(result.hash.to_string())],
        names: result.names.clone(),
        size: result.size,
        content_type: guess_content_type(result.names.first()),
        tags: result.tags.iter().map(tag_to_entry).collect(),
        sources: vec![Source {
            protocol: Protocol::Kad2,
            address: dht.bind_addr()?.to_string(),
            extra: serde_json::json!({
                "search_mode": "network",
                "source_count": result.source_count,
            }),
        }],
    })
}
