use crate::traversal::{TraversalConfig, TraversalContact, TraversalKind, run_traversal};
use crate::types::{NoteResult, SearchResult, SourceResult};
use overlord_kad_net::RpcManager;
use overlord_kad_proto::constants::SEARCH_TIMEOUT_SECS;
use overlord_kad_proto::{Ed2kHash, NodeId, SearchKeyReq};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const SEARCH_TIMEOUT: Duration = Duration::from_secs(SEARCH_TIMEOUT_SECS);
/// Buffer used between traversal SEARCH_RES ingestion and higher-level search consumers.
///
/// Large passive harvest bursts can deliver many consecutive SEARCH_RES pages
/// from one peer. Keeping this buffer comfortably above one page train avoids
/// turning inbound harvest volume into backpressure on the traversal loop.
const SEARCH_RESULT_STREAM_BUFFER: usize = 2048;

/// Run a keyword search. Returns a Stream of results.
pub fn search_keywords(
    rpc: RpcManager,
    initial: Vec<TraversalContact>,
    target: NodeId,
    result_cap: usize,
    phase2_fanout: usize,
    cancel: CancellationToken,
) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
    search_keywords_by_request(
        rpc,
        initial,
        SearchKeyReq {
            target,
            start_position: 0,
            restrictive_payload: Vec::new(),
        },
        result_cap,
        phase2_fanout,
        cancel,
    )
}

/// Run a keyword search using a prebuilt Kad keyword request shape.
pub fn search_keywords_by_request(
    rpc: RpcManager,
    initial: Vec<TraversalContact>,
    request: SearchKeyReq,
    result_cap: usize,
    phase2_fanout: usize,
    cancel: CancellationToken,
) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
    let (tx, rx) = mpsc::channel::<SearchResult>(SEARCH_RESULT_STREAM_BUFFER);
    tokio::spawn(async move {
        let (raw_tx, mut raw_rx) =
            mpsc::channel::<(Ed2kHash, Vec<overlord_kad_proto::Tag>)>(SEARCH_RESULT_STREAM_BUFFER);
        let config = TraversalConfig {
            target: request.target,
            search_kind: TraversalKind::Keyword { request },
            timeout: SEARCH_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout,
            cancel: cancel.clone(),
            result_tx: Some(raw_tx),
        };

        let traversal = tokio::spawn(async move {
            let _ = run_traversal(&rpc, initial, config).await;
        });

        let mut seen_hashes = HashSet::new();
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => break,
                next = raw_rx.recv() => next,
            };
            let Some((hash, tags)) = next else {
                break;
            };
            if seen_hashes.len() >= result_cap {
                break;
            }

            let result = SearchResult::from_tags(hash, tags);
            if !is_acceptable_keyword_result(&result) {
                continue;
            }
            if !seen_hashes.insert(result.hash) {
                continue;
            }
            if tx.send(result).await.is_err() {
                break;
            }
        }

        drop(raw_rx);
        let _ = traversal.await;
    });
    ReceiverStream::new(rx)
}

/// Run a source search.
pub fn search_sources(
    rpc: RpcManager,
    initial: Vec<TraversalContact>,
    file_hash: Ed2kHash,
    file_size: u64,
    result_cap: usize,
    phase2_fanout: usize,
    cancel: CancellationToken,
) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
    let (tx, rx) = mpsc::channel::<SourceResult>(SEARCH_RESULT_STREAM_BUFFER);
    let target = NodeId::from_bytes(file_hash.0);

    tokio::spawn(async move {
        let (raw_tx, mut raw_rx) =
            mpsc::channel::<(Ed2kHash, Vec<overlord_kad_proto::Tag>)>(SEARCH_RESULT_STREAM_BUFFER);
        let config = TraversalConfig {
            target,
            search_kind: TraversalKind::Source { size: file_size },
            timeout: SEARCH_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout,
            cancel: cancel.clone(),
            result_tx: Some(raw_tx),
        };

        let traversal = tokio::spawn(async move {
            let _ = run_traversal(&rpc, initial, config).await;
        });

        let mut seen_sources = HashSet::<(Ipv4Addr, u16, u16)>::new();
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => break,
                next = raw_rx.recv() => next,
            };
            let Some((hash, tags)) = next else {
                break;
            };
            if seen_sources.len() >= result_cap {
                break;
            }

            let Some(source) = SourceResult::from_tags(hash, tags) else {
                continue;
            };
            let source_key = (source.ip, source.tcp_port, source.udp_port);
            if !seen_sources.insert(source_key) {
                continue;
            }
            if tx.send(source).await.is_err() {
                break;
            }
        }

        drop(raw_rx);
        let _ = traversal.await;
    });
    ReceiverStream::new(rx)
}

/// Run a notes search.
pub fn search_notes(
    rpc: RpcManager,
    initial: Vec<TraversalContact>,
    file_hash: Ed2kHash,
    file_size: u64,
    result_cap: usize,
    phase2_fanout: usize,
    cancel: CancellationToken,
) -> impl tokio_stream::Stream<Item = NoteResult> + Send + 'static {
    let (tx, rx) = mpsc::channel::<NoteResult>(SEARCH_RESULT_STREAM_BUFFER);
    let target = NodeId::from_bytes(file_hash.0);

    tokio::spawn(async move {
        let (raw_tx, mut raw_rx) =
            mpsc::channel::<(Ed2kHash, Vec<overlord_kad_proto::Tag>)>(SEARCH_RESULT_STREAM_BUFFER);
        let config = TraversalConfig {
            target,
            search_kind: TraversalKind::Notes { size: file_size },
            timeout: SEARCH_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout,
            cancel: cancel.clone(),
            result_tx: Some(raw_tx),
        };

        let traversal = tokio::spawn(async move {
            let _ = run_traversal(&rpc, initial, config).await;
        });

        let mut seen_authors = HashSet::new();
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => break,
                next = raw_rx.recv() => next,
            };
            let Some((author_id, tags)) = next else {
                break;
            };
            if seen_authors.len() >= result_cap {
                break;
            }

            let Some(note) = NoteResult::from_tags(file_hash, author_id, tags) else {
                continue;
            };
            if !seen_authors.insert(note.author_id) {
                continue;
            }
            if tx.send(note).await.is_err() {
                break;
            }
        }

        drop(raw_rx);
        let _ = traversal.await;
    });
    ReceiverStream::new(rx)
}

fn is_acceptable_keyword_result(result: &SearchResult) -> bool {
    // Harvest-first repo policy: keep wire-compatible requests, but accept any
    // keyword result which has the core fields needed for indexing. We
    // intentionally do not apply eMule's local query-word filtering here,
    // because this daemon is an indexer rather than a UI search client.
    !result.names.is_empty() && result.size.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use overlord_kad_proto::{Tag, TagValue, tag_name};

    #[test]
    fn keyword_result_requires_filename_and_size() {
        let missing_name =
            SearchResult::from_tags(Ed2kHash::from_bytes([1; 16]), vec![Tag::filesize(42)]);
        assert!(!is_acceptable_keyword_result(&missing_name));

        let missing_size = SearchResult::from_tags(
            Ed2kHash::from_bytes([2; 16]),
            vec![Tag::filename("torino-trip.avi")],
        );
        assert!(!is_acceptable_keyword_result(&missing_size));
    }

    #[test]
    fn keyword_result_accepts_nonmatching_filename_when_core_fields_exist() {
        let result = SearchResult::from_tags(
            Ed2kHash::from_bytes([3; 16]),
            vec![Tag::filename("Torino Holiday.avi"), Tag::filesize(123)],
        );
        assert!(is_acceptable_keyword_result(&result));
    }

    #[test]
    fn keyword_result_accepts_matching_multiword_filename() {
        let result = SearchResult::from_tags(
            Ed2kHash::from_bytes([4; 16]),
            vec![
                Tag::filename("Live In Torino Train Station.mkv"),
                Tag::filesize(123),
            ],
        );
        assert!(is_acceptable_keyword_result(&result));
    }

    #[test]
    fn notes_parsing_keeps_description_and_rating_only() {
        let note = NoteResult::from_tags(
            Ed2kHash::from_bytes([5; 16]),
            Ed2kHash::from_bytes([6; 16]),
            vec![
                Tag::new_short(tag_name::DESCRIPTION, TagValue::String("good".into())),
                Tag::new_short(tag_name::FILERATING, TagValue::U8(4)),
            ],
        )
        .expect("note");
        assert_eq!(note.comment.as_deref(), Some("good"));
        assert_eq!(note.rating, Some(4));
    }
}
