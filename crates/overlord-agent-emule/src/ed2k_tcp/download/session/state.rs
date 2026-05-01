use tokio::time::Instant;

use super::super::super::Ed2kPeerSecureIdentState;
use super::super::ActiveDownloadPiece;

pub(super) struct DownloadSessionState {
    pub(super) peer_secure_ident: Ed2kPeerSecureIdentState,
    pub(super) hello_complete: bool,
    pub(super) secure_ident_started: bool,
    pub(super) remote_supports_file_identifiers: bool,
    pub(super) startup_file_requests_sent: bool,
    pub(super) startup_file_response_received: bool,
    pub(super) source_request_sent: bool,
    pub(super) aich_file_hash_requested: bool,
    pub(super) hashset_requested: bool,
    pub(super) hashset_requested_at: Option<Instant>,
    pub(super) upload_requested: bool,
    pub(super) upload_accepted: bool,
    pub(super) upload_accepted_at: Option<Instant>,
    pub(super) part_response_deadline: Option<Instant>,
    pub(super) queued_until: Option<Instant>,
    pub(super) active_piece_request: Option<ActiveDownloadPiece>,
    pub(super) completed_block_count: usize,
    pub(super) session_payload_down: u64,
}

impl DownloadSessionState {
    pub(super) fn new(initial_hello_complete: bool, initial_secure_ident_started: bool) -> Self {
        Self {
            peer_secure_ident: Ed2kPeerSecureIdentState::default(),
            hello_complete: initial_hello_complete,
            secure_ident_started: initial_secure_ident_started,
            remote_supports_file_identifiers: false,
            startup_file_requests_sent: false,
            startup_file_response_received: false,
            source_request_sent: false,
            aich_file_hash_requested: false,
            hashset_requested: false,
            hashset_requested_at: None,
            upload_requested: false,
            upload_accepted: false,
            upload_accepted_at: None,
            part_response_deadline: None,
            queued_until: None,
            active_piece_request: None,
            completed_block_count: 0,
            session_payload_down: 0,
        }
    }
}
