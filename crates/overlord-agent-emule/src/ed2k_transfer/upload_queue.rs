use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

/// Upload-slot and waiting-queue policy used by the inbound ED2K listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ed2kUploadQueueConfig {
    /// Maximum number of concurrently granted upload sessions.
    pub active_slots: usize,
    /// Maximum number of queued waiters retained at once.
    pub waiting_capacity: usize,
    /// Maximum idle time for a queued waiter before it is discarded.
    pub waiting_timeout: Duration,
    /// Maximum stall time after grant before the peer requests data.
    pub granted_timeout: Duration,
    /// Maximum idle time while a peer already has an active upload slot.
    pub upload_timeout: Duration,
}

impl Default for Ed2kUploadQueueConfig {
    fn default() -> Self {
        Self {
            active_slots: 3,
            waiting_capacity: 512,
            waiting_timeout: Duration::from_secs(180),
            granted_timeout: Duration::from_secs(30),
            upload_timeout: Duration::from_secs(90),
        }
    }
}

/// Stable peer identity used to keep uploader queue decisions deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Ed2kUploadPeerIdentity {
    /// Remote peer IP address.
    pub ip: IpAddr,
    /// Remote peer TCP port advertised in hello or observed on the socket.
    pub tcp_port: u16,
    /// Remote peer user hash when known.
    pub user_hash: Option<[u8; 16]>,
    /// Remote peer client-id when known.
    pub client_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct Ed2kUploadSessionKey {
    peer: Ed2kUploadPeerIdentity,
    file_hash: String,
}

/// Opaque handle bound to one live uploader transport session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ed2kUploadSessionHandle {
    key: Ed2kUploadSessionKey,
    connection_id: u64,
}

impl Ed2kUploadSessionHandle {
    pub(super) fn new(peer: Ed2kUploadPeerIdentity, file_hash: String, connection_id: u64) -> Self {
        Self {
            key: Ed2kUploadSessionKey { peer, file_hash },
            connection_id,
        }
    }

    pub(super) const fn key(&self) -> &Ed2kUploadSessionKey {
        &self.key
    }
}

/// Queue-visible state of one inbound upload session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ed2kUploadSessionStatus {
    /// The peer is queued and should see a rank.
    Waiting { rank: u16 },
    /// The peer currently owns an upload slot.
    Granted,
    /// The session expired, was cancelled, or was replaced by a reconnect.
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ed2kUploadSessionPhase {
    Waiting,
    Granted,
    Uploading,
}

#[derive(Debug, Clone)]
struct Ed2kUploadSessionEntry {
    phase: Ed2kUploadSessionPhase,
    connection_id: u64,
    last_activity: Instant,
}

#[derive(Debug)]
pub(super) struct Ed2kUploadQueueState {
    config: Ed2kUploadQueueConfig,
    sessions: HashMap<Ed2kUploadSessionKey, Ed2kUploadSessionEntry>,
    waiting_order: VecDeque<Ed2kUploadSessionKey>,
}

impl Ed2kUploadQueueState {
    pub(super) fn new(config: Ed2kUploadQueueConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            waiting_order: VecDeque::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn configure(&mut self, config: Ed2kUploadQueueConfig) {
        self.config = config;
        let now = Instant::now();
        self.reap_expired_sessions(now);
        self.trim_waiting_queue();
        self.promote_waiters(now);
    }

    pub(super) fn begin_session(
        &mut self,
        key: Ed2kUploadSessionKey,
        connection_id: u64,
        now: Instant,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
        if let Some(session) = self.sessions.get_mut(&key) {
            session.connection_id = connection_id;
            session.last_activity = now;
            return self.status_for_key(&key);
        }
        if let Some(existing_key) = self.session_key_for_peer(&key.peer) {
            let Some(mut session) = self.sessions.remove(&existing_key) else {
                unreachable!("existing peer queue key missing from session map");
            };
            if session.phase == Ed2kUploadSessionPhase::Waiting {
                self.replace_waiting_key(&existing_key, &key);
            }
            session.connection_id = connection_id;
            session.last_activity = now;
            self.sessions.insert(key.clone(), session);
            return self.status_for_key(&key);
        }

        let phase = if self.active_session_count() < self.config.active_slots {
            Ed2kUploadSessionPhase::Granted
        } else {
            self.trim_waiting_queue();
            self.waiting_order.push_back(key.clone());
            Ed2kUploadSessionPhase::Waiting
        };
        self.sessions.insert(
            key.clone(),
            Ed2kUploadSessionEntry {
                phase,
                connection_id,
                last_activity: now,
            },
        );
        self.status_for_key(&key)
    }

    pub(super) fn poll_session(
        &mut self,
        handle: &Ed2kUploadSessionHandle,
        now: Instant,
        refresh_activity: bool,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
        let Some(session) = self.sessions.get_mut(&handle.key) else {
            return Ed2kUploadSessionStatus::Stale;
        };
        if session.connection_id != handle.connection_id {
            return Ed2kUploadSessionStatus::Stale;
        }
        if refresh_activity {
            session.last_activity = now;
        }
        self.status_for_key(&handle.key)
    }

    pub(super) fn note_request_parts(
        &mut self,
        handle: &Ed2kUploadSessionHandle,
        now: Instant,
    ) -> Ed2kUploadSessionStatus {
        self.reap_expired_sessions(now);
        let Some(session) = self.sessions.get_mut(&handle.key) else {
            return Ed2kUploadSessionStatus::Stale;
        };
        if session.connection_id != handle.connection_id {
            return Ed2kUploadSessionStatus::Stale;
        }
        session.last_activity = now;
        if matches!(
            session.phase,
            Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading
        ) {
            session.phase = Ed2kUploadSessionPhase::Uploading;
            return Ed2kUploadSessionStatus::Granted;
        }
        self.status_for_key(&handle.key)
    }

    pub(super) fn release_session(&mut self, handle: &Ed2kUploadSessionHandle, now: Instant) {
        let Some(session) = self.sessions.get(&handle.key) else {
            return;
        };
        if session.connection_id != handle.connection_id {
            return;
        }
        let phase = session.phase;
        self.sessions.remove(&handle.key);
        if phase == Ed2kUploadSessionPhase::Waiting {
            self.waiting_order.retain(|key| key != &handle.key);
        }
        self.reap_expired_sessions(now);
        self.promote_waiters(now);
    }

    fn status_for_key(&self, key: &Ed2kUploadSessionKey) -> Ed2kUploadSessionStatus {
        match self.sessions.get(key).map(|session| session.phase) {
            Some(Ed2kUploadSessionPhase::Waiting) => Ed2kUploadSessionStatus::Waiting {
                rank: self.rank_for_key(key),
            },
            Some(Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading) => {
                Ed2kUploadSessionStatus::Granted
            }
            None => Ed2kUploadSessionStatus::Stale,
        }
    }

    fn rank_for_key(&self, key: &Ed2kUploadSessionKey) -> u16 {
        let Some(position) = self.waiting_order.iter().position(|queued| queued == key) else {
            return 0;
        };
        u16::try_from(position.saturating_add(1)).unwrap_or(u16::MAX)
    }

    fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| {
                matches!(
                    session.phase,
                    Ed2kUploadSessionPhase::Granted | Ed2kUploadSessionPhase::Uploading
                )
            })
            .count()
    }

    fn session_key_for_peer(&self, peer: &Ed2kUploadPeerIdentity) -> Option<Ed2kUploadSessionKey> {
        self.sessions
            .keys()
            .find(|existing_key| existing_key.peer == *peer)
            .cloned()
    }

    fn replace_waiting_key(
        &mut self,
        existing_key: &Ed2kUploadSessionKey,
        new_key: &Ed2kUploadSessionKey,
    ) {
        for queued in &mut self.waiting_order {
            if *queued == *existing_key {
                *queued = new_key.clone();
                return;
            }
        }
    }

    fn trim_waiting_queue(&mut self) {
        while self.waiting_order.len() >= self.config.waiting_capacity {
            let Some(evicted) = self.waiting_order.pop_front() else {
                break;
            };
            self.sessions.remove(&evicted);
        }
    }

    fn reap_expired_sessions(&mut self, now: Instant) {
        let expired = self
            .sessions
            .iter()
            .filter_map(|(key, session)| {
                let timeout = match session.phase {
                    Ed2kUploadSessionPhase::Waiting => self.config.waiting_timeout,
                    Ed2kUploadSessionPhase::Granted => self.config.granted_timeout,
                    Ed2kUploadSessionPhase::Uploading => self.config.upload_timeout,
                };
                (now.duration_since(session.last_activity) > timeout).then(|| key.clone())
            })
            .collect::<Vec<_>>();
        for key in expired {
            self.sessions.remove(&key);
            self.waiting_order.retain(|queued| queued != &key);
        }
        self.promote_waiters(now);
    }

    fn promote_waiters(&mut self, now: Instant) {
        while self.active_session_count() < self.config.active_slots {
            let Some(next_key) = self.waiting_order.pop_front() else {
                break;
            };
            let Some(next_session) = self.sessions.get_mut(&next_key) else {
                continue;
            };
            next_session.phase = Ed2kUploadSessionPhase::Granted;
            next_session.last_activity = now;
        }
    }
}
