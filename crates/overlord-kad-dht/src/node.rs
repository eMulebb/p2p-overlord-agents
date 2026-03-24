use crate::bootstrap::{BootstrapContact, hardcoded_bootstrap, parse_nodes_dat, parse_nodes_text};
use crate::error::DhtError;
use crate::traversal::{TraversalConfig, TraversalContact, TraversalKind, run_traversal};
use crate::types::{NoteResult, SearchResult, SourceResult};
use overlord_kad_net::{ObfuscationLayer, ReceivedKadPacket, RpcConfig, RpcManager, UdpTransport};
use overlord_kad_proto::{
    Ed2kHash, KadPacket, KadUdpKey, NodeId, SearchKeyReq, SearchSourceReq, Tag, constants::K,
    opcode,
};
use overlord_kad_routing::{Contact, RoutingTable};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::sync::{Mutex, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Configuration for DhtNode.
#[derive(Debug, Clone)]
pub struct DhtConfig {
    /// UDP bind address.
    pub bind_addr: SocketAddr,
    /// Our Kad2 node ID. All-zeros = generate random on start.
    pub node_id: NodeId,
    /// Max contacts in routing table.
    pub max_routing_table_size: usize,
    /// Max concurrent searches (semaphore).
    pub max_concurrent_searches: usize,
    /// Search timeout.
    pub search_timeout: Duration,
    /// Store/publish timeout.
    pub store_timeout: Duration,
    /// Republish interval.
    pub republish_interval: Duration,
    /// Max outbound packets per second. 0 = unlimited.
    pub max_outbound_pps: u32,
    /// Max number of phase-2 search packets to send after traversal.
    pub search_phase2_fanout: usize,
    /// Harvest-oriented keyword result cap.
    pub keyword_result_cap: usize,
    /// Harvest-oriented source result cap.
    pub source_result_cap: usize,
    /// Harvest-oriented notes result cap.
    pub notes_result_cap: usize,
    /// Obfuscation enabled.
    pub obfuscation_enabled: bool,
    /// Our UDP key (anti-spoofing). 0 = generate random.
    pub udp_key: u32,
    /// Bootstrap sources: binary nodes.dat content.
    pub nodes_dat: Option<Vec<u8>>,
    /// Bootstrap sources: plain text format.
    pub nodes_text: Option<String>,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:4672".parse().unwrap(),
            node_id: NodeId::ZERO,
            max_routing_table_size: 12000,
            max_concurrent_searches: 5,
            search_timeout: Duration::from_secs(45),
            store_timeout: Duration::from_secs(140),
            republish_interval: Duration::from_secs(18000),
            max_outbound_pps: 50,
            search_phase2_fanout: 50,
            keyword_result_cap: 5000,
            source_result_cap: 1000,
            notes_result_cap: 1000,
            obfuscation_enabled: true,
            udp_key: 0,
            nodes_dat: None,
            nodes_text: None,
        }
    }
}

struct DhtInner {
    own_id: NodeId,
    routing_table: Mutex<RoutingTable>,
    rpc: RpcManager,
    config: DhtConfig,
    /// Semaphore for limiting concurrent searches. Reserved for future use.
    #[allow(dead_code)]
    semaphore: Semaphore,
    bootstrapped: std::sync::atomic::AtomicBool,
}

/// The top-level DHT node. Clone-able (backed by Arc).
pub struct DhtNode {
    inner: Arc<DhtInner>,
}

impl Clone for DhtNode {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl DhtNode {
    /// Create a new DhtNode. Does NOT bind the socket or start any tasks.
    /// Call `start()` to begin.
    pub async fn new(mut config: DhtConfig) -> Result<Self, DhtError> {
        use rand::Rng;

        // Generate random node ID if not set
        if config.node_id == NodeId::ZERO {
            let bytes: [u8; 16] = rand::thread_rng().r#gen();
            config.node_id = NodeId::from_bytes(bytes);
        }

        // Generate random UDP key if not set
        if config.udp_key == 0 {
            config.udp_key = rand::thread_rng().r#gen();
        }

        let transport = UdpTransport::bind(config.bind_addr).await?;
        let obfuscation =
            ObfuscationLayer::new(config.node_id, config.udp_key, config.obfuscation_enabled);
        let rpc = RpcManager::new(
            transport,
            obfuscation,
            RpcConfig {
                max_outbound_pps: config.max_outbound_pps,
                ..RpcConfig::default()
            },
        );

        let routing_table =
            RoutingTable::with_max_size(config.node_id, config.max_routing_table_size);
        let semaphore = Semaphore::new(config.max_concurrent_searches);

        Ok(Self {
            inner: Arc::new(DhtInner {
                own_id: config.node_id,
                routing_table: Mutex::new(routing_table),
                rpc,
                config,
                semaphore,
                bootstrapped: std::sync::atomic::AtomicBool::new(false),
            }),
        })
    }

    /// Start the receive loop. Must be called before any DHT operations.
    /// Returns the JoinHandle for the background task.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        self.inner.rpc.start()
    }

    /// Our node ID.
    pub fn own_id(&self) -> NodeId {
        self.inner.own_id
    }

    /// Our UDP anti-spoofing key.
    pub fn udp_key(&self) -> u32 {
        self.inner.config.udp_key
    }

    /// Derive the Kad UDP verify key we should announce to a specific peer IP.
    pub fn verify_key_for_ip(&self, ip: Ipv4Addr) -> u32 {
        self.inner.rpc.verify_key_for_ip(ip)
    }

    /// Actual UDP bind address.
    pub fn bind_addr(&self) -> Result<SocketAddr, DhtError> {
        Ok(self.inner.rpc.local_addr()?)
    }

    /// Current routing table size.
    pub fn routing_table_size(&self) -> usize {
        match self.inner.routing_table.try_lock() {
            Ok(rt) => rt.len(),
            Err(_) => 0,
        }
    }

    /// True if the routing table has enough contacts to operate.
    pub fn is_bootstrapped(&self) -> bool {
        self.inner
            .bootstrapped
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Subscribe to unsolicited incoming Kad packets.
    pub fn subscribe_packets(&self) -> broadcast::Receiver<ReceivedKadPacket> {
        self.inner.rpc.subscribe()
    }

    /// Snapshot currently known contacts.
    pub async fn routing_contacts(&self) -> Vec<Contact> {
        self.inner.routing_table.lock().await.all_contacts()
    }

    /// Upsert a single contact into the routing table.
    pub async fn add_contact(&self, contact: Contact) -> Result<(), DhtError> {
        let addr = addr_from_contact(&contact);
        self.inner.rpc.register_peer_identity(addr, contact.id);
        self.inner
            .rpc
            .register_peer_version(addr, contact.kad_version);
        if contact.udp_key != KadUdpKey::ZERO {
            self.inner
                .rpc
                .register_peer_key(addr, contact.udp_key.value());
        }
        self.inner.routing_table.lock().await.add_contact(contact)?;
        Ok(())
    }

    /// Return the closest known contacts to the target.
    pub async fn closest_contacts(&self, target: &NodeId, limit: usize) -> Vec<Contact> {
        self.inner
            .routing_table
            .lock()
            .await
            .get_closest(target, limit)
    }

    /// Send a packet without waiting for a response.
    pub async fn send_packet(&self, addr: SocketAddr, packet: &KadPacket) -> Result<(), DhtError> {
        self.inner.rpc.send(addr, packet).await?;
        Ok(())
    }

    /// Register a peer's announced receiver verify key for obfuscated replies.
    pub fn register_peer_key(&self, addr: SocketAddr, udp_key: u32) {
        self.inner.rpc.register_peer_key(addr, udp_key);
    }

    /// Bootstrap from configured sources. Populates the routing table.
    pub async fn bootstrap(&self) -> Result<(), DhtError> {
        let contacts = self.load_bootstrap_contacts();

        if contacts.is_empty() {
            return Err(DhtError::NoBootstrapNodes);
        }

        info!("bootstrapping from {} contacts", contacts.len());

        let mut responded = 0usize;

        // Send BOOTSTRAP_REQ to up to 10 contacts
        for bc in contacts.iter().take(10) {
            let addr = SocketAddr::new(IpAddr::V4(bc.ip), bc.udp_port);
            if bc.node_id != NodeId::ZERO {
                self.inner.rpc.register_peer_identity(addr, bc.node_id);
            }
            self.inner.rpc.register_peer_version(addr, bc.version);
            if bc.udp_key != KadUdpKey::ZERO {
                self.inner.rpc.register_peer_key(addr, bc.udp_key.value());
            }
            debug!("bootstrap attempt to {}", addr);

            match self
                .inner
                .rpc
                .request(
                    addr,
                    &KadPacket::BootstrapReq,
                    opcode::BOOTSTRAP_RES,
                    Duration::from_secs(5),
                )
                .await
            {
                Ok(KadPacket::BootstrapRes(res)) => {
                    responded += 1;
                    let mut rt = self.inner.routing_table.lock().await;
                    for entry in res.contacts {
                        if entry.ip == 0 || entry.udp_port == 0 {
                            continue;
                        }
                        let contact = Contact::new(
                            entry.node_id,
                            entry.ip_addr(),
                            entry.udp_port,
                            entry.tcp_port,
                            entry.version,
                        );
                        self.inner
                            .rpc
                            .register_peer_identity(addr_from_contact(&contact), contact.id);
                        self.inner.rpc.register_peer_version(
                            addr_from_contact(&contact),
                            contact.kad_version,
                        );
                        let _ = rt.add_contact(contact);
                    }
                    info!(
                        "bootstrap response from {} - routing table now {} contacts",
                        addr,
                        rt.len()
                    );
                }
                Ok(_) => warn!("unexpected packet type during bootstrap from {}", addr),
                Err(e) => debug!("bootstrap contact {} failed: {}", addr, e),
            }
        }

        if responded == 0 {
            return Err(DhtError::BootstrapFailed);
        }

        // Run node lookup for own ID to fill routing table
        self.lookup_nodes(&self.inner.own_id).await?;

        let size = self.inner.routing_table.lock().await.len();
        info!("bootstrap complete - routing table has {} contacts", size);

        if size >= 10 {
            self.inner
                .bootstrapped
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        Ok(())
    }

    /// Iterative node lookup. Returns up to K contacts closest to target.
    pub async fn lookup_nodes(&self, target: &NodeId) -> Result<Vec<TraversalContact>, DhtError> {
        let initial = {
            let rt = self.inner.routing_table.lock().await;
            rt.get_closest(target, K)
                .into_iter()
                .map(|c| TraversalContact {
                    id: c.id,
                    addr: SocketAddr::new(IpAddr::V4(c.ip), c.udp_port),
                    version: c.kad_version,
                })
                .collect::<Vec<_>>()
        };

        let config = TraversalConfig {
            target: *target,
            search_kind: TraversalKind::FindNode,
            timeout: Duration::from_secs(45),
            query_timeout: Duration::from_secs(10),
            phase2_fanout: self.inner.config.search_phase2_fanout,
            cancel: CancellationToken::new(),
            result_tx: None,
        };

        let result = run_traversal(&self.inner.rpc, initial, config).await;

        // Add discovered contacts to routing table
        {
            let mut rt = self.inner.routing_table.lock().await;
            for contact in &result.closest {
                let ip = match contact.addr.ip() {
                    IpAddr::V4(ip) => ip,
                    _ => continue,
                };
                let c = Contact::new(
                    contact.id,
                    ip,
                    contact.addr.port(),
                    contact.addr.port(), // use same port for tcp as fallback
                    contact.version,
                );
                self.inner
                    .rpc
                    .register_peer_identity(addr_from_contact(&c), c.id);
                let _ = rt.add_contact(c);
            }
        }

        Ok(result.closest)
    }

    /// Search by keyword hash. Returns a Stream of results.
    pub fn search_keywords(
        &self,
        target: NodeId,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        self.search_keywords_with_cancel(target, CancellationToken::new())
    }

    pub fn search_keywords_with_cancel(
        &self,
        target: NodeId,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        self.search_keyword_request_with_cancel(
            SearchKeyReq {
                target,
                start_position: 0,
                restrictive_payload: Vec::new(),
            },
            cancel,
        )
    }

    /// Replay a full Kad keyword request shape harvested from the network.
    pub fn search_keyword_request(
        &self,
        request: SearchKeyReq,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        self.search_keyword_request_with_cancel(request, CancellationToken::new())
    }

    pub fn search_keyword_request_with_cancel(
        &self,
        request: SearchKeyReq,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        self.search_keyword_request_with_phase2_fanout_and_cancel(
            request,
            self.inner.config.search_phase2_fanout,
            cancel,
        )
    }

    /// Replay a harvested Kad keyword request shape with an explicit phase-2
    /// responder ceiling.
    pub fn search_keyword_request_with_phase2_fanout_and_cancel(
        &self,
        request: SearchKeyReq,
        phase2_fanout: usize,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        let target = request.target;
        let initial = self.closest_search_contacts(target);
        crate::search::search_keywords_by_request(
            self.inner.rpc.clone(),
            initial,
            request,
            self.inner.config.keyword_result_cap,
            phase2_fanout,
            cancel,
        )
    }

    /// Search for file sources. Returns a Stream of results.
    pub fn search_sources(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_sources_with_cancel(file_hash, file_size, CancellationToken::new())
    }

    pub fn search_sources_with_cancel(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_source_request_with_phase2_fanout_and_cancel(
            SearchSourceReq {
                target: NodeId::from_bytes(file_hash.0),
                start_position: 0,
                size: file_size,
            },
            self.inner.config.search_phase2_fanout,
            cancel,
        )
    }

    /// Replay a full Kad source request shape harvested from the network.
    pub fn search_source_request(
        &self,
        request: SearchSourceReq,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_source_request_with_cancel(request, CancellationToken::new())
    }

    pub fn search_source_request_with_cancel(
        &self,
        request: SearchSourceReq,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_source_request_with_phase2_fanout_and_cancel(
            request,
            self.inner.config.search_phase2_fanout,
            cancel,
        )
    }

    /// Search for file sources with an explicit phase-2 responder ceiling while
    /// preserving the full request shape.
    pub fn search_source_request_with_phase2_fanout_and_cancel(
        &self,
        request: SearchSourceReq,
        phase2_fanout: usize,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        let target = request.target;
        let initial = self.closest_search_contacts(target);
        crate::search::search_sources_by_request(
            self.inner.rpc.clone(),
            initial,
            request,
            self.inner.config.source_result_cap,
            phase2_fanout,
            cancel,
        )
    }

    /// Search for file sources with an explicit phase-2 responder ceiling.
    pub fn search_sources_with_phase2_fanout_and_cancel(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
        phase2_fanout: usize,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_source_request_with_phase2_fanout_and_cancel(
            SearchSourceReq {
                target: NodeId::from_bytes(file_hash.0),
                start_position: 0,
                size: file_size,
            },
            phase2_fanout,
            cancel,
        )
    }

    /// Search for notes/ratings. Returns a Stream of results.
    pub fn search_notes(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
    ) -> impl tokio_stream::Stream<Item = NoteResult> + Send + 'static {
        self.search_notes_with_cancel(file_hash, file_size, CancellationToken::new())
    }

    pub fn search_notes_with_cancel(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = NoteResult> + Send + 'static {
        self.search_notes_with_phase2_fanout_and_cancel(
            file_hash,
            file_size,
            self.inner.config.search_phase2_fanout,
            cancel,
        )
    }

    /// Search for notes/ratings with an explicit phase-2 responder ceiling.
    pub fn search_notes_with_phase2_fanout_and_cancel(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
        phase2_fanout: usize,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = NoteResult> + Send + 'static {
        let target = NodeId::from_bytes(file_hash.0);
        let initial = self.closest_search_contacts(target);
        crate::search::search_notes(
            self.inner.rpc.clone(),
            initial,
            file_hash,
            file_size,
            self.inner.config.notes_result_cap,
            phase2_fanout,
            cancel,
        )
    }

    /// Publish a keyword → file mapping.
    pub async fn publish_keyword(
        &self,
        keyword_hash: NodeId,
        file_hash: Ed2kHash,
        tags: Vec<Tag>,
    ) -> Result<crate::publish::PublishAttemptStats, DhtError> {
        crate::publish::publish_keyword(
            &self.inner.rpc,
            &self.inner.routing_table,
            keyword_hash,
            file_hash,
            tags,
        )
        .await
    }

    /// Publish source availability for a file.
    pub async fn publish_source(
        &self,
        file_hash: Ed2kHash,
        publisher_id: NodeId,
        tags: Vec<Tag>,
    ) -> Result<crate::publish::PublishAttemptStats, DhtError> {
        crate::publish::publish_source(
            &self.inner.rpc,
            &self.inner.routing_table,
            publisher_id,
            file_hash,
            tags,
        )
        .await
    }

    /// Publish a note/rating for a file.
    pub async fn publish_notes(
        &self,
        file_hash: Ed2kHash,
        note_hash: Ed2kHash,
        tags: Vec<Tag>,
    ) -> Result<usize, DhtError> {
        crate::publish::publish_notes(
            &self.inner.rpc,
            &self.inner.routing_table,
            file_hash,
            note_hash,
            tags,
        )
        .await
    }

    /// Returns the routing-table contacts used to seed one Kad search walk.
    fn closest_search_contacts(&self, target: NodeId) -> Vec<TraversalContact> {
        match self.inner.routing_table.try_lock() {
            Ok(rt) => rt
                .get_closest(&target, K)
                .into_iter()
                .map(|c| TraversalContact {
                    id: c.id,
                    addr: SocketAddr::new(IpAddr::V4(c.ip), c.udp_port),
                    version: c.kad_version,
                })
                .collect(),
            Err(_) => vec![],
        }
    }

    fn load_bootstrap_contacts(&self) -> Vec<BootstrapContact> {
        let mut contacts = Vec::new();

        // 1. nodes.dat binary
        if let Some(ref data) = self.inner.config.nodes_dat {
            match parse_nodes_dat(data) {
                Ok(c) => contacts.extend(c),
                Err(e) => warn!("failed to parse nodes.dat: {}", e),
            }
        }

        // 2. Text format
        if let Some(ref text) = self.inner.config.nodes_text {
            contacts.extend(parse_nodes_text(text));
        }

        // 3. Hardcoded fallback
        if contacts.is_empty() {
            contacts.extend(hardcoded_bootstrap());
        }

        contacts
    }
}

fn addr_from_contact(contact: &Contact) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(contact.ip), contact.udp_port)
}

#[cfg(test)]
mod tests {
    #[test]
    fn bootstrap_log_messages_are_ascii_only() {
        assert!(
            "bootstrap response from {addr} - routing table now {contacts} contacts".is_ascii()
        );
        assert!("bootstrap complete - routing table has {contacts} contacts".is_ascii());
    }
}
