use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Tracks incoming packet counts per IP and Kad opcode family to detect flooding.
pub struct PacketTracker {
    /// (packet_count, window_start)
    counts: HashMap<PacketTrackerKey, (u32, Instant)>,
    limits: HashMap<PacketTrackerBucket, PacketTrackerLimit>,
    default_limit: PacketTrackerLimit,
}

/// Flood-tracking key for one inbound packet family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketTrackerKey {
    /// Source IP that owns this budget.
    pub ip: IpAddr,
    /// Kad packet family that owns this budget.
    pub bucket: PacketTrackerBucket,
}

/// Inbound Kad packet family with distinct rate limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketTrackerBucket {
    /// Bootstrap request/response traffic.
    Bootstrap,
    /// HELLO request/response/ack traffic.
    Hello,
    /// Search request families share the oracle 3/min budget.
    SearchReq,
    /// Keyword publish requests use the eMule 4/min budget.
    PublishKeyReq,
    /// Source publish requests use the eMule 3/min budget.
    PublishSourceReq,
    /// Notes publish requests use the eMule 2/min budget.
    PublishNotesReq,
    /// Search responses keep the relaxed flood budget used by the current runtime.
    SearchRes,
    /// Control traffic such as ping/pong, lookup req/res, firewall checks and publish replies.
    Control,
    /// Fallback bucket for any packet family not classified explicitly.
    Default,
}

impl PacketTrackerBucket {
    /// Stable human-readable label used in logs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Hello => "hello",
            Self::SearchReq => "search_req",
            Self::PublishKeyReq => "publish_key_req",
            Self::PublishSourceReq => "publish_source_req",
            Self::PublishNotesReq => "publish_notes_req",
            Self::Control => "control",
            Self::Default => "default",
            Self::SearchRes => "search_res",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PacketTrackerLimit {
    max_packets: u32,
    window: Duration,
}

impl PacketTrackerLimit {
    fn new(max_packets: u32, window: Duration) -> Self {
        Self {
            max_packets,
            window,
        }
    }
}

/// Result of recording one inbound Kad packet against a tracker bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketTrackerDecision {
    /// Whether the packet is still within the bucket's configured budget.
    pub allowed: bool,
    /// Number of packets observed for this bucket within the active window.
    pub observed_packets: u32,
    /// Maximum packets allowed for this bucket within the active window.
    pub max_packets: u32,
    /// Active rate-limit window used for the bucket.
    pub window: Duration,
}

impl PacketTracker {
    /// Creates a tracker with oracle-shaped budgets for search/publish requests
    /// and configurable flood budgets for general traffic and `SEARCH_RES`.
    pub fn new(
        max_per_window: u32,
        search_res_max_per_window: u32,
        window: Duration,
        request_window: Duration,
    ) -> Self {
        let default_limit = PacketTrackerLimit::new(max_per_window, window);
        let limits = HashMap::from([
            (PacketTrackerBucket::Bootstrap, default_limit),
            (PacketTrackerBucket::Hello, default_limit),
            (
                PacketTrackerBucket::SearchReq,
                PacketTrackerLimit::new(3, request_window),
            ),
            (
                PacketTrackerBucket::PublishKeyReq,
                PacketTrackerLimit::new(4, request_window),
            ),
            (
                PacketTrackerBucket::PublishSourceReq,
                PacketTrackerLimit::new(3, request_window),
            ),
            (
                PacketTrackerBucket::PublishNotesReq,
                PacketTrackerLimit::new(2, request_window),
            ),
            (
                PacketTrackerBucket::SearchRes,
                PacketTrackerLimit::new(search_res_max_per_window, window),
            ),
            (PacketTrackerBucket::Control, default_limit),
        ]);
        Self {
            counts: HashMap::new(),
            limits,
            default_limit,
        }
    }

    /// Record an incoming packet from this IP.
    /// Returns the full decision so callers can log the exact bucket budget that applied.
    pub fn record_and_check(&mut self, key: PacketTrackerKey) -> PacketTrackerDecision {
        let now = Instant::now();
        let limit = self.limit_for_bucket(key.bucket);
        let entry = self.counts.entry(key).or_insert((0, now));

        // Reset window if expired
        if now.duration_since(entry.1) >= limit.window {
            *entry = (0, now);
        }

        entry.0 += 1;
        PacketTrackerDecision {
            allowed: entry.0 <= limit.max_packets,
            observed_packets: entry.0,
            max_packets: limit.max_packets,
            window: limit.window,
        }
    }

    /// Prune stale entries (call periodically to prevent memory growth).
    pub fn prune(&mut self) {
        let now = Instant::now();
        let limits = self.limits.clone();
        let default_limit = self.default_limit;
        self.counts.retain(|key, (_, window_start)| {
            let limit = limits.get(&key.bucket).copied().unwrap_or(default_limit);
            now.duration_since(*window_start) < limit.window.saturating_mul(2)
        });
    }

    fn limit_for_bucket(&self, bucket: PacketTrackerBucket) -> PacketTrackerLimit {
        self.limits
            .get(&bucket)
            .copied()
            .unwrap_or(self.default_limit)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn key(ip: &str, bucket: PacketTrackerBucket) -> PacketTrackerKey {
        PacketTrackerKey {
            ip: parse_ip(ip),
            bucket,
        }
    }

    #[test]
    fn test_normal_traffic_passes() {
        let mut tracker =
            PacketTracker::new(10, 100, Duration::from_secs(1), Duration::from_secs(60));
        let addr = key("1.2.3.4", PacketTrackerBucket::Default);
        for _ in 0..10 {
            assert!(tracker.record_and_check(addr).allowed);
        }
    }

    #[test]
    fn test_flood_over_limit_blocked() {
        let mut tracker =
            PacketTracker::new(5, 100, Duration::from_secs(1), Duration::from_secs(60));
        let addr = key("1.2.3.4", PacketTrackerBucket::Control);
        // First 5 pass
        for _ in 0..5 {
            assert!(tracker.record_and_check(addr).allowed);
        }
        // 6th and beyond are blocked
        assert!(!tracker.record_and_check(addr).allowed);
        assert!(!tracker.record_and_check(addr).allowed);
    }

    #[test]
    fn test_window_reset() {
        // Use a very short window to test expiry
        let mut tracker =
            PacketTracker::new(2, 100, Duration::from_millis(50), Duration::from_secs(60));
        let addr = key("5.6.7.8", PacketTrackerBucket::Control);
        assert!(tracker.record_and_check(addr).allowed);
        assert!(tracker.record_and_check(addr).allowed);
        assert!(!tracker.record_and_check(addr).allowed); // over limit

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(60));

        // Window should be reset — packets allowed again
        assert!(tracker.record_and_check(addr).allowed);
    }

    #[test]
    fn test_search_res_uses_higher_limit_than_default_bucket() {
        let mut tracker =
            PacketTracker::new(5, 50, Duration::from_secs(1), Duration::from_secs(60));
        let default_key = key("1.2.3.4", PacketTrackerBucket::Control);
        let search_res_key = key("1.2.3.4", PacketTrackerBucket::SearchRes);

        for _ in 0..5 {
            assert!(tracker.record_and_check(default_key).allowed);
        }
        assert!(!tracker.record_and_check(default_key).allowed);

        for _ in 0..50 {
            assert!(tracker.record_and_check(search_res_key).allowed);
        }
        assert!(!tracker.record_and_check(search_res_key).allowed);
    }

    #[test]
    fn test_search_requests_use_oracle_minute_budget() {
        let mut tracker =
            PacketTracker::new(20, 50, Duration::from_secs(1), Duration::from_secs(1));
        let search_key = key("1.2.3.4", PacketTrackerBucket::SearchReq);

        for _ in 0..3 {
            assert!(tracker.record_and_check(search_key).allowed);
        }
        let decision = tracker.record_and_check(search_key);
        assert!(!decision.allowed);
        assert_eq!(decision.max_packets, 3);
        assert_eq!(decision.window, Duration::from_secs(1));
    }

    #[test]
    fn test_publish_buckets_have_distinct_limits() {
        let mut tracker =
            PacketTracker::new(20, 50, Duration::from_secs(1), Duration::from_secs(60));
        let publish_key = key("1.2.3.4", PacketTrackerBucket::PublishKeyReq);
        let publish_source = key("1.2.3.4", PacketTrackerBucket::PublishSourceReq);
        let publish_notes = key("1.2.3.4", PacketTrackerBucket::PublishNotesReq);

        for _ in 0..4 {
            assert!(tracker.record_and_check(publish_key).allowed);
        }
        assert!(!tracker.record_and_check(publish_key).allowed);

        for _ in 0..3 {
            assert!(tracker.record_and_check(publish_source).allowed);
        }
        assert!(!tracker.record_and_check(publish_source).allowed);

        for _ in 0..2 {
            assert!(tracker.record_and_check(publish_notes).allowed);
        }
        assert!(!tracker.record_and_check(publish_notes).allowed);
    }
}
