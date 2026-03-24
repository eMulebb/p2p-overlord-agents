use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Tracks incoming packet counts per IP to detect flooding.
pub struct PacketTracker {
    /// (packet_count, window_start)
    counts: HashMap<PacketTrackerKey, (u32, Instant)>,
    max_per_window: u32,
    search_res_max_per_window: u32,
    window: Duration,
}

/// Flood-tracking key for one inbound packet family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketTrackerKey {
    pub ip: IpAddr,
    pub bucket: PacketTrackerBucket,
}

/// Inbound packet family with distinct flood limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketTrackerBucket {
    Default,
    SearchRes,
}

impl PacketTrackerBucket {
    /// Stable human-readable label used in logs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::SearchRes => "search_res",
        }
    }
}

impl PacketTracker {
    /// Creates a tracker with separate budgets for regular traffic and SEARCH_RES floods.
    pub fn new(max_per_window: u32, search_res_max_per_window: u32, window: Duration) -> Self {
        Self {
            counts: HashMap::new(),
            max_per_window,
            search_res_max_per_window,
            window,
        }
    }

    /// Record an incoming packet from this IP.
    /// Returns `true` if the packet should be allowed, `false` if it's over limit.
    pub fn record_and_check(&mut self, key: PacketTrackerKey) -> bool {
        let now = Instant::now();
        let entry = self.counts.entry(key).or_insert((0, now));

        // Reset window if expired
        if now.duration_since(entry.1) >= self.window {
            *entry = (0, now);
        }

        entry.0 += 1;
        entry.0 <= self.limit_for_bucket(key.bucket)
    }

    /// Prune stale entries (call periodically to prevent memory growth).
    pub fn prune(&mut self) {
        let now = Instant::now();
        self.counts
            .retain(|_, (_, window_start)| now.duration_since(*window_start) < self.window * 2);
    }

    fn limit_for_bucket(&self, bucket: PacketTrackerBucket) -> u32 {
        match bucket {
            PacketTrackerBucket::Default => self.max_per_window,
            PacketTrackerBucket::SearchRes => self.search_res_max_per_window,
        }
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
        let mut tracker = PacketTracker::new(10, 100, Duration::from_secs(1));
        let addr = key("1.2.3.4", PacketTrackerBucket::Default);
        for _ in 0..10 {
            assert!(tracker.record_and_check(addr));
        }
    }

    #[test]
    fn test_flood_over_limit_blocked() {
        let mut tracker = PacketTracker::new(5, 100, Duration::from_secs(1));
        let addr = key("1.2.3.4", PacketTrackerBucket::Default);
        // First 5 pass
        for _ in 0..5 {
            assert!(tracker.record_and_check(addr));
        }
        // 6th and beyond are blocked
        assert!(!tracker.record_and_check(addr));
        assert!(!tracker.record_and_check(addr));
    }

    #[test]
    fn test_window_reset() {
        // Use a very short window to test expiry
        let mut tracker = PacketTracker::new(2, 100, Duration::from_millis(50));
        let addr = key("5.6.7.8", PacketTrackerBucket::Default);
        assert!(tracker.record_and_check(addr));
        assert!(tracker.record_and_check(addr));
        assert!(!tracker.record_and_check(addr)); // over limit

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(60));

        // Window should be reset — packets allowed again
        assert!(tracker.record_and_check(addr));
    }

    #[test]
    fn test_search_res_uses_higher_limit_than_default_bucket() {
        let mut tracker = PacketTracker::new(5, 50, Duration::from_secs(1));
        let default_key = key("1.2.3.4", PacketTrackerBucket::Default);
        let search_res_key = key("1.2.3.4", PacketTrackerBucket::SearchRes);

        for _ in 0..5 {
            assert!(tracker.record_and_check(default_key));
        }
        assert!(!tracker.record_and_check(default_key));

        for _ in 0..50 {
            assert!(tracker.record_and_check(search_res_key));
        }
        assert!(!tracker.record_and_check(search_res_key));
    }
}
