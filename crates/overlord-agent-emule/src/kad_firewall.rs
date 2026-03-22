//! Minimal Kad UDP firewall-check state tracking.
//!
//! The oracle verifies UDP reachability by asking a small set of helper peers
//! to send `KADEMLIA2_FIREWALLUDP` packets back to us. This module keeps just
//! enough state to correlate those helper packets with an active verification
//! round and derive an "open", "firewalled", or "unverified" result.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use chrono::{DateTime, Utc};

/// Snapshot of one completed UDP firewall-check round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpFirewallCheckSummary {
    /// Whether at least one helper successfully reached our UDP port.
    pub open: bool,
    /// Number of helper peers that were selected for the round.
    pub helpers_selected: usize,
    /// Number of helper peers whose TCP request could be sent successfully.
    pub helpers_requested: usize,
    /// Number of helper peers that replied with a positive UDP check.
    pub helpers_succeeded: usize,
    /// Number of helper peers that reported an error or wrong port.
    pub helpers_failed: usize,
    /// Timestamp when the round started.
    pub started_at: DateTime<Utc>,
    /// Timestamp when the round finished.
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HelperOutcome {
    Pending,
    RequestFailed,
    RemoteError,
    WrongPort,
    Succeeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UdpFirewallCheckRound {
    started_at: DateTime<Utc>,
    expected_ports: HashSet<u16>,
    helper_outcomes: HashMap<IpAddr, HelperOutcome>,
}

/// Process-local Kad firewall verification state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KadFirewallState {
    /// Whether we currently have a verified UDP-open result.
    pub udp_open: bool,
    /// Whether the current UDP-open/firewalled status has been verified.
    pub udp_verified: bool,
    /// Timestamp of the most recent UDP firewall-check start.
    pub last_udp_check_started_at: Option<DateTime<Utc>>,
    /// Timestamp of the most recent successful UDP firewall-check.
    pub last_udp_check_succeeded_at: Option<DateTime<Utc>>,
    /// Timestamp of the most recent failed UDP firewall-check.
    pub last_udp_check_failed_at: Option<DateTime<Utc>>,
    /// Helper IP that last reported a UDP firewall-check result.
    pub last_helper_ip: Option<String>,
    /// UDP port most recently reported by a helper peer.
    pub last_reported_port: Option<u16>,
    /// Last firewall-check error captured by the runtime.
    pub last_error: Option<String>,
    active_round: Option<UdpFirewallCheckRound>,
}

/// Result of processing a `KADEMLIA2_FIREWALLUDP` packet for the active round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallUdpPacketOutcome {
    /// The packet completed the round with an "open" result.
    Open(UdpFirewallCheckSummary),
    /// The packet was associated with the active round but did not finish it.
    Recorded,
    /// The packet does not belong to the active round.
    Ignored,
}

impl KadFirewallState {
    /// Start a new UDP firewall-check round.
    pub fn begin_udp_check(
        &mut self,
        helper_ips: impl IntoIterator<Item = IpAddr>,
        expected_ports: impl IntoIterator<Item = u16>,
        started_at: DateTime<Utc>,
    ) -> bool {
        let helper_outcomes = helper_ips
            .into_iter()
            .map(|ip| (ip, HelperOutcome::Pending))
            .collect::<HashMap<_, _>>();
        if helper_outcomes.is_empty() {
            self.last_error = Some("no UDP firewall-check helpers available".to_string());
            return false;
        }

        let expected_ports = expected_ports
            .into_iter()
            .filter(|port| *port != 0)
            .collect::<HashSet<_>>();
        if expected_ports.is_empty() {
            self.last_error = Some("UDP firewall-check has no expected ports".to_string());
            return false;
        }

        self.last_udp_check_started_at = Some(started_at);
        self.last_error = None;
        self.active_round = Some(UdpFirewallCheckRound {
            started_at,
            expected_ports,
            helper_outcomes,
        });
        true
    }

    /// Mark one helper request as failed before any UDP probe arrives.
    pub fn record_helper_request_failed(&mut self, helper_ip: IpAddr, error: &str) {
        if let Some(round) = &mut self.active_round
            && let Some(outcome) = round.helper_outcomes.get_mut(&helper_ip)
        {
            *outcome = HelperOutcome::RequestFailed;
            self.last_helper_ip = Some(helper_ip.to_string());
            self.last_error = Some(error.to_string());
        }
    }

    /// Record an inbound `KADEMLIA2_FIREWALLUDP` packet for the current round.
    pub fn record_firewall_udp_packet(
        &mut self,
        helper_ip: IpAddr,
        error_code: u8,
        incoming_port: u16,
        observed_at: DateTime<Utc>,
    ) -> FirewallUdpPacketOutcome {
        let Some(round) = &mut self.active_round else {
            return FirewallUdpPacketOutcome::Ignored;
        };
        let Some(outcome) = round.helper_outcomes.get_mut(&helper_ip) else {
            return FirewallUdpPacketOutcome::Ignored;
        };

        self.last_helper_ip = Some(helper_ip.to_string());
        self.last_reported_port = Some(incoming_port);

        if error_code == 0 && round.expected_ports.contains(&incoming_port) {
            *outcome = HelperOutcome::Succeeded;
            let summary = finalize_round(
                &mut self.active_round,
                true,
                observed_at,
                &mut self.udp_open,
                &mut self.udp_verified,
                &mut self.last_udp_check_succeeded_at,
                &mut self.last_udp_check_failed_at,
            )
            .expect("active round disappeared while marking success");
            self.last_error = None;
            return FirewallUdpPacketOutcome::Open(summary);
        }

        *outcome = if error_code == 0 {
            HelperOutcome::WrongPort
        } else {
            HelperOutcome::RemoteError
        };
        FirewallUdpPacketOutcome::Recorded
    }

    /// Finalize the current round after the runtime wait timeout expires.
    pub fn finish_udp_check(
        &mut self,
        completed_at: DateTime<Utc>,
    ) -> Option<UdpFirewallCheckSummary> {
        let round = self.active_round.as_ref()?;
        if round
            .helper_outcomes
            .values()
            .all(|outcome| matches!(outcome, HelperOutcome::Succeeded))
        {
            return None;
        }

        if round
            .helper_outcomes
            .values()
            .any(|outcome| matches!(outcome, HelperOutcome::Succeeded))
        {
            return finalize_round(
                &mut self.active_round,
                true,
                completed_at,
                &mut self.udp_open,
                &mut self.udp_verified,
                &mut self.last_udp_check_succeeded_at,
                &mut self.last_udp_check_failed_at,
            );
        }

        let no_requests_sent = round
            .helper_outcomes
            .values()
            .all(|outcome| matches!(outcome, HelperOutcome::RequestFailed));
        if no_requests_sent {
            self.last_error = Some("all UDP firewall-check TCP requests failed".to_string());
            self.active_round = None;
            return None;
        }

        self.last_error =
            Some("UDP firewall-check timed out without a positive result".to_string());
        finalize_round(
            &mut self.active_round,
            false,
            completed_at,
            &mut self.udp_open,
            &mut self.udp_verified,
            &mut self.last_udp_check_succeeded_at,
            &mut self.last_udp_check_failed_at,
        )
    }
}

fn finalize_round(
    round: &mut Option<UdpFirewallCheckRound>,
    open: bool,
    completed_at: DateTime<Utc>,
    udp_open: &mut bool,
    udp_verified: &mut bool,
    last_succeeded_at: &mut Option<DateTime<Utc>>,
    last_failed_at: &mut Option<DateTime<Utc>>,
) -> Option<UdpFirewallCheckSummary> {
    let round = round.take()?;
    let helpers_selected = round.helper_outcomes.len();
    let helpers_requested = round
        .helper_outcomes
        .values()
        .filter(|outcome| !matches!(outcome, HelperOutcome::RequestFailed))
        .count();
    let helpers_succeeded = round
        .helper_outcomes
        .values()
        .filter(|outcome| matches!(outcome, HelperOutcome::Succeeded))
        .count();
    let helpers_failed = round
        .helper_outcomes
        .values()
        .filter(|outcome| !matches!(outcome, HelperOutcome::Pending | HelperOutcome::Succeeded))
        .count();

    *udp_open = open;
    *udp_verified = true;
    if open {
        *last_succeeded_at = Some(completed_at);
    } else {
        *last_failed_at = Some(completed_at);
    }

    Some(UdpFirewallCheckSummary {
        open,
        helpers_selected,
        helpers_requested,
        helpers_succeeded,
        helpers_failed,
        started_at: round.started_at,
        completed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::{FirewallUdpPacketOutcome, KadFirewallState};
    use chrono::{TimeZone, Utc};

    #[test]
    fn udp_round_marks_open_on_matching_port() {
        let mut state = KadFirewallState::default();
        let helper = "203.0.113.10".parse().unwrap();
        let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 30, 0).unwrap();
        let observed_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 30, 5).unwrap();

        assert!(state.begin_udp_check([helper], [41000, 51000], started_at));
        let outcome = state.record_firewall_udp_packet(helper, 0, 41000, observed_at);

        match outcome {
            FirewallUdpPacketOutcome::Open(summary) => {
                assert!(summary.open);
                assert_eq!(summary.helpers_succeeded, 1);
            }
            other => panic!("expected open result, got {other:?}"),
        }

        assert!(state.udp_open);
        assert!(state.udp_verified);
        assert_eq!(state.last_reported_port, Some(41000));
    }

    #[test]
    fn udp_round_times_out_as_firewalled_after_negative_results() {
        let mut state = KadFirewallState::default();
        let helper_a = "203.0.113.10".parse().unwrap();
        let helper_b = "203.0.113.11".parse().unwrap();
        let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 31, 0).unwrap();
        let completed_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 31, 20).unwrap();

        assert!(state.begin_udp_check([helper_a, helper_b], [41000], started_at));
        let _ = state.record_firewall_udp_packet(helper_a, 1, 41000, completed_at);
        let _ = state.record_firewall_udp_packet(helper_b, 0, 42000, completed_at);
        let summary = state.finish_udp_check(completed_at).expect("summary");

        assert!(!summary.open);
        assert!(!state.udp_open);
        assert!(state.udp_verified);
        assert_eq!(summary.helpers_failed, 2);
    }

    #[test]
    fn udp_round_stays_unverified_when_no_tcp_request_can_be_sent() {
        let mut state = KadFirewallState::default();
        let helper = "203.0.113.12".parse().unwrap();
        let started_at = Utc.with_ymd_and_hms(2026, 3, 22, 22, 32, 0).unwrap();

        assert!(state.begin_udp_check([helper], [41000], started_at));
        state.record_helper_request_failed(helper, "connect failed");

        assert!(state.finish_udp_check(started_at).is_none());
        assert!(!state.udp_verified);
        assert_eq!(
            state.last_error.as_deref(),
            Some("all UDP firewall-check TCP requests failed")
        );
    }
}
