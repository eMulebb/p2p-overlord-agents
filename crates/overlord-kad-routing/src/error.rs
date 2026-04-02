/// Scope of a routing-table subnet-limit rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingSubnetLimitScope {
    /// The table-wide `/24` cap rejected the contact.
    Global,
    /// The destination bin already has the oracle-local `/24` allotment.
    BinLocal,
}

/// Why a full leaf bin was not allowed to split further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingSplitDeniedReason {
    /// The routing tree already reached the hard Kad depth ceiling.
    DepthLimit,
    /// The local table-size ceiling blocked further expansion.
    MaxTableSize,
    /// Oracle `CanSplit` no longer allows this zone index to split at this depth.
    ZoneIndexCap,
}

#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error("routing table is full (max {max} contacts)")]
    TableFull { max: usize },
    #[error("duplicate IP: {ip}")]
    IpLimitExceeded { ip: std::net::Ipv4Addr },
    #[error("subnet /{prefix} limit exceeded in {scope:?} scope")]
    SubnetLimitExceeded {
        prefix: u8,
        scope: RoutingSubnetLimitScope,
    },
    #[error("routing leaf could not split because of {reason:?}")]
    SplitDenied { reason: RoutingSplitDeniedReason },
}
