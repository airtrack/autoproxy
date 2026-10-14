//! Metric names, label vocabularies and the metadata the telemetry setup
//! installs.
//!
//! Recording goes through the `metrics` macros at each call site and resolves
//! against the global recorder, so this module holds no state: it defines the
//! name table and the closed set of label values, and [`describe_metrics`] plus
//! [`histogram_bounds`] are called once by
//! [`Telemetry::init`](crate::telemetry::Telemetry::init) at startup — before
//! anything is recorded, because a recorder cannot restate a metric's
//! description or its buckets after its first use. With no recorder installed
//! every call below is a no-op.
//!
//! Every label value comes from one of the enums in this module, so a domain,
//! an IP or a proxy address can never become a label.

use metrics::{Unit, describe_counter, describe_gauge, describe_histogram};

use crate::rule::RuleResult;

/// Accepted client connections that finished, by protocol. Every connection is
/// counted once, whether it relayed, failed to connect or was blocked.
pub const CONNECTIONS: &str = "autoproxy.proxy.connections";
/// Time from accepting a client connection to it ending.
pub const CONNECTION_DURATION: &str = "autoproxy.proxy.connection.duration";
/// Client connections currently being served.
pub const ACTIVE_CONNECTIONS: &str = "autoproxy.proxy.active_connections";
/// Routing decisions per connection, by the path chosen.
pub const CONNECT_DECISIONS: &str = "autoproxy.proxy.connect.decisions";
/// SOCKS5 UDP packets relayed, by direction.
pub const UDP_PACKETS: &str = "autoproxy.proxy.udp.packets";
/// SOCKS5 UDP payload bytes relayed, by direction.
pub const UDP_BYTES: &str = "autoproxy.proxy.udp.bytes";
/// SOCKS5 UDP packets dropped by a `Block` rule.
pub const UDP_BLOCKED: &str = "autoproxy.proxy.udp.blocked";
/// DNS queries answered or forwarded, by query type and routing path.
pub const DNS_QUERIES: &str = "autoproxy.dns.queries";
/// Time from forwarding a DNS query upstream to its response arriving.
pub const DNS_UPSTREAM_DURATION: &str = "autoproxy.dns.upstream.duration";
/// DNS queries that could not be sent upstream, by path.
pub const DNS_UPSTREAM_ERRORS: &str = "autoproxy.dns.upstream.errors";
/// DNS queries waiting for an upstream response.
pub const DNS_IN_FLIGHT: &str = "autoproxy.dns.in_flight";
/// Addresses currently held by the DNS path cache.
pub const DNS_CACHE_ENTRIES: &str = "autoproxy.dns.cache.entries";
/// Lookups in the DNS path cache, by result. A miss re-runs the rules.
pub const DNS_CACHE_LOOKUPS: &str = "autoproxy.dns.cache.lookups";

/// One finished client connection. Recorded for HTTP and SOCKS5 alike; a UDP
/// association counts once, for its whole life.
pub fn connection_finished(protocol: Protocol, outcome: Outcome, elapsed_secs: f64) {
    metrics::gauge!(ACTIVE_CONNECTIONS, "protocol" => protocol.as_str()).decrement(1.0);
    metrics::counter!(
        CONNECTIONS,
        "protocol" => protocol.as_str(),
        "outcome" => outcome.as_str(),
    )
    .increment(1);
    metrics::histogram!(
        CONNECTION_DURATION,
        "protocol" => protocol.as_str(),
        "outcome" => outcome.as_str(),
    )
    .record(elapsed_secs);
}

/// One accepted client connection: the pair of this and
/// [`connection_finished`] is what makes the active gauge follow the listener.
pub fn connection_started(protocol: Protocol) {
    metrics::gauge!(ACTIVE_CONNECTIONS, "protocol" => protocol.as_str()).increment(1.0);
}

/// The path one connection took, recorded once the rules have been applied.
pub fn connect_decision(protocol: Protocol, path: Path) {
    metrics::counter!(
        CONNECT_DECISIONS,
        "protocol" => protocol.as_str(),
        "path" => path.as_str(),
    )
    .increment(1);
}

/// One relayed SOCKS5 UDP packet and its payload size.
pub fn udp_packet(direction: Direction, bytes: u64) {
    let direction = direction.as_str();
    metrics::counter!(UDP_PACKETS, "direction" => direction).increment(1);
    metrics::counter!(UDP_BYTES, "direction" => direction).increment(bytes);
}

/// One SOCKS5 UDP packet a `Block` rule dropped. The packet never leaves the
/// process, so it has neither direction nor size worth reporting.
pub fn udp_blocked() {
    metrics::counter!(UDP_BLOCKED).increment(1);
}

/// One client DNS query, by the answer path it took.
pub fn dns_query(query_type: QueryType, path: Path) {
    metrics::counter!(
        DNS_QUERIES,
        "type" => query_type.as_str(),
        "path" => path.as_str(),
    )
    .increment(1);
}

/// One upstream DNS response, timed from the request that was forwarded.
pub fn dns_upstream_duration(path: Path, elapsed_secs: f64) {
    metrics::histogram!(DNS_UPSTREAM_DURATION, "path" => path.as_str()).record(elapsed_secs);
}

/// One upstream DNS query that could not be sent.
pub fn dns_upstream_error(path: Path) {
    metrics::counter!(DNS_UPSTREAM_ERRORS, "path" => path.as_str()).increment(1);
}

/// Upstream DNS queries currently waiting for a response.
pub fn dns_in_flight(count: usize) {
    metrics::gauge!(DNS_IN_FLIGHT).set(count as f64);
}

/// The DNS path cache's current size.
pub fn dns_cache_entries(count: usize) {
    metrics::gauge!(DNS_CACHE_ENTRIES).set(count as f64);
}

/// One lookup in the DNS path cache.
pub fn dns_cache_lookup(result: CacheLookup) {
    metrics::counter!(DNS_CACHE_LOOKUPS, "result" => result.as_str()).increment(1);
}

/// Which listener a connection arrived on. Labels `protocol`.
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Http,
    Socks5,
}

impl Protocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
        }
    }
}

/// How a connection, or a step of one, ended. Labels `outcome`.
#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    Ok,
    Error,
}

impl Outcome {
    pub const fn of(success: bool) -> Self {
        match success {
            true => Self::Ok,
            false => Self::Error,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

/// Where a target was sent. Labels `path`.
///
/// `Hosts` is a connection answered from the hosts files rather than by the
/// rules; `Block` is a connection (or query) the rules refused.
#[derive(Debug, Clone, Copy)]
pub enum Path {
    Direct,
    Proxy,
    Hosts,
    Block,
}

impl Path {
    /// The path a rule result selects. `NotFound` never reaches a decision —
    /// the rule chain falls back to `Direct` — and maps there too.
    pub const fn of(result: RuleResult) -> Self {
        match result {
            RuleResult::Proxy => Self::Proxy,
            RuleResult::Block => Self::Block,
            RuleResult::Direct | RuleResult::NotFound => Self::Direct,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Proxy => "proxy",
            Self::Hosts => "hosts",
            Self::Block => "block",
        }
    }
}

/// Which way one relayed UDP packet went. Labels `direction`: `Up` is client
/// to target, `Down` is target to client.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Up,
    Down,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
        }
    }
}

/// The query type of a client DNS query. Labels `type`.
#[derive(Debug, Clone, Copy)]
pub enum QueryType {
    A,
    Aaaa,
    Other,
}

impl QueryType {
    pub const fn of(record_type: hickory_proto::rr::RecordType) -> Self {
        match record_type {
            hickory_proto::rr::RecordType::A => Self::A,
            hickory_proto::rr::RecordType::AAAA => Self::Aaaa,
            _ => Self::Other,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::Aaaa => "aaaa",
            Self::Other => "other",
        }
    }
}

/// Whether the DNS path cache knew an address. Labels `result`.
#[derive(Debug, Clone, Copy)]
pub enum CacheLookup {
    Hit,
    Miss,
}

impl CacheLookup {
    pub const fn of(cached: bool) -> Self {
        match cached {
            true => Self::Hit,
            false => Self::Miss,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
        }
    }
}

/// Histogram bucket boundaries per metric, in the recorder's terms. The scale
/// groups differ by orders of magnitude — a proxied connection can live for
/// minutes or hours, a DNS lookup resolves in milliseconds or seconds — which
/// is why the boundaries are per metric rather than one global set.
/// [`Telemetry::init`](crate::telemetry::Telemetry::init) installs them once,
/// before anything is recorded: a recorder cannot restate buckets after a
/// metric's first use.
pub fn histogram_bounds() -> Vec<(&'static str, Vec<f64>)> {
    let connection_seconds = vec![
        0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0,
    ];
    let upstream_seconds = vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
    ];

    vec![
        (CONNECTION_DURATION, connection_seconds),
        (DNS_UPSTREAM_DURATION, upstream_seconds),
    ]
}

/// Describe every metric this crate records. Must run before the first
/// recording: the recorder stores descriptions per name and never restates
/// them, so a metric described late exports without one.
pub fn describe_metrics() {
    describe_counter!(
        CONNECTIONS,
        Unit::Count,
        "Client connections served, by listener protocol and outcome"
    );
    describe_histogram!(
        CONNECTION_DURATION,
        Unit::Seconds,
        "Wall-clock duration of one client connection"
    );
    describe_gauge!(
        ACTIVE_CONNECTIONS,
        Unit::Count,
        "Client connections currently being served"
    );
    describe_counter!(
        CONNECT_DECISIONS,
        Unit::Count,
        "Connections by the routing path their target took"
    );
    describe_counter!(
        UDP_PACKETS,
        Unit::Count,
        "SOCKS5 UDP packets relayed, by direction"
    );
    describe_counter!(
        UDP_BYTES,
        Unit::Bytes,
        "SOCKS5 UDP payload bytes relayed, by direction"
    );
    describe_counter!(
        UDP_BLOCKED,
        Unit::Count,
        "SOCKS5 UDP packets dropped by a Block rule"
    );
    describe_counter!(
        DNS_QUERIES,
        Unit::Count,
        "DNS queries handled, by query type and answer path"
    );
    describe_histogram!(
        DNS_UPSTREAM_DURATION,
        Unit::Seconds,
        "Time from forwarding a DNS query upstream to its response"
    );
    describe_counter!(
        DNS_UPSTREAM_ERRORS,
        Unit::Count,
        "DNS queries that could not be sent upstream"
    );
    describe_gauge!(
        DNS_IN_FLIGHT,
        Unit::Count,
        "DNS queries waiting for an upstream response"
    );
    describe_gauge!(
        DNS_CACHE_ENTRIES,
        Unit::Count,
        "Addresses currently held by the DNS path cache"
    );
    describe_counter!(
        DNS_CACHE_LOOKUPS,
        Unit::Count,
        "Lookups in the DNS path cache, a miss re-runs the rules"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_described_metric_has_a_name_a_backend_can_read() {
        // The names are the contract with the collector; a typo here would
        // silently create a second series. No name carries a `_total` suffix
        // either: the exporter adds the aggregation, not the name.
        for name in [
            CONNECTIONS,
            CONNECTION_DURATION,
            ACTIVE_CONNECTIONS,
            CONNECT_DECISIONS,
            UDP_PACKETS,
            UDP_BYTES,
            UDP_BLOCKED,
            DNS_QUERIES,
            DNS_UPSTREAM_DURATION,
            DNS_UPSTREAM_ERRORS,
            DNS_IN_FLIGHT,
            DNS_CACHE_ENTRIES,
            DNS_CACHE_LOOKUPS,
        ] {
            assert!(name.starts_with("autoproxy."), "{name}");
            assert!(!name.ends_with("_total"), "{name}");
        }
    }

    #[test]
    fn histogram_bounds_cover_every_histogram() {
        let bounded: Vec<&str> = histogram_bounds().into_iter().map(|(n, _)| n).collect();
        for name in [CONNECTION_DURATION, DNS_UPSTREAM_DURATION] {
            assert!(bounded.contains(&name), "no bounds for {name}");
        }
        // Ascending, or the recorder's bucketing is meaningless.
        for (name, bounds) in histogram_bounds() {
            assert!(bounds.windows(2).all(|w| w[0] < w[1]), "{name}");
        }
    }

    #[test]
    fn the_rule_fallback_is_a_direct_path() {
        assert_eq!(Path::of(RuleResult::Proxy).as_str(), "proxy");
        assert_eq!(Path::of(RuleResult::Block).as_str(), "block");
        assert_eq!(Path::of(RuleResult::Direct).as_str(), "direct");
        assert_eq!(Path::of(RuleResult::NotFound).as_str(), "direct");
    }

    #[test]
    fn label_values_are_lowercase_and_closed() {
        assert_eq!(Protocol::Http.as_str(), "http");
        assert_eq!(Protocol::Socks5.as_str(), "socks5");
        assert_eq!(Outcome::of(true).as_str(), "ok");
        assert_eq!(Outcome::of(false).as_str(), "error");
        assert_eq!(
            QueryType::of(hickory_proto::rr::RecordType::AAAA).as_str(),
            "aaaa"
        );
        assert_eq!(
            QueryType::of(hickory_proto::rr::RecordType::TXT).as_str(),
            "other"
        );
        assert_eq!(CacheLookup::of(true).as_str(), "hit");
        assert_eq!(CacheLookup::of(false).as_str(), "miss");
    }
}
