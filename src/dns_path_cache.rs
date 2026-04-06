use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;

use crate::rule::RuleResult;

const MIN_TTL: Duration = Duration::from_secs(60);
const MAX_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone)]
pub struct DnsPathCache {
    entries: Arc<DashMap<IpAddr, CachedPath>>,
}

#[derive(Clone, Copy)]
struct CachedPath {
    path: RuleResult,
    expires_at: Instant,
}

impl DnsPathCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
        }
    }

    pub fn insert(&self, ip: IpAddr, path: RuleResult, ttl: u32) {
        if !matches!(path, RuleResult::Direct | RuleResult::Proxy) {
            return;
        }

        self.entries.insert(
            ip,
            CachedPath {
                path,
                expires_at: Instant::now() + clamp_ttl(ttl),
            },
        );
    }

    pub fn get(&self, ip: IpAddr) -> Option<RuleResult> {
        let entry = self.entries.get(&ip)?;
        if Instant::now() < entry.expires_at {
            return Some(entry.path);
        }

        drop(entry);
        self.entries.remove(&ip);
        None
    }

    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| now < entry.expires_at);
    }
}

fn clamp_ttl(ttl: u32) -> Duration {
    Duration::from_secs(ttl.into()).clamp(MIN_TTL, MAX_TTL)
}
