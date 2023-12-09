use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
};

use async_trait::async_trait;
use ipnet::IpNet;
use maxminddb::{geoip2, Reader};
use serde::Deserialize;
use tokio::net;

#[derive(Debug, Copy, Clone, Deserialize)]
pub enum RuleResult {
    Proxy,
    Direct,
    NotFound,
}

#[async_trait]
pub trait Rule: Sync + Send {
    async fn find_proxy_rule(&self, host: &String) -> RuleResult;
}

pub struct DirectRule {
    rule: RuleResult,
}

impl DirectRule {
    pub fn new(rule: RuleResult) -> Self {
        Self { rule }
    }
}

#[async_trait]
impl Rule for DirectRule {
    async fn find_proxy_rule(&self, _: &String) -> RuleResult {
        self.rule
    }
}

pub struct IpNetRule {
    net: IpNet,
    rule: RuleResult,
}

impl IpNetRule {
    pub fn new(ip_net: &str, rule: RuleResult) -> Self {
        let net = ip_net.parse().unwrap();
        Self { net, rule }
    }
}

#[async_trait]
impl Rule for IpNetRule {
    async fn find_proxy_rule(&self, host: &String) -> RuleResult {
        match host.parse::<SocketAddr>() {
            Ok(addr) => {
                if self.net.contains(&addr.ip()) {
                    self.rule
                } else {
                    RuleResult::NotFound
                }
            }
            Err(_) => RuleResult::NotFound,
        }
    }
}

pub struct DomainKeywordRule {
    keyword: String,
    rule: RuleResult,
}

impl DomainKeywordRule {
    pub fn new(keyword: String, rule: RuleResult) -> Self {
        Self { keyword, rule }
    }
}

#[async_trait]
impl Rule for DomainKeywordRule {
    async fn find_proxy_rule(&self, host: &String) -> RuleResult {
        if host.contains(&self.keyword) {
            self.rule
        } else {
            RuleResult::NotFound
        }
    }
}

pub struct GeoIpRule {
    mmdb: Reader<Vec<u8>>,
    country: String,
    rule: RuleResult,
}

impl GeoIpRule {
    pub fn new(mmdb_path: &str, country: String, rule: RuleResult) -> Self {
        let mmdb = Reader::open_readfile(mmdb_path).unwrap();
        Self {
            mmdb,
            country,
            rule,
        }
    }

    async fn need_to_proxy(&self, host: &String) -> std::io::Result<RuleResult> {
        let addrs = net::lookup_host(host).await?;

        for addr in addrs {
            let country = self
                .mmdb
                .lookup::<geoip2::Country>(addr.ip())
                .map_err(|_| Error::new(ErrorKind::Other, "mmdb lookup error"))?;
            let in_country = country
                .country
                .map(|c| c.iso_code.map(|code| code == self.country).unwrap_or(false))
                .unwrap_or(false);
            if in_country {
                return Ok(self.rule);
            }
        }

        Ok(RuleResult::NotFound)
    }
}

#[async_trait]
impl Rule for GeoIpRule {
    async fn find_proxy_rule(&self, host: &String) -> RuleResult {
        self.need_to_proxy(host)
            .await
            .unwrap_or(RuleResult::NotFound)
    }
}
