use std::{
    fs::read_to_string,
    io::{Error, ErrorKind},
    net::SocketAddr,
};

use aho_corasick::AhoCorasick;
use async_trait::async_trait;
use ipnet::IpNet;
use maxminddb::{Reader, geoip2};
use serde::Deserialize;
use tokio::net;

#[derive(Debug, Copy, Clone, Deserialize)]
pub enum RuleResult {
    Proxy,
    Direct,
    Block,
    NotFound,
}

#[async_trait]
pub trait Rule: Sync + Send {
    async fn find_proxy_rule(&self, host: &str) -> RuleResult;
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
    async fn find_proxy_rule(&self, _: &str) -> RuleResult {
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
    async fn find_proxy_rule(&self, host: &str) -> RuleResult {
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
    async fn find_proxy_rule(&self, host: &str) -> RuleResult {
        if host.contains(&self.keyword) {
            self.rule
        } else {
            RuleResult::NotFound
        }
    }
}

pub struct DomainSuffixSetRule {
    ac: AhoCorasick,
    rule: RuleResult,
}

impl DomainSuffixSetRule {
    pub fn new(file: &str, rule: RuleResult) -> Self {
        let content = read_to_string(file).unwrap();
        let lines = content.lines().filter(|line| !line.starts_with('#'));
        Self {
            ac: AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(lines)
                .unwrap(),
            rule,
        }
    }
}

#[async_trait]
impl Rule for DomainSuffixSetRule {
    async fn find_proxy_rule(&self, host: &str) -> RuleResult {
        let parts: Vec<&str> = host.split(':').collect();
        let domain = parts[0];
        for mat in self.ac.find_overlapping_iter(domain) {
            if mat.end() == domain.len() {
                let index = mat.start();
                if index == 0 {
                    return self.rule;
                }
                if &domain[index - 1..index] == "." {
                    return self.rule;
                }
            }
        }
        RuleResult::NotFound
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

    async fn need_to_proxy(&self, host: &str) -> std::io::Result<RuleResult> {
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
    async fn find_proxy_rule(&self, host: &str) -> RuleResult {
        self.need_to_proxy(host)
            .await
            .unwrap_or(RuleResult::NotFound)
    }
}
