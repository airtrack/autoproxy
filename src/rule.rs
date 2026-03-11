use anyhow::anyhow;
use std::{
    collections::HashMap,
    fs::read_to_string,
    io::{Error, ErrorKind, Result},
    net::SocketAddr,
    sync::Arc,
};

use aho_corasick::AhoCorasick;
use async_trait::async_trait;
use ipnet::IpNet;
use log::info;
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

pub trait Rule {
    fn find_proxy_rule(&self, host: &str) -> RuleResult;
}

#[async_trait]
pub trait AsyncRule: Sync + Send {
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

impl Rule for DirectRule {
    fn find_proxy_rule(&self, _: &str) -> RuleResult {
        self.rule
    }
}

#[async_trait]
impl AsyncRule for DirectRule {
    async fn find_proxy_rule(&self, _: &str) -> RuleResult {
        self.rule
    }
}

pub struct IpNetRule {
    net: IpNet,
    rule: RuleResult,
}

impl IpNetRule {
    pub fn new(ip_net: &str, rule: RuleResult) -> anyhow::Result<Self> {
        let net = ip_net.parse()?;
        Ok(Self { net, rule })
    }

    fn apply_proxy_rule(&self, host: &str) -> RuleResult {
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

impl Rule for IpNetRule {
    fn find_proxy_rule(&self, host: &str) -> RuleResult {
        self.apply_proxy_rule(host)
    }
}

#[async_trait]
impl AsyncRule for IpNetRule {
    async fn find_proxy_rule(&self, host: &str) -> RuleResult {
        self.apply_proxy_rule(host)
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

    fn apply_proxy_rule(&self, host: &str) -> RuleResult {
        if host.contains(&self.keyword) {
            self.rule
        } else {
            RuleResult::NotFound
        }
    }
}

impl Rule for DomainKeywordRule {
    fn find_proxy_rule(&self, host: &str) -> RuleResult {
        self.apply_proxy_rule(host)
    }
}

#[async_trait]
impl AsyncRule for DomainKeywordRule {
    async fn find_proxy_rule(&self, host: &str) -> RuleResult {
        self.apply_proxy_rule(host)
    }
}

pub fn load_ac_from_file(file: &str) -> anyhow::Result<Arc<AhoCorasick>> {
    let content = read_to_string(file)?;
    let lines = content.lines().filter(|line| !line.starts_with('#'));
    let ac = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(lines)?;
    Ok(Arc::new(ac))
}

pub struct DomainSuffixSetRule {
    ac: Arc<AhoCorasick>,
    rule: RuleResult,
}

impl DomainSuffixSetRule {
    pub fn new(ac: Arc<AhoCorasick>, rule: RuleResult) -> Self {
        Self { ac, rule }
    }

    fn apply_proxy_rule(&self, host: &str) -> RuleResult {
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

impl Rule for DomainSuffixSetRule {
    fn find_proxy_rule(&self, host: &str) -> RuleResult {
        self.apply_proxy_rule(host)
    }
}

#[async_trait]
impl AsyncRule for DomainSuffixSetRule {
    async fn find_proxy_rule(&self, host: &str) -> RuleResult {
        self.apply_proxy_rule(host)
    }
}

pub struct GeoIpRule {
    mmdb: Arc<Reader<Vec<u8>>>,
    country: String,
    rule: RuleResult,
}

impl GeoIpRule {
    pub fn new(mmdb: Arc<Reader<Vec<u8>>>, country: String, rule: RuleResult) -> Self {
        Self {
            mmdb,
            country,
            rule,
        }
    }

    async fn need_to_proxy(&self, host: &str) -> Result<RuleResult> {
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
impl AsyncRule for GeoIpRule {
    async fn find_proxy_rule(&self, host: &str) -> RuleResult {
        self.need_to_proxy(host)
            .await
            .unwrap_or(RuleResult::NotFound)
    }
}

#[derive(Clone)]
pub struct AutoRules {
    rules: Arc<Vec<Arc<dyn Rule>>>,
}

impl AutoRules {
    fn new(rules: Arc<Vec<Arc<dyn Rule>>>) -> Self {
        Self { rules }
    }

    pub fn apply_proxy_rules(&self, host: &str) -> RuleResult {
        for rule in self.rules.iter() {
            match rule.find_proxy_rule(host) {
                RuleResult::NotFound => {}
                r => return r,
            }
        }

        RuleResult::Direct
    }
}

#[derive(Clone)]
pub struct AsyncAutoRules {
    rules: Arc<Vec<Arc<dyn AsyncRule>>>,
}

impl AsyncAutoRules {
    fn new(rules: Arc<Vec<Arc<dyn AsyncRule>>>) -> Self {
        Self { rules }
    }

    pub async fn apply_proxy_rules(&self, host: &str) -> RuleResult {
        for rule in self.rules.iter() {
            match rule.find_proxy_rule(host).await {
                RuleResult::NotFound => {}
                r => return r,
            }
        }

        RuleResult::Direct
    }
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum RuleConfig {
    Direct {
        rule: RuleResult,
    },
    IpNet {
        ipnet: String,
        rule: RuleResult,
    },
    DomainKeyword {
        keyword: String,
        rule: RuleResult,
    },
    DomainSuffixSet {
        name: Option<String>,
        file: Option<String>,
        rule: RuleResult,
    },
    GeoIp {
        name: Option<String>,
        country: String,
        rule: RuleResult,
    },
}

#[derive(Deserialize)]
pub struct DomainSetConfig {
    pub name: String,
    pub file: String,
}

#[derive(Deserialize)]
pub struct MmdbSetConfig {
    pub name: String,
    pub file: String,
}

#[derive(Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub domain_sets: Vec<DomainSetConfig>,
    #[serde(default)]
    pub mmdb_sets: Vec<MmdbSetConfig>,
    pub mmdb: Option<String>,
    pub rules: Vec<RuleConfig>,
}

pub fn load_rules(config: RulesConfig) -> anyhow::Result<(AutoRules, AsyncAutoRules)> {
    let mut rules = Vec::<Arc<dyn Rule>>::new();
    let mut async_rules = Vec::<Arc<dyn AsyncRule>>::new();
    let mut ac_cache = HashMap::<String, Arc<AhoCorasick>>::new();
    let mut mmdb_cache = HashMap::<String, Arc<Reader<Vec<u8>>>>::new();

    for ds in config.domain_sets {
        info!("DomainSet {}: {}", ds.name, ds.file);
        let ac = load_ac_from_file(&ds.file)?;
        ac_cache.insert(ds.name, ac);
    }

    for ms in config.mmdb_sets {
        info!("MMDB {}: {}", ms.name, ms.file);
        let reader = Reader::open_readfile(&ms.file)?;
        mmdb_cache.insert(ms.name, Arc::new(reader));
    }

    let default_mmdb = if let Some(ref path) = config.mmdb {
        let reader = Reader::open_readfile(path)?;
        Some(Arc::new(reader))
    } else {
        None
    };

    for rule in config.rules {
        match rule {
            RuleConfig::Direct { rule } => {
                info!("DirectRule {rule:?}");
                let direct = Arc::new(DirectRule::new(rule));
                rules.push(direct.clone());
                async_rules.push(direct);
            }
            RuleConfig::IpNet { ipnet, rule } => {
                info!("IpNetRule {ipnet} {rule:?}");
                let ip_net = IpNetRule::new(&ipnet, rule)?;
                let net = Arc::new(ip_net);
                rules.push(net.clone());
                async_rules.push(net);
            }
            RuleConfig::DomainKeyword { keyword, rule } => {
                info!("DomainKeyword {keyword} {rule:?}");
                let keyword = Arc::new(DomainKeywordRule::new(keyword, rule));
                rules.push(keyword.clone());
                async_rules.push(keyword);
            }
            RuleConfig::DomainSuffixSet { name, file, rule } => {
                let ac = if let Some(ref name) = name {
                    info!("DomainSuffixSet name: {name} {rule:?}");
                    ac_cache.get(name).cloned().ok_or_else(|| {
                        anyhow!("Domain set '{name}' not found in domain_sets config")
                    })?
                } else if let Some(ref file) = file {
                    info!("DomainSuffixSet file: {file} {rule:?}");
                    load_ac_from_file(file)?
                } else {
                    return Err(anyhow!(
                        "Either 'name' or 'file' must be provided for DomainSuffixSet rule"
                    ));
                };

                let suffix_set = DomainSuffixSetRule::new(ac, rule);
                let set = Arc::new(suffix_set);
                rules.push(set.clone());
                async_rules.push(set);
            }
            RuleConfig::GeoIp {
                name,
                country,
                rule,
            } => {
                let mmdb = if let Some(ref name) = name {
                    info!("GeoIp name: {name} {country} {rule:?}");
                    mmdb_cache
                        .get(name)
                        .cloned()
                        .ok_or_else(|| anyhow!("MMDB set '{name}' not found in mmdb_sets config"))?
                } else {
                    info!("GeoIp {country} {rule:?}");
                    default_mmdb.as_ref().cloned().ok_or_else(|| {
                        anyhow!(
                            "Global mmdb is not configured and no name is provided for GeoIp rule"
                        )
                    })?
                };

                let geoip = GeoIpRule::new(mmdb, country, rule);
                async_rules.push(Arc::new(geoip));
            }
        }
    }

    let rules = AutoRules::new(Arc::new(rules));
    let async_rules = AsyncAutoRules::new(Arc::new(async_rules));

    Ok((rules, async_rules))
}
