use std::{
    collections::HashMap,
    fs::read_to_string,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use anyhow::{anyhow, bail};
use log::info;

#[derive(Clone, Default)]
pub struct Hosts {
    ipv4: Arc<HashMap<String, Ipv4Addr>>,
    ipv6: Arc<HashMap<String, Ipv6Addr>>,
}

impl Hosts {
    pub fn load(ipv4_file: Option<&str>, ipv6_file: Option<&str>) -> anyhow::Result<Self> {
        let ipv4 = if let Some(file) = ipv4_file {
            info!("Hosts IPv4: {}", file);
            Arc::new(load_hosts_file::<Ipv4Addr>(file)?)
        } else {
            Arc::new(HashMap::new())
        };

        let ipv6 = if let Some(file) = ipv6_file {
            info!("Hosts IPv6: {}", file);
            Arc::new(load_hosts_file::<Ipv6Addr>(file)?)
        } else {
            Arc::new(HashMap::new())
        };

        Ok(Self { ipv4, ipv6 })
    }

    pub fn lookup_ipv4(&self, domain: &str) -> Option<Ipv4Addr> {
        self.ipv4.get(&normalize_domain(domain)).copied()
    }

    pub fn lookup_ipv6(&self, domain: &str) -> Option<Ipv6Addr> {
        self.ipv6.get(&normalize_domain(domain)).copied()
    }

    pub fn lookup_preferred_ip(&self, domain: &str) -> Option<IpAddr> {
        self.lookup_ipv4(domain)
            .map(IpAddr::V4)
            .or_else(|| self.lookup_ipv6(domain).map(IpAddr::V6))
    }

    pub fn has_domain(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.ipv4.contains_key(&domain) || self.ipv6.contains_key(&domain)
    }
}

fn load_hosts_file<T>(file: &str) -> anyhow::Result<HashMap<String, T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let content = read_to_string(file)?;
    let mut hosts = HashMap::new();

    for (index, line) in content.lines().enumerate() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let ip = parts
            .next()
            .ok_or_else(|| anyhow!("Invalid hosts line {} in {}", index + 1, file))?;
        let domain = parts
            .next()
            .ok_or_else(|| anyhow!("Invalid hosts line {} in {}", index + 1, file))?;

        if parts.next().is_some() {
            bail!("Invalid hosts line {} in {}", index + 1, file);
        }

        let domain = normalize_domain(domain);
        let ip = ip
            .parse::<T>()
            .map_err(|error| anyhow!("Invalid IP '{}' in {}: {}", ip, file, error))?;

        if hosts.insert(domain.clone(), ip).is_some() {
            bail!("Duplicate hosts entry '{}' in {}", domain, file);
        }
    }

    Ok(hosts)
}

fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::Hosts;

    #[test]
    fn prefer_ipv4_host() {
        let dir = std::env::temp_dir().join(format!("autoproxy-hosts-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let ipv4 = dir.join("hosts4.txt");
        let ipv6 = dir.join("hosts6.txt");
        fs::write(&ipv4, "1.2.3.4 Example.COM\n").unwrap();
        fs::write(&ipv6, "2408::1 example.com\n").unwrap();

        let hosts = Hosts::load(ipv4.to_str(), ipv6.to_str()).unwrap();
        assert_eq!(
            hosts
                .lookup_preferred_ip("example.com")
                .unwrap()
                .to_string(),
            "1.2.3.4"
        );
        assert!(hosts.has_domain("example.com."));

        fs::remove_file(ipv4).ok();
        fs::remove_file(ipv6).ok();
        fs::remove_dir(dir).ok();
    }
}
