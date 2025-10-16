use std::sync::Arc;
use std::{env, fs};

use autoproxy::proxy::AutoProxy;
use autoproxy::rule::{
    DirectRule, DomainKeywordRule, DomainSuffixSetRule, GeoIpRule, IpNetRule, Rule, RuleResult,
};

use log::info;
use serde::Deserialize;
use tokio::runtime::Runtime;

#[derive(Deserialize)]
#[serde(tag = "type")]
enum RuleConfig {
    Direct { rule: RuleResult },
    IpNet { ipnet: String, rule: RuleResult },
    DomainKeyword { keyword: String, rule: RuleResult },
    DomainSuffixSet { file: String, rule: RuleResult },
    GeoIp { country: String, rule: RuleResult },
}

#[derive(Deserialize)]
struct Config {
    http: String,
    socks5: String,
    mmdb: String,
    proxy: String,
    rules: Vec<RuleConfig>,
}

fn main() {
    let mut args = env::args();
    if args.len() != 2 {
        println!("Usage: {} config.toml", args.nth(0).unwrap());
        return;
    }

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let content = String::from_utf8(fs::read(&args.nth(1).unwrap()).unwrap()).unwrap();
    let config: Config = toml::from_str(&content).unwrap();

    let mut rules = Vec::<Box<dyn Rule>>::new();

    for rule in config.rules {
        match rule {
            RuleConfig::Direct { rule } => {
                info!("DirectRule {:?}", rule);
                let direct = DirectRule::new(rule);
                rules.push(Box::new(direct));
            }
            RuleConfig::IpNet { ipnet, rule } => {
                info!("IpNetRule {} {:?}", ipnet, rule);
                let net = IpNetRule::new(&ipnet, rule);
                rules.push(Box::new(net));
            }
            RuleConfig::DomainKeyword { keyword, rule } => {
                info!("DomainKeyword {} {:?}", keyword, rule);
                let keyword = DomainKeywordRule::new(keyword, rule);
                rules.push(Box::new(keyword));
            }
            RuleConfig::DomainSuffixSet { file, rule } => {
                info!("DomainSuffixSet {} {:?}", file, rule);
                let set = DomainSuffixSetRule::new(&file, rule);
                rules.push(Box::new(set));
            }
            RuleConfig::GeoIp { country, rule } => {
                info!("GeoIp {} {:?}", country, rule);
                let geoip = GeoIpRule::new(&config.mmdb, country, rule);
                rules.push(Box::new(geoip));
            }
        }
    }

    let rt = Runtime::new().unwrap();
    rt.block_on(async move {
        let auto_proxy =
            AutoProxy::listen(&config.http, &config.socks5, Arc::new(rules), config.proxy)
                .await
                .unwrap();
        auto_proxy.run().await;
    });
}
