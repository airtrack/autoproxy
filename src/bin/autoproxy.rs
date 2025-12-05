use std::sync::Arc;
use std::{env, fs};

use autoproxy::proxy::{AutoRules, run_http_proxy, run_socks5_proxy};
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
struct Listen {
    http: String,
    socks5: String,
}

#[derive(Deserialize)]
struct Proxy {
    http: String,
    socks5: String,
}

#[derive(Deserialize)]
struct Config {
    listen: Listen,
    proxy: Proxy,
    mmdb: String,
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

    let rules = AutoRules::new(Arc::new(rules));

    let rt = Runtime::new().unwrap();
    rt.block_on(async move {
        let h = run_http_proxy(&config.listen.http, &config.proxy.http, &rules);
        let s = run_socks5_proxy(&config.listen.socks5, &config.proxy.socks5, &rules);
        let _r = futures::join!(h, s);
    });
}
