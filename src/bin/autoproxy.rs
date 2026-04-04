use std::{env, fs};

use autoproxy::dns::run_dns_server;
use autoproxy::hosts::Hosts;
use autoproxy::proxy::{run_http_proxy, run_socks5_proxy};
use autoproxy::rule::{RulesConfig, load_rules};
use futures::TryFutureExt;
use serde::Deserialize;

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
struct DnsConfig {
    listen: String,
    upstream_direct: String,
    upstream_proxy: String,
}

#[cfg(target_os = "macos")]
#[derive(serde::Deserialize)]
struct MacOsLogging {
    enable: bool,
    subsystem: String,
}

#[derive(Deserialize)]
struct Config {
    listen: Listen,
    proxy: Proxy,
    dns: DnsConfig,
    hosts_ipv4: Option<String>,
    hosts_ipv6: Option<String>,

    #[serde(flatten)]
    rules: RulesConfig,

    #[cfg(target_os = "macos")]
    macos_logging: Option<MacOsLogging>,
}

fn init_log(_config: &Config) {
    #[cfg(target_os = "macos")]
    if let Some(ref macos_logging) = _config.macos_logging {
        if macos_logging.enable {
            oslog::OsLogger::new(&macos_logging.subsystem)
                .level_filter(log::LevelFilter::Info)
                .category_level_filter("", log::LevelFilter::Info)
                .init()
                .unwrap();
            return;
        }
    }

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();
}

#[tokio::main]
async fn main() {
    let mut args = env::args();
    if args.len() != 2 {
        println!("Usage: {} config.toml", args.nth(0).unwrap());
        return;
    }

    let content = String::from_utf8(fs::read(&args.nth(1).unwrap()).unwrap()).unwrap();
    let config: Config = toml::from_str(&content).unwrap();

    init_log(&config);
    let hosts = Hosts::load(config.hosts_ipv4.as_deref(), config.hosts_ipv6.as_deref()).unwrap();
    let (rules, async_rules) = load_rules(config.rules).unwrap();

    let h = run_http_proxy(
        &config.listen.http,
        &config.proxy.http,
        &async_rules,
        &hosts,
    )
    .map_err(anyhow::Error::from);
    let s = run_socks5_proxy(
        &config.listen.socks5,
        &config.proxy.socks5,
        &async_rules,
        &hosts,
    )
    .map_err(anyhow::Error::from);
    let d = run_dns_server(
        &config.dns.listen,
        &config.dns.upstream_direct,
        &config.dns.upstream_proxy,
        &config.proxy.socks5,
        &rules,
        &hosts,
    );
    futures::try_join!(h, s, d).unwrap();
}
