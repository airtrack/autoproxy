use std::{env, fs};

use autoproxy::dns::run_dns_server;
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
#[derive(serde::Deserialize, Default)]
struct MacOsLogging {
    enable: bool,
    subsystem: String,
}

#[derive(Deserialize)]
struct Config {
    listen: Listen,
    proxy: Proxy,
    dns: DnsConfig,

    #[serde(flatten)]
    rules: RulesConfig,

    #[cfg(target_os = "macos")]
    #[serde(default)]
    macos_logging: MacOsLogging,
}

fn init_log(_config: &Config) {
    #[cfg(target_os = "macos")]
    if _config.macos_logging.enable {
        oslog::OsLogger::new(&_config.macos_logging.subsystem)
            .level_filter(log::LevelFilter::Info)
            .category_level_filter("", log::LevelFilter::Info)
            .init()
            .unwrap();
        return;
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
    let (rules, async_rules) = load_rules(config.rules).unwrap();

    let h = run_http_proxy(&config.listen.http, &config.proxy.http, &async_rules)
        .map_err(anyhow::Error::from);
    let s = run_socks5_proxy(&config.listen.socks5, &config.proxy.socks5, &async_rules)
        .map_err(anyhow::Error::from);
    let d = run_dns_server(
        &config.dns.listen,
        &config.dns.upstream_direct,
        &config.dns.upstream_proxy,
        &config.proxy.socks5,
        &rules,
    );
    futures::try_join!(h, s, d).unwrap();
}
