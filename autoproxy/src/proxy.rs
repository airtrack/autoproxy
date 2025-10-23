use std::{
    io::{Error, ErrorKind, Result},
    sync::Arc,
};

use httpproxy::HttpProxy;
use log::info;
use socks5::{TcpIncoming, UdpIncoming};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::rule::{Rule, RuleResult};

#[derive(Clone)]
pub struct AutoRules {
    rules: Arc<Vec<Box<dyn Rule>>>,
}

impl AutoRules {
    pub fn new(rules: Arc<Vec<Box<dyn Rule>>>) -> Self {
        Self { rules }
    }

    async fn connect<F>(&self, proxy: &str, host: &str, f: F) -> Result<TcpStream>
    where
        F: AsyncFnOnce(&str, &str) -> Result<TcpStream>,
    {
        match self.apply_proxy_rules(host).await {
            RuleResult::Proxy => {
                info!("Proxy - {}", host);
                f(proxy, host).await
            }
            RuleResult::Direct => {
                info!("Direct - {}", host);
                TcpStream::connect(host).await
            }
            _ => {
                info!("Block - {}", host);
                Err(Error::new(ErrorKind::ConnectionRefused, "Blocked"))
            }
        }
    }

    async fn apply_proxy_rules(&self, host: &str) -> RuleResult {
        for rule in self.rules.iter() {
            match rule.find_proxy_rule(host).await {
                RuleResult::NotFound => {}
                r => return r,
            }
        }

        RuleResult::Direct
    }
}

pub async fn run_http_proxy(listen: &str, proxy: &String, rules: &AutoRules) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let proxy = proxy.clone();
        let rules = rules.clone();

        tokio::spawn(async move { run_http_proxy_connection(stream, rules, &proxy).await });
    }
}

pub async fn run_socks5_proxy(listen: &str, proxy: &String, rules: &AutoRules) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let proxy = proxy.clone();
        let rules = rules.clone();

        tokio::spawn(async move { run_socks5_proxy_connection(stream, rules, &proxy).await });
    }
}

async fn run_http_proxy_connection(stream: TcpStream, rules: AutoRules, proxy: &str) -> Result<()> {
    let mut inbound = HttpProxy::accept(stream).await?;
    let mut outbound = rules
        .connect(proxy, inbound.host(), async |proxy, host| {
            HttpProxy::connect(proxy, host).await
        })
        .await?;
    inbound
        .copy_bidirectional_tcp_stream(&mut outbound)
        .await
        .map(|_| ())
}

async fn run_socks5_proxy_connection(
    stream: TcpStream,
    rules: AutoRules,
    proxy: &str,
) -> Result<()> {
    match socks5::accept(stream).await? {
        socks5::AcceptResult::Connect(incoming) => {
            run_socks5_tcp_proxy(incoming, rules, proxy).await
        }
        socks5::AcceptResult::UdpAssociate(incoming) => {
            run_socks5_udp_proxy(incoming, rules, proxy).await
        }
    }
}

async fn run_socks5_tcp_proxy(incoming: TcpIncoming, rules: AutoRules, proxy: &str) -> Result<()> {
    let host = match incoming.destination() {
        socks5::Address::Host(host) => host.clone(),
        socks5::Address::Ip(addr) => addr.to_string(),
    };
    let destination = incoming.destination().clone();

    let mut outbound = rules
        .connect(proxy, &host, async |proxy, _| {
            socks5::connect(proxy, destination).await
        })
        .await?;

    let mut inbound = incoming.reply_ok(outbound.local_addr()?).await?;

    tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .map(|_| ())
}

async fn run_socks5_udp_proxy(
    incoming: UdpIncoming,
    _rules: AutoRules,
    _proxy: &str,
) -> Result<()> {
    let mut buf = socks5::UdpSocketBuf::new();
    let (inbound, holder, dst) = incoming.recv_wait(&mut buf).await?;
    let outbound = UdpSocket::bind("0.0.0.0:0").await?;

    outbound.send_to(buf.as_ref(), dst).await?;
    async fn udp_send(inbound: &socks5::UdpSocket, outbound: &UdpSocket) -> Result<()> {
        let mut buf = socks5::UdpSocketBuf::new();
        loop {
            let addr = inbound.recv(&mut buf).await?;
            outbound.send_to(buf.as_ref(), addr).await?;
        }
    }

    async fn udp_recv(inbound: &socks5::UdpSocket, outbound: &UdpSocket) -> Result<()> {
        let mut buf = socks5::UdpSocketBuf::new();
        loop {
            let (len, from) = outbound.recv_from(buf.as_mut()).await?;
            buf.set_len(len);
            inbound.send(&mut buf, from).await?;
        }
    }

    async fn udp_holder(mut holder: socks5::UdpSocketHolder) -> Result<()> {
        holder.wait().await
    }

    futures::try_join!(
        udp_send(&inbound, &outbound),
        udp_recv(&inbound, &outbound),
        udp_holder(holder),
    )?;

    Ok(())
}
