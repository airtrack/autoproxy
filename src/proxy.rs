use std::{
    io::{Error, ErrorKind, Result},
    net::{IpAddr, SocketAddr},
};

use log::{info, trace};
use socks5::{TcpIncoming, UdpIncoming};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream, UdpSocket},
};

use crate::{
    dns_path_cache::DnsPathCache,
    hosts::Hosts,
    rule::{AsyncAutoRules, RuleResult},
};

pub async fn run_http_proxy(
    listen: &str,
    proxy: &str,
    rules: &AsyncAutoRules,
    hosts: &Hosts,
    dns_path_cache: &DnsPathCache,
) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let proxy = proxy.to_owned();
        let rules = rules.clone();
        let hosts = hosts.clone();
        let dns_path_cache = dns_path_cache.clone();

        tokio::spawn(async move {
            run_http_proxy_connection(stream, rules, hosts, dns_path_cache, &proxy).await
        });
    }
}

pub async fn run_socks5_proxy(
    listen: &str,
    proxy: &str,
    rules: &AsyncAutoRules,
    hosts: &Hosts,
    dns_path_cache: &DnsPathCache,
) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let proxy = proxy.to_owned();
        let rules = rules.clone();
        let hosts = hosts.clone();
        let dns_path_cache = dns_path_cache.clone();

        tokio::spawn(async move {
            run_socks5_proxy_connection(stream, rules, hosts, dns_path_cache, &proxy).await
        });
    }
}

enum ConnectTarget {
    Proxy,
    Direct,
    DirectAddr(SocketAddr),
    Block,
}

enum TargetHost {
    Domain(String),
    Ip(IpAddr),
}

async fn connect<F>(
    rules: &AsyncAutoRules,
    hosts: &Hosts,
    dns_path_cache: &DnsPathCache,
    proxy: &str,
    target: &str,
    f: F,
) -> Result<TcpStream>
where
    F: AsyncFnOnce(&str, &str) -> Result<TcpStream>,
{
    match resolve_connect_target(rules, hosts, dns_path_cache, target).await? {
        ConnectTarget::Proxy => {
            info!("proxy connect tcp {}", target);
            f(proxy, target).await
        }
        ConnectTarget::Direct => {
            info!("direct connect tcp {}", target);
            TcpStream::connect(target).await
        }
        ConnectTarget::DirectAddr(addr) => {
            info!("hosts connect tcp {} -> {}", target, addr);
            TcpStream::connect(addr).await
        }
        ConnectTarget::Block => {
            trace!("block connect tcp {}", target);
            Err(Error::new(ErrorKind::ConnectionRefused, "Blocked"))
        }
    }
}

async fn resolve_connect_target(
    rules: &AsyncAutoRules,
    hosts: &Hosts,
    dns_path_cache: &DnsPathCache,
    target: &str,
) -> Result<ConnectTarget> {
    let (host, port) = parse_target(target)?;

    match host {
        TargetHost::Domain(domain) => {
            if let Some(ip) = hosts.lookup_preferred_ip(&domain) {
                return Ok(ConnectTarget::DirectAddr(SocketAddr::new(ip, port)));
            }
        }
        TargetHost::Ip(ip) => {
            if let Some(path) = dns_path_cache.get(ip) {
                return match path {
                    RuleResult::Proxy => Ok(ConnectTarget::Proxy),
                    RuleResult::Direct => Ok(ConnectTarget::Direct),
                    _ => Ok(ConnectTarget::Block),
                };
            }
        }
    }

    match rules.apply_proxy_rules(target).await {
        RuleResult::Proxy => Ok(ConnectTarget::Proxy),
        RuleResult::Direct => Ok(ConnectTarget::Direct),
        _ => Ok(ConnectTarget::Block),
    }
}

fn parse_target(target: &str) -> Result<(TargetHost, u16)> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok((TargetHost::Ip(addr.ip()), addr.port()));
    }

    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Invalid target"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid target port"))?;

    Ok((TargetHost::Domain(host.to_string()), port))
}

async fn run_http_proxy_connection(
    stream: TcpStream,
    rules: AsyncAutoRules,
    hosts: Hosts,
    dns_path_cache: DnsPathCache,
    proxy: &str,
) -> Result<()> {
    let inbound = httpproxy::accept(stream).await?;
    let mut outbound = connect(
        &rules,
        &hosts,
        &dns_path_cache,
        proxy,
        inbound.host(),
        async |proxy, host| httpproxy::connect(proxy, host).await,
    )
    .await?;

    let (mut inbound, req) = inbound.response_200().await?;
    if let Some(req) = req {
        outbound.write_all(&req).await?;
    }

    copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .map(|_| ())
}

async fn run_socks5_proxy_connection(
    stream: TcpStream,
    rules: AsyncAutoRules,
    hosts: Hosts,
    dns_path_cache: DnsPathCache,
    proxy: &str,
) -> Result<()> {
    match socks5::accept(stream).await? {
        socks5::AcceptResult::Connect(incoming) => {
            run_socks5_tcp_proxy(incoming, rules, hosts, dns_path_cache, proxy).await
        }
        socks5::AcceptResult::UdpAssociate(incoming) => {
            run_socks5_udp_proxy(incoming, rules, proxy).await
        }
    }
}

async fn run_socks5_tcp_proxy(
    incoming: TcpIncoming,
    rules: AsyncAutoRules,
    hosts: Hosts,
    dns_path_cache: DnsPathCache,
    proxy: &str,
) -> Result<()> {
    let host = match incoming.destination() {
        socks5::Address::Host(host) => host.clone(),
        socks5::Address::Ip(addr) => addr.to_string(),
    };
    let destination = incoming.destination().clone();

    let mut outbound = connect(
        &rules,
        &hosts,
        &dns_path_cache,
        proxy,
        &host,
        async |proxy, _| socks5::connect(proxy, destination).await,
    )
    .await?;

    let mut inbound = incoming.reply_ok(outbound.local_addr()?).await?;

    copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .map(|_| ())
}

async fn run_socks5_udp_proxy(
    incoming: UdpIncoming,
    rules: AsyncAutoRules,
    proxy: &str,
) -> Result<()> {
    let mut buf = socks5::UdpSocketBuf::new();
    let (inbound, holder, dst) = incoming.recv_wait(&mut buf).await?;
    let outbound = UdpOutboundSocket::new(inbound.peer_addr(), rules, proxy.to_string());

    async fn udp_relay(
        inbound: socks5::UdpSocket,
        mut outbound: UdpOutboundSocket,
        mut buf: socks5::UdpSocketBuf,
        mut addr: SocketAddr,
    ) -> Result<()> {
        outbound.send(&mut buf, addr).await?;

        let mut buf1 = socks5::UdpSocketBuf::new();
        let mut buf2 = socks5::UdpSocketBuf::new();

        loop {
            tokio::select! {
                r = inbound.recv(&mut buf) => {
                    addr = r?;
                    outbound.send(&mut buf, addr).await?;
                }
                r = outbound.recv(&mut buf1, &mut buf2) => {
                    let (buf, addr) = r?;
                    inbound.send(buf, addr).await?;
                }
            }
        }
    }

    async fn udp_holder(mut holder: socks5::UdpSocketHolder) -> Result<()> {
        holder.wait().await
    }

    futures::try_join!(udp_relay(inbound, outbound, buf, dst), udp_holder(holder))?;
    Ok(())
}

struct UdpOutboundSocket {
    from: SocketAddr,
    proxy: String,
    rules: AsyncAutoRules,
    direct: Option<UdpSocket>,
    socks5: Option<socks5::UdpSocket>,
    holder: Option<socks5::UdpSocketHolder>,
}

impl UdpOutboundSocket {
    fn new(from: SocketAddr, rules: AsyncAutoRules, proxy: String) -> Self {
        Self {
            from,
            proxy,
            rules,
            direct: None,
            socks5: None,
            holder: None,
        }
    }

    async fn send(&mut self, buf: &mut socks5::UdpSocketBuf, addr: SocketAddr) -> Result<()> {
        match self.rules.apply_proxy_rules(&addr.to_string()).await {
            RuleResult::Direct => {
                if self.direct.is_none() {
                    let socket = UdpSocket::bind("0.0.0.0:0").await?;
                    self.direct = Some(socket);
                    info!(
                        "direct start udp socket [{}]: [direct {}, socks5 {}]",
                        self.from,
                        self.direct.is_some(),
                        self.socks5.is_some()
                    );
                }

                trace!("direct send udp packet [{}] to {}", self.from, addr);
                self.direct
                    .as_ref()
                    .expect("udp socket was not initialized")
                    .send_to(buf.as_ref(), addr)
                    .await?;
            }
            RuleResult::Proxy => {
                if self.socks5.is_none() {
                    let socket = UdpSocket::bind("0.0.0.0:0").await?;
                    let (socket, holder) = socks5::udp_associate(&self.proxy, socket).await?;
                    self.socks5 = Some(socket);
                    self.holder = Some(holder);
                    info!(
                        "socks5 start udp socket [{}]: [direct {}, socks5 {}]",
                        self.from,
                        self.direct.is_some(),
                        self.socks5.is_some()
                    );
                }

                trace!("socks5 send udp packet [{}] to {}", self.from, addr);
                self.socks5
                    .as_ref()
                    .expect("socks5 udp socket was not initialized")
                    .send(buf, addr)
                    .await?;
            }
            _ => {
                info!("block udp packet {} to {}", self.from, addr);
            }
        }

        Ok(())
    }

    async fn recv<'a>(
        &mut self,
        buf1: &'a mut socks5::UdpSocketBuf,
        buf2: &'a mut socks5::UdpSocketBuf,
    ) -> Result<(&'a mut socks5::UdpSocketBuf, SocketAddr)> {
        if let Some(ref direct) = self.direct
            && let Some(ref socks5) = self.socks5
            && let Some(ref mut holder) = self.holder
        {
            tokio::select! {
                r = recv_from_direct(direct, buf1) => {
                    return r;
                }
                r = recv_from_socks5(socks5, buf2) => {
                    return r;
                }
                r = holder.wait() => {
                    r?;
                }
            }
        } else if let Some(ref socks5) = self.socks5
            && let Some(ref mut holder) = self.holder
        {
            tokio::select! {
                r = recv_from_socks5(socks5, buf2) => {
                    return r;
                }
                r = holder.wait() => {
                    r?;
                }
            }
        } else if let Some(ref direct) = self.direct {
            return recv_from_direct(direct, buf1).await;
        }

        futures::future::pending().await
    }
}

async fn recv_from_direct<'a>(
    socket: &UdpSocket,
    buf: &'a mut socks5::UdpSocketBuf,
) -> Result<(&'a mut socks5::UdpSocketBuf, SocketAddr)> {
    let (len, from) = socket.recv_from(buf.as_mut()).await?;
    buf.set_len(len);
    return Ok((buf, from));
}

async fn recv_from_socks5<'a>(
    socket: &socks5::UdpSocket,
    buf: &'a mut socks5::UdpSocketBuf,
) -> Result<(&'a mut socks5::UdpSocketBuf, SocketAddr)> {
    let from = socket.recv(buf).await?;
    return Ok((buf, from));
}
