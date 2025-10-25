use std::{
    io::{Error, ErrorKind, Result},
    net::SocketAddr,
    sync::Arc,
};

use httpproxy::HttpProxy;
use log::{info, trace};
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
                info!("proxy connect tcp {}", host);
                f(proxy, host).await
            }
            RuleResult::Direct => {
                info!("direct connect tcp {}", host);
                TcpStream::connect(host).await
            }
            _ => {
                info!("block connect tcp {}", host);
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

async fn run_socks5_udp_proxy(incoming: UdpIncoming, rules: AutoRules, proxy: &str) -> Result<()> {
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
    rules: AutoRules,
    direct: Option<UdpSocket>,
    socks5: Option<socks5::UdpSocket>,
    holder: Option<socks5::UdpSocketHolder>,
}

impl UdpOutboundSocket {
    fn new(from: SocketAddr, rules: AutoRules, proxy: String) -> Self {
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
