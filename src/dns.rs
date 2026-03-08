use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use hickory_proto::op::{Message, OpCode};
use log::{error, info};
use tokio::net::UdpSocket;

use crate::rule::{AutoRules, RuleResult};

const DNS_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const MAX_IN_FLIGHT_TOTAL: usize = 32768;

/// DNS query identifier for tracking upstream requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UpstreamId(u16);

/// Context preserved to route upstream responses back to the original client.
struct InFlight {
    client_id: u16,
    client_addr: SocketAddr,
    created_at: Instant,
}

/// A "smart" SOCKS5 UDP socket that handles association and lifecycle internally.
struct Socks5Socket {
    socks5: String,
    socket: Option<socks5::UdpSocket>,
    holder: Option<socks5::UdpSocketHolder>,
}

impl Socks5Socket {
    fn new(socks5: String) -> Self {
        Self {
            socks5,
            socket: None,
            holder: None,
        }
    }

    async fn send(&mut self, data: &[u8], target: SocketAddr) -> anyhow::Result<()> {
        if self.socket.is_none() {
            info!("Creating new SOCKS5 UDP association via {}", self.socks5);

            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            let (socket, holder) = socks5::udp_associate(&self.socks5, socket).await?;
            self.socket = Some(socket);
            self.holder = Some(holder);
        }

        let mut buf = socks5::UdpSocketBuf::new();
        if data.len() > buf.as_mut().len() {
            return Err(anyhow!("Data exceeds SOCKS5 UDP buffer"));
        }

        buf.as_mut()[..data.len()].copy_from_slice(data);
        buf.set_len(data.len());

        self.socket
            .as_ref()
            .unwrap()
            .send(&mut buf, target)
            .await
            .map_err(|e| anyhow!(e))
    }

    async fn recv(&mut self, buf: &mut socks5::UdpSocketBuf) -> anyhow::Result<SocketAddr> {
        if self.socket.is_none() {
            return futures::future::pending().await;
        }

        let socket = self.socket.as_ref().unwrap();
        let holder = self.holder.as_mut().unwrap();

        tokio::select! {
            res = socket.recv(buf) => {
                res.map_err(|e| anyhow!(e))
            }
            _ = holder.wait() => {
                info!("SOCKS5 association closed, invalidating...");
                self.socket = None;
                self.holder = None;
                Err(anyhow!("SOCKS5 association closed"))
            }
        }
    }
}

/// Handles DNS protocol logic.
struct DnsHandler {
    socket: UdpSocket,
    upstream_direct: SocketAddr,
    upstream_proxy: SocketAddr,
    rules: AutoRules,
    direct_socket: UdpSocket,
    socks5_socket: Socks5Socket,
    in_flight_requests: HashMap<UpstreamId, InFlight>,
    next_id: u16,
}

fn get_system_dns() -> anyhow::Result<SocketAddr> {
    let (config, _) = hickory_resolver::system_conf::read_system_conf()
        .map_err(|e| anyhow!("Failed to read system DNS config: {}", e))?;

    let ns = config
        .name_servers()
        .first()
        .ok_or_else(|| anyhow!("No system DNS servers found"))?;

    Ok(ns.socket_addr)
}

impl DnsHandler {
    async fn new(
        listen: &str,
        upstream_direct: &str,
        upstream_proxy: &str,
        socks5: &str,
        rules: &AutoRules,
    ) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(listen).await?;
        let upstream_direct = if upstream_direct == "system" {
            get_system_dns().inspect(|addr| {
                info!("Using system DNS: {addr}");
            })?
        } else {
            upstream_direct.parse()?
        };
        let upstream_proxy = upstream_proxy.parse::<SocketAddr>()?;
        let direct_socket = UdpSocket::bind("0.0.0.0:0").await?;

        Ok(Self {
            socket,
            upstream_direct,
            upstream_proxy,
            rules: rules.clone(),
            direct_socket,
            socks5_socket: Socks5Socket::new(socks5.to_string()),
            in_flight_requests: HashMap::new(),
            next_id: 0,
        })
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let mut client_buf = [0u8; 1500];
        let mut direct_buf = [0u8; 1500];
        let mut socks5_buf = socks5::UdpSocketBuf::new();
        let mut cleanup_interval = tokio::time::interval(CLEANUP_INTERVAL);

        loop {
            tokio::select! {
                res = self.socket.recv_from(&mut client_buf) => {
                    let (len, src) = res?;
                    self.handle_client_query(&client_buf[..len], src).await.inspect_err(|error| {
                        error!("Request handling error from {src}: {error}");
                    }).ok();
                }
                res = self.direct_socket.recv_from(&mut direct_buf) => {
                    let (len, _) = res?;
                    self.handle_upstream_response(&direct_buf[..len]).await.inspect_err(|error| {
                        error!("Direct response error: {error}");
                    }).ok();
                }
                res = self.socks5_socket.recv(&mut socks5_buf) => {
                    if let Ok(_) = res {
                        self.handle_upstream_response(socks5_buf.as_ref()).await.inspect_err(|error| {
                            error!("Proxy response handling error: {error}");
                        }).ok();
                    }
                }
                _ = cleanup_interval.tick() => {
                    let now = Instant::now();
                    self.in_flight_requests.retain(|_, in_flight| {
                        now.duration_since(in_flight.created_at) < DNS_REQUEST_TIMEOUT
                    });
                }
            }
        }
    }

    fn next_upstream_id(&mut self) -> UpstreamId {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        UpstreamId(id)
    }

    async fn handle_client_query(&mut self, data: &[u8], src: SocketAddr) -> anyhow::Result<()> {
        let message = Message::from_vec(data)?;
        if message.op_code() != OpCode::Query {
            return Ok(());
        }

        let question = message
            .queries()
            .first()
            .ok_or_else(|| anyhow!("No questions"))?;

        let mut domain = question.name().to_string();
        if domain.ends_with(".") {
            domain.pop();
        }

        let rule_result = self.rules.apply_proxy_rules(&domain);

        match rule_result {
            RuleResult::Block => {
                info!("{domain} blocked");
                return Ok(());
            }
            RuleResult::Proxy => {
                info!("{domain} --> {}", self.upstream_proxy);
            }
            _ => {
                info!("{domain} --> {}", self.upstream_direct);
            }
        }

        if self.in_flight_requests.len() >= MAX_IN_FLIGHT_TOTAL {
            return Err(anyhow!("Too many in-flight requests"));
        }

        let mut upstream_id = self.next_upstream_id();
        while self.in_flight_requests.contains_key(&upstream_id) {
            upstream_id = self.next_upstream_id();
        }

        self.in_flight_requests.insert(
            upstream_id,
            InFlight {
                client_addr: src,
                client_id: message.id(),
                created_at: Instant::now(),
            },
        );

        let mut upstream_message = message;
        let upstream_data = upstream_message
            .set_id(upstream_id.0)
            .to_vec()
            .map_err(|e| anyhow!(e))?;

        match rule_result {
            RuleResult::Proxy => {
                self.socks5_socket
                    .send(&upstream_data, self.upstream_proxy)
                    .await
                    .map_err(|error| {
                        self.in_flight_requests.remove(&upstream_id);
                        error
                    })?;
            }
            _ => {
                self.direct_socket
                    .send_to(&upstream_data, self.upstream_direct)
                    .await
                    .map_err(|error| {
                        self.in_flight_requests.remove(&upstream_id);
                        anyhow!(error)
                    })?;
            }
        };

        Ok(())
    }

    async fn handle_upstream_response(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let message = Message::from_vec(data)?;

        if let Some(in_flight) = self.in_flight_requests.remove(&UpstreamId(message.id())) {
            let mut response = message;
            let response_data = response
                .set_id(in_flight.client_id)
                .to_vec()
                .map_err(|e| anyhow!(e))?;

            self.socket
                .send_to(&response_data, in_flight.client_addr)
                .await?;
        }

        Ok(())
    }
}

pub async fn run_dns_server(
    listen: &str,
    upstream_direct: &str,
    upstream_proxy: &str,
    socks5: &str,
    rules: &AutoRules,
) -> anyhow::Result<()> {
    let handler = DnsHandler::new(listen, upstream_direct, upstream_proxy, socks5, rules).await?;
    info!("DNS server listening on {}", listen);
    handler.run().await
}
