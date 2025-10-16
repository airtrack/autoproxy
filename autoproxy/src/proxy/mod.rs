use std::{net::SocketAddr, sync::Arc};

use crate::rule::{Rule, RuleResult};
use httpproxy::HttpProxy;

use futures::stream::StreamExt;
use log::info;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub struct AutoProxy {
    http_listener: TcpListener,
    socks5_listener: TcpListener,
    rules: Arc<Vec<Box<dyn Rule>>>,
    proxy: String,
    http_port: u16,
}

impl AutoProxy {
    pub async fn listen(
        http: &str,
        socks5: &str,
        rules: Arc<Vec<Box<dyn Rule>>>,
        proxy: String,
    ) -> std::io::Result<Self> {
        let http_listener = TcpListener::bind(http).await?;
        let socks5_listener = TcpListener::bind(socks5).await?;
        let http_port = http_listener.local_addr().unwrap().port();
        Ok(Self {
            http_listener,
            socks5_listener,
            rules,
            proxy,
            http_port,
        })
    }

    pub async fn run(self) {
        let mut listener = futures::stream::select(
            tokio_stream::wrappers::TcpListenerStream::new(self.http_listener),
            tokio_stream::wrappers::TcpListenerStream::new(self.socks5_listener),
        );

        while let Some(stream) = listener.next().await {
            match stream {
                Ok(stream) => {
                    let rules = self.rules.clone();
                    let proxy = self.proxy.clone();
                    let http_conn = stream.local_addr().unwrap().port() == self.http_port;

                    tokio::spawn(async move {
                        let conn = Connection::new(rules, proxy);
                        if http_conn {
                            let _ = conn.run_http_proxy(stream).await;
                        } else {
                            let _ = conn.run_socks5_proxy(stream).await;
                        }
                    });
                }
                Err(_) => {}
            }
        }
    }
}

struct Connection {
    rules: Arc<Vec<Box<dyn Rule>>>,
    proxy: String,
}

impl Connection {
    fn new(rules: Arc<Vec<Box<dyn Rule>>>, proxy: String) -> Self {
        Self { rules, proxy }
    }

    async fn run_http_proxy(&self, stream: TcpStream) -> std::io::Result<(u64, u64)> {
        let mut inbound = HttpProxy::accept(stream).await?;
        let mut outbound = self.connect(inbound.host()).await?;
        inbound.copy_bidirectional_tcp_stream(&mut outbound).await
    }

    async fn run_socks5_proxy(&self, stream: TcpStream) -> std::io::Result<(u64, u64)> {
        match socks5::accept(stream).await? {
            socks5::AcceptResult::Connect(tcp_incoming) => {
                let mut outbound = self.connect(tcp_incoming.destination()).await?;
                let mut inbound = tcp_incoming.reply_ok(outbound.local_addr()?).await?;
                tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
            }
            socks5::AcceptResult::UdpAssociate(udp_incoming) => {
                let mut buf = socks5::UdpSocketBuf::new();
                let (inbound, holder, dst) = udp_incoming.recv_wait(&mut buf).await?;
                let outbound = UdpSocket::bind("0.0.0.0:0").await?;

                outbound.send_to(buf.as_ref(), dst).await?;
                async fn udp_send(
                    inbound: &socks5::UdpSocket,
                    outbound: &UdpSocket,
                ) -> std::io::Result<()> {
                    let mut buf = socks5::UdpSocketBuf::new();
                    loop {
                        let addr = inbound.recv(&mut buf).await?;
                        outbound.send_to(buf.as_ref(), addr).await?;
                    }
                }

                async fn udp_recv(
                    inbound: &socks5::UdpSocket,
                    outbound: &UdpSocket,
                ) -> std::io::Result<()> {
                    let mut buf = socks5::UdpSocketBuf::new();
                    loop {
                        if let (len, SocketAddr::V4(from)) =
                            outbound.recv_from(buf.as_mut()).await?
                        {
                            buf.set_len(len);
                            inbound.send(&mut buf, from).await?;
                        }
                    }
                }

                async fn udp_holder(mut holder: socks5::UdpSocketHolder) -> std::io::Result<()> {
                    holder.wait().await
                }

                futures::try_join!(
                    udp_send(&inbound, &outbound),
                    udp_recv(&inbound, &outbound),
                    udp_holder(holder),
                )?;

                Ok((0, 0))
            }
        }
    }

    async fn connect(&self, host: &str) -> std::io::Result<TcpStream> {
        match self.apply_proxy_rules(host).await {
            RuleResult::Proxy => {
                info!("Proxy - {}", host);
                HttpProxy::connect(&self.proxy, host).await
            }
            RuleResult::Direct => {
                info!("Direct - {}", host);
                TcpStream::connect(host).await
            }
            _ => {
                info!("Block - {}", host);
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "Blocked",
                ))
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
