mod http;
mod socks5;

use std::sync::Arc;

use crate::rule::{Rule, RuleResult};
use futures::stream::StreamExt;
use http::{HttpAccept, HttpProxy};
use socks5::Socks5Proxy;
use tokio::{
    io::{copy_bidirectional, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

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

    async fn run_http_proxy(&self, mut stream: TcpStream) -> std::io::Result<(u64, u64)> {
        match HttpProxy::accept(&mut stream).await? {
            HttpAccept::Connect { host } => {
                let mut server = self.connect(&host).await?;
                HttpProxy::response_200(&mut stream).await?;
                copy_bidirectional(&mut stream, &mut server).await
            }
            HttpAccept::Request { mut host, request } => {
                if !host.contains(':') {
                    host.push_str(":80");
                }

                let mut server = self.connect(&host).await?;
                server.write_all(&request).await?;
                copy_bidirectional(&mut stream, &mut server).await
            }
        }
    }

    async fn run_socks5_proxy(&self, stream: TcpStream) -> std::io::Result<(u64, u64)> {
        match Socks5Proxy::accept(stream).await? {
            Socks5Proxy::Connect { mut stream, host } => {
                let mut outbound = self.connect(&host).await?;
                stream.copy_bidirectional_tcp_stream(&mut outbound).await
            }
            Socks5Proxy::UdpAssociate { socket, holder } => {
                let outbound = UdpSocket::bind("0.0.0.0:0").await?;
                socket.copy_bidirectional_udp_socket(outbound, holder).await
            }
        }
    }

    async fn connect(&self, host: &String) -> std::io::Result<TcpStream> {
        if self.apply_proxy_rules(host).await {
            println!("Proxy - {}", host);
            HttpProxy::connect(&self.proxy, host).await
        } else {
            println!("Direct - {}", host);
            TcpStream::connect(host).await
        }
    }

    async fn apply_proxy_rules(&self, host: &String) -> bool {
        for rule in self.rules.iter() {
            match rule.find_proxy_rule(host).await {
                RuleResult::Proxy => return true,
                RuleResult::Direct => return false,
                RuleResult::NotFound => {}
            }
        }

        false
    }
}
