mod http;

use std::sync::Arc;

use crate::rule::{Rule, RuleResult};
use http::{HttpAccept, HttpProxy};
use tokio::{
    io::{copy_bidirectional, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub struct AutoProxy {
    listener: TcpListener,
    rules: Arc<Vec<Box<dyn Rule>>>,
    proxy: String,
}

impl AutoProxy {
    pub async fn listen(
        address: &str,
        rules: Arc<Vec<Box<dyn Rule>>>,
        proxy: String,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        Ok(Self {
            listener,
            rules,
            proxy,
        })
    }

    pub async fn run(&self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _)) => {
                    let rules = self.rules.clone();
                    let proxy = self.proxy.clone();
                    tokio::spawn(async move {
                        let mut conn = Connection::new(stream, rules, proxy);
                        let _ = conn.run().await;
                    });
                }
                Err(_) => {}
            }
        }
    }
}

struct Connection {
    stream: TcpStream,
    rules: Arc<Vec<Box<dyn Rule>>>,
    proxy: String,
}

impl Connection {
    fn new(stream: TcpStream, rules: Arc<Vec<Box<dyn Rule>>>, proxy: String) -> Self {
        Self {
            stream,
            rules,
            proxy,
        }
    }

    async fn run(&mut self) -> std::io::Result<(u64, u64)> {
        match HttpProxy::accept(&mut self.stream).await? {
            HttpAccept::Connect { host } => {
                let mut server = self.connect(&host).await?;
                HttpProxy::response_200(&mut self.stream).await?;
                copy_bidirectional(&mut self.stream, &mut server).await
            }
            HttpAccept::Request { mut host, request } => {
                if !host.contains(':') {
                    host.push_str(":80");
                }

                let mut server = self.connect(&host).await?;
                server.write_all(&request).await?;
                copy_bidirectional(&mut self.stream, &mut server).await
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
