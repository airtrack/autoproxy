use std::{
    io::{Error, ErrorKind},
    sync::Arc,
};

use crate::rule::{Rule, RuleResult};
use httparse::Status;
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
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

const HTTP_200_OK: &str = "HTTP/1.1 200 OK\r\n\r\n";

enum HttpHandshake {
    Connect(String),
    Request(String, Vec<u8>),
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
        match self.handshake().await? {
            HttpHandshake::Connect(host) => self.process_tunnel(host).await,
            HttpHandshake::Request(host, data) => self.process_request(host, data).await,
        }
    }

    async fn handshake(&mut self) -> std::io::Result<HttpHandshake> {
        let mut buf = vec![0u8; 1500];
        let mut len = 0;

        while len < buf.len() {
            let size = self.stream.read(&mut buf[len..]).await?;
            if size == 0 {
                return Err(Error::new(ErrorKind::ConnectionAborted, "client closed"));
            }
            len += size;

            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut req = httparse::Request::new(&mut headers);

            match req.parse(&buf[0..len]) {
                Ok(Status::Complete(_)) => {}
                Ok(Status::Partial) => {
                    continue;
                }
                Err(_) => {
                    return Err(Error::new(ErrorKind::Other, "http error"));
                }
            }

            let is_connect_method = |m: &str| m.to_ascii_uppercase() == "CONNECT";

            if req.method.map_or_else(|| false, is_connect_method) {
                if req.path.is_none() {
                    return Err(Error::new(ErrorKind::Other, "CONNECT path empty"));
                } else {
                    return Ok(HttpHandshake::Connect(req.path.unwrap().to_string()));
                }
            } else {
                let mut host: String = String::default();
                for header in req.headers {
                    if header.name.to_ascii_uppercase() == "HOST" {
                        host = String::from_utf8(header.value.to_vec()).unwrap_or_default();
                        break;
                    }
                }

                if host.is_empty() {
                    return Err(Error::new(ErrorKind::Other, "Host empty"));
                }

                buf.truncate(len);
                return Ok(HttpHandshake::Request(host, buf));
            }
        }

        Err(Error::new(ErrorKind::Other, "http header too large"))
    }

    async fn process_tunnel(&mut self, host: String) -> std::io::Result<(u64, u64)> {
        let mut server = if self.process_proxy_rule(host.clone()).await {
            println!("Proxy - {}", host);
            self.connect_proxy(host).await?
        } else {
            println!("Direct - {}", host);
            TcpStream::connect(host).await?
        };

        self.stream.write_all(HTTP_200_OK.as_bytes()).await?;
        copy_bidirectional(&mut self.stream, &mut server).await
    }

    async fn process_request(
        &mut self,
        mut host: String,
        data: Vec<u8>,
    ) -> std::io::Result<(u64, u64)> {
        if !host.contains(':') {
            host.push_str(":80");
        }

        let mut server = if self.process_proxy_rule(host.clone()).await {
            println!("Proxy - {}", host);
            self.connect_proxy(host).await?
        } else {
            println!("Direct - {}", host);
            TcpStream::connect(host).await?
        };

        server.write_all(&data).await?;
        copy_bidirectional(&mut self.stream, &mut server).await
    }

    async fn process_proxy_rule(&self, host: String) -> bool {
        for rule in self.rules.iter() {
            match rule.find_proxy_rule(host.clone()).await {
                RuleResult::Proxy => return true,
                RuleResult::Direct => return false,
                RuleResult::NotFound => {}
            }
        }

        false
    }

    async fn connect_proxy(&self, host: String) -> std::io::Result<TcpStream> {
        let mut proxy = TcpStream::connect(&self.proxy).await?;
        let req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", host, host);
        proxy.write_all(req.as_bytes()).await?;

        let mut buf = [0u8; 1500];
        let mut len = 0;

        while len < buf.len() {
            let size = proxy.read(&mut buf[len..]).await?;
            if size == 0 {
                return Err(Error::new(ErrorKind::ConnectionReset, "proxy closed"));
            }
            len += size;

            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut resp = httparse::Response::new(&mut headers);

            match resp.parse(&buf[0..len]) {
                Ok(Status::Complete(offset)) => {
                    let code = resp.code.unwrap_or_default();
                    if code >= 200 && code < 300 && len == offset {
                        return Ok(proxy);
                    }

                    let error = format!("proxy response code {}", code);
                    return Err(Error::new(ErrorKind::Other, error));
                }
                Ok(Status::Partial) => {
                    println!("parse HTTP response partial, len: {}", len);
                    continue;
                }
                Err(_) => {
                    return Err(Error::new(ErrorKind::Other, "connect proxy error"));
                }
            }
        }

        Err(Error::new(ErrorKind::Other, "proxy response too large"))
    }
}
