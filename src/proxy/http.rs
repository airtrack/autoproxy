use std::io::{Error, ErrorKind};

use httparse::Status;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub enum HttpAccept {
    Connect { host: String },
    Request { host: String, request: Vec<u8> },
}

pub struct HttpProxy;

impl HttpProxy {
    pub async fn accept(stream: &mut TcpStream) -> std::io::Result<HttpAccept> {
        let mut buf = vec![0u8; 1500];
        let mut len = 0;

        while len < buf.len() {
            let size = stream.read(&mut buf[len..]).await?;
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
                    let host = req.path.unwrap().to_string();
                    return Ok(HttpAccept::Connect { host });
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
                return Ok(HttpAccept::Request { host, request: buf });
            }
        }

        Err(Error::new(ErrorKind::Other, "http header too large"))
    }

    pub async fn connect(addr: &String, host: &String) -> std::io::Result<TcpStream> {
        let mut proxy = TcpStream::connect(addr).await?;
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

    pub async fn response_200(stream: &mut TcpStream) -> std::io::Result<()> {
        const HTTP_200_OK: &str = "HTTP/1.1 200 OK\r\n\r\n";
        stream.write_all(HTTP_200_OK.as_bytes()).await
    }
}
