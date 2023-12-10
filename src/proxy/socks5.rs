use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const SOCKS5_VER: u8 = 5;
const METHOD_NO_AUTH: u8 = 0;

const CMD_CONNECT: u8 = 1;

const ADDR_TYPE_IPV4: u8 = 1;
const ADDR_TYPE_IPV6: u8 = 4;
const ADDR_TYPE_DOMAIN: u8 = 3;

const REP_SUCCESS: u8 = 0;
const REP_HOST_UNREACHABLE: u8 = 4;

pub enum Socks5Accept {
    Connect { host: String },
}

pub struct Socks5Proxy;

impl Socks5Proxy {
    pub async fn accept(stream: &mut TcpStream) -> std::io::Result<Socks5Accept> {
        Self::select_method(stream).await?;

        let mut req = [0u8; 4];
        stream.read_exact(&mut req).await?;
        match req[1] {
            CMD_CONNECT => {}
            c => {
                let error = format!("Unsupport SOCKS5 CMD {}", c);
                return Err(Error::new(ErrorKind::Other, error));
            }
        }

        let host = match req[3] {
            ADDR_TYPE_IPV4 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).await?;
                let port = stream.read_u16().await?;
                format!(
                    "{}.{}.{}.{}:{}",
                    octets[0], octets[1], octets[2], octets[3], port
                )
            }
            ADDR_TYPE_DOMAIN => {
                let len = stream.read_u8().await?;
                let mut domain = vec![0u8; len as usize];
                stream.read_exact(&mut domain).await?;
                let port = stream.read_u16().await?;
                let host = String::from_utf8(domain)
                    .map_err(|_| Error::new(ErrorKind::Other, "Domain is invalid"))?;
                format!("{}:{}", host, port)
            }
            ADDR_TYPE_IPV6 => {
                let error = format!("IPv6 address is not support");
                return Err(Error::new(ErrorKind::Other, error));
            }
            addr_type => {
                let error = format!("Unsupport SOCKS5 addr type {}", addr_type);
                return Err(Error::new(ErrorKind::Other, error));
            }
        };

        Ok(Socks5Accept::Connect { host })
    }

    pub async fn reply(
        stream: &mut TcpStream,
        success: bool,
        bind: SocketAddr,
    ) -> std::io::Result<()> {
        let rep = if success {
            REP_SUCCESS
        } else {
            REP_HOST_UNREACHABLE
        };
        let addr_type = if bind.is_ipv4() {
            ADDR_TYPE_IPV4
        } else {
            ADDR_TYPE_IPV6
        };

        let ack = [SOCKS5_VER, rep, 0, addr_type];
        stream.write_all(&ack).await?;

        match bind {
            SocketAddr::V4(addr) => {
                stream.write_all(&addr.ip().octets()).await?;
                stream.write_u16(addr.port()).await
            }
            SocketAddr::V6(addr) => {
                stream.write_all(&addr.ip().octets()).await?;
                stream.write_u16(addr.port()).await
            }
        }
    }

    async fn select_method(stream: &mut TcpStream) -> std::io::Result<()> {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;

        if buf[0] != SOCKS5_VER {
            return Err(Error::new(ErrorKind::Other, "SOCKS5 VER error"));
        }

        let mut methods = vec![0u8; buf[1] as usize];
        stream.read_exact(&mut methods).await?;
        if !methods.into_iter().any(|m| m == METHOD_NO_AUTH) {
            return Err(Error::new(ErrorKind::Other, "Not found NO AUTH method"));
        }

        let ack = [SOCKS5_VER, METHOD_NO_AUTH];
        stream.write_all(&ack).await
    }
}
