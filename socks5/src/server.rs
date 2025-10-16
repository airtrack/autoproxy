use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proto::*;
use crate::udp::*;

pub async fn accept(stream: TcpStream) -> std::io::Result<AcceptResult> {
    let acceptor = Acceptor::new(stream);
    acceptor.accept().await
}

pub enum AcceptResult {
    Connect(TcpIncoming),
    UdpAssociate(UdpIncoming),
}

pub struct TcpIncoming {
    acceptor: Acceptor,
    host: String,
}

impl TcpIncoming {
    fn new(acceptor: Acceptor, host: String) -> Self {
        Self { acceptor, host }
    }

    pub fn destination(&self) -> &str {
        &self.host
    }

    pub async fn reply_ok(mut self, bind: SocketAddr) -> Result<TcpStream> {
        self.acceptor.reply(true, bind).await?;
        Ok(self.acceptor.stream)
    }

    pub async fn reply_err(mut self) -> Result<()> {
        self.acceptor
            .reply(
                false,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            )
            .await
    }
}

pub struct UdpIncoming {
    socket: UdpSocketInner,
    holder: UdpSocketHolder,
}

impl UdpIncoming {
    fn new(socket: UdpSocketInner, holder: UdpSocketHolder) -> Self {
        Self { socket, holder }
    }

    pub async fn recv_wait(
        self,
        buf: &mut UdpSocketBuf,
    ) -> Result<(UdpSocket, UdpSocketHolder, SocketAddrV4)> {
        let (from, addr) = self.socket.recv(buf).await?;
        let socket = UdpSocket::from(self.socket, from);
        Ok((socket, self.holder, addr))
    }
}

struct Acceptor {
    stream: TcpStream,
}

impl Acceptor {
    fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    async fn accept(mut self) -> std::io::Result<AcceptResult> {
        self.select_method().await?;

        let mut req = [0u8; 4];
        self.stream.read_exact(&mut req).await?;
        match req[1] {
            CMD_CONNECT => self.accept_connect(req[3]).await,
            CMD_UDP_ASSOCIATE => self.accept_udp_associate(req[3]).await,
            c => {
                let error = format!("socks5: unknown CMD {}", c);
                Err(Error::new(ErrorKind::Other, error))
            }
        }
    }

    async fn accept_connect(mut self, atype: u8) -> std::io::Result<AcceptResult> {
        let host = self.parse_host(atype).await?;
        let incoming = TcpIncoming::new(self, host);
        Ok(AcceptResult::Connect(incoming))
    }

    async fn accept_udp_associate(mut self, atype: u8) -> std::io::Result<AcceptResult> {
        let _ = self.parse_host(atype).await?;
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        self.reply(true, socket.local_addr()?).await?;

        let socket = UdpSocketInner::from(socket);
        let holder = UdpSocketHolder::new(self.stream);
        let incoming = UdpIncoming::new(socket, holder);
        Ok(AcceptResult::UdpAssociate(incoming))
    }

    async fn reply(&mut self, success: bool, bind: SocketAddr) -> std::io::Result<()> {
        let rep = if success {
            REP_SUCCESS
        } else {
            REP_HOST_UNREACHABLE
        };
        let addr_type = if bind.is_ipv4() { ATYP_IPV4 } else { ATYP_IPV6 };

        let ack = [VER, rep, 0, addr_type];
        self.stream.write_all(&ack).await?;

        match bind {
            SocketAddr::V4(addr) => {
                self.stream.write_all(&addr.ip().octets()).await?;
                self.stream.write_u16(addr.port()).await
            }
            SocketAddr::V6(addr) => {
                self.stream.write_all(&addr.ip().octets()).await?;
                self.stream.write_u16(addr.port()).await
            }
        }
    }

    async fn select_method(&mut self) -> std::io::Result<()> {
        let mut buf = [0u8; 2];
        self.stream.read_exact(&mut buf).await?;

        if buf[0] != VER {
            return Err(Error::new(ErrorKind::Other, "socks5: VER error"));
        }

        let mut methods = vec![0u8; buf[1] as usize];
        self.stream.read_exact(&mut methods).await?;
        if !methods.into_iter().any(|m| m == NO_AUTH) {
            return Err(Error::new(
                ErrorKind::Other,
                "socks5: not found NO AUTH method",
            ));
        }

        let ack = [VER, NO_AUTH];
        self.stream.write_all(&ack).await
    }

    async fn parse_host(&mut self, atype: u8) -> std::io::Result<String> {
        let host = match atype {
            ATYP_IPV4 => {
                let mut octets = [0u8; 4];
                self.stream.read_exact(&mut octets).await?;
                let port = self.stream.read_u16().await?;
                format!(
                    "{}.{}.{}.{}:{}",
                    octets[0], octets[1], octets[2], octets[3], port
                )
            }
            ATYP_DOMAIN => {
                let len = self.stream.read_u8().await?;
                let mut domain = vec![0u8; len as usize];
                self.stream.read_exact(&mut domain).await?;
                let port = self.stream.read_u16().await?;
                let host = String::from_utf8(domain)
                    .map_err(|_| Error::new(ErrorKind::Other, "socks5: invalid domain"))?;
                format!("{}:{}", host, port)
            }
            ATYP_IPV6 => {
                let error = format!("socks5: unsupport IPv6");
                return Err(Error::new(ErrorKind::Other, error));
            }
            addr_type => {
                let error = format!("socks5: unknown addr type {}", addr_type);
                return Err(Error::new(ErrorKind::Other, error));
            }
        };

        Ok(host)
    }
}
