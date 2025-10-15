use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const VER: u8 = 5;
const NO_AUTH: u8 = 0;

const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

const ATYP_IPV4: u8 = 1;
const ATYP_IPV6: u8 = 4;
const ATYP_DOMAIN: u8 = 3;

const REP_SUCCESS: u8 = 0;
const REP_HOST_UNREACHABLE: u8 = 4;

#[allow(unused)]
pub async fn connect(socks5: SocketAddr, destination: SocketAddr) -> Result<TcpStream> {
    let mut connector = Connector::new(socks5).await?;
    connector.handshake(destination, CMD_CONNECT).await?;
    Ok(connector.stream)
}

#[allow(unused)]
pub async fn udp_associate(
    socks5: SocketAddr,
    socket: tokio::net::UdpSocket,
) -> Result<(UdpSocket, UdpSocketHolder)> {
    let local_addr = socket.local_addr()?;
    let mut connector = Connector::new(socks5).await?;
    let mut peer_addr = connector.handshake(local_addr, CMD_UDP_ASSOCIATE).await?;

    if peer_addr.ip().is_unspecified() {
        peer_addr = SocketAddr::new(socks5.ip(), peer_addr.port());
    }

    Ok((
        UdpSocket::from(UdpSocketInner::from(socket), peer_addr),
        UdpSocketHolder::new(connector.stream),
    ))
}

pub async fn accept(stream: TcpStream) -> std::io::Result<AcceptResult> {
    let acceptor = Acceptor::new(stream);
    acceptor.accept().await
}

struct Connector {
    stream: TcpStream,
}

impl Connector {
    async fn new(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let mut connector = Self { stream };

        connector.select_method().await?;
        Ok(connector)
    }

    async fn select_method(&mut self) -> Result<()> {
        let request = [VER, 1, NO_AUTH];
        self.stream.write_all(&request).await?;

        let mut response = [0u8; 2];
        self.stream.read_exact(&mut response).await?;

        if response[0] != VER || response[1] != NO_AUTH {
            return Err(Error::new(ErrorKind::Other, "socks5: select method error"));
        }

        Ok(())
    }

    async fn handshake(&mut self, address: SocketAddr, cmd: u8) -> Result<SocketAddr> {
        let mut request = [0u8; 10];
        request[0] = VER;
        request[1] = cmd;
        request[2] = 0;
        request[3] = ATYP_IPV4;

        match address {
            SocketAddr::V4(addr) => {
                request[4..8].copy_from_slice(&addr.ip().octets());
                request[8..10].copy_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(_) => {
                return Err(Error::new(ErrorKind::Other, "socks5: unsupport IPv6"))
            }
        }

        self.stream.write_all(&request).await?;

        let mut response = [0u8; 10];
        self.stream.read_exact(&mut response).await?;

        if response[0] != VER || response[1] != 0 || response[3] != ATYP_IPV4 {
            return Err(Error::new(ErrorKind::Other, "socks5: handshake error"));
        }

        let ip = Ipv4Addr::new(response[4], response[5], response[6], response[7]);
        let port = u16::from_be_bytes(response[8..10].try_into().unwrap());

        Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }
}

pub struct UdpSocketBuf {
    buf: [u8; 1500],
    data_len: usize,
}

impl UdpSocketBuf {
    pub fn new() -> Self {
        Self {
            buf: [0; _],
            data_len: 0,
        }
    }

    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[10..]
    }

    pub fn set_len(&mut self, len: usize) {
        self.data_len = len;
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.buf[10..10 + self.data_len]
    }
}

pub struct UdpSocket {
    inner: UdpSocketInner,
    peer_addr: SocketAddr,
}

impl UdpSocket {
    fn from(inner: UdpSocketInner, peer_addr: SocketAddr) -> Self {
        Self { inner, peer_addr }
    }

    #[inline]
    pub async fn send(&self, buf: &mut UdpSocketBuf, addr: SocketAddrV4) -> Result<()> {
        self.inner.send(buf, addr, self.peer_addr).await
    }

    #[inline]
    pub async fn recv(&self, buf: &mut UdpSocketBuf) -> Result<SocketAddrV4> {
        let (_, addr) = self.inner.recv(buf).await?;
        Ok(addr)
    }
}

struct UdpSocketInner {
    socket: tokio::net::UdpSocket,
}

impl UdpSocketInner {
    fn from(socket: tokio::net::UdpSocket) -> Self {
        Self { socket }
    }

    async fn send(
        &self,
        buf: &mut UdpSocketBuf,
        addr: SocketAddrV4,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let len = buf.data_len;
        let buf = &mut buf.buf;

        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = ATYP_IPV4;
        buf[4..8].copy_from_slice(&addr.ip().octets());
        buf[8..10].copy_from_slice(&addr.port().to_be_bytes());

        self.socket.send_to(&buf[..10 + len], peer_addr).await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut UdpSocketBuf) -> Result<(SocketAddr, SocketAddrV4)> {
        loop {
            let (n, from) = self.socket.recv_from(&mut buf.buf).await?;
            if n <= 10 || buf.buf[3] != ATYP_IPV4 {
                continue;
            }

            buf.set_len(n - 10);

            let buf = &mut buf.buf;
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes(buf[8..10].try_into().unwrap());

            return Ok((from, SocketAddrV4::new(ip, port)));
        }
    }
}

pub struct UdpSocketHolder {
    stream: TcpStream,
}

impl UdpSocketHolder {
    fn new(stream: TcpStream) -> UdpSocketHolder {
        Self { stream }
    }

    pub async fn wait(&mut self) -> Result<()> {
        loop {
            let mut buffer = [0u8; 1024];
            let size = self.stream.read(&mut buffer).await?;
            if size == 0 {
                return Err(std::io::Error::new(
                    ErrorKind::ConnectionAborted,
                    "socks5: holding tcp conn of udp was closed",
                ));
            }
        }
    }
}

pub enum AcceptResult {
    Connect(TcpIncoming),
    UdpAssociate(UdpIncoming),
}

pub struct TcpIncoming {
    acceptor: Acceptor,
    host: String,
}

#[allow(unused)]
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
