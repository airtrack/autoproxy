use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::proto::*;

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
    pub(crate) fn from(inner: UdpSocketInner, peer_addr: SocketAddr) -> Self {
        Self { inner, peer_addr }
    }

    #[inline]
    pub async fn send(&self, buf: &mut UdpSocketBuf, addr: SocketAddr) -> Result<()> {
        if let SocketAddr::V4(addr) = addr {
            self.inner.send(buf, addr, self.peer_addr).await
        } else {
            Err(Error::new(ErrorKind::Other, "socks5: unsupport IPv6"))
        }
    }

    #[inline]
    pub async fn recv(&self, buf: &mut UdpSocketBuf) -> Result<SocketAddr> {
        let (_, addr) = self.inner.recv(buf).await?;
        Ok(SocketAddr::V4(addr))
    }
}

pub(crate) struct UdpSocketInner {
    socket: tokio::net::UdpSocket,
}

impl UdpSocketInner {
    pub(crate) fn from(socket: tokio::net::UdpSocket) -> Self {
        Self { socket }
    }

    pub(crate) async fn send(
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

    pub(crate) async fn recv(&self, buf: &mut UdpSocketBuf) -> Result<(SocketAddr, SocketAddrV4)> {
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
    pub(crate) fn new(stream: TcpStream) -> UdpSocketHolder {
        Self { stream }
    }

    pub async fn wait(&mut self) -> Result<()> {
        loop {
            let mut buffer = [0u8; 1024];
            let size = self.stream.read(&mut buffer).await?;
            if size == 0 {
                return Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    "socks5: holding tcp conn of udp was closed",
                ));
            }
        }
    }
}
