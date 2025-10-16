use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proto::*;
use crate::udp::*;

pub async fn connect(socks5: SocketAddr, destination: SocketAddr) -> Result<TcpStream> {
    let mut connector = Connector::new(socks5).await?;
    connector.handshake(destination, CMD_CONNECT).await?;
    Ok(connector.stream)
}

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
                return Err(Error::new(ErrorKind::Other, "socks5: unsupport IPv6"));
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
