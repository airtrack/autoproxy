use std::net::SocketAddr;

pub(crate) const VER: u8 = 5;
pub(crate) const NO_AUTH: u8 = 0;

pub(crate) const CMD_CONNECT: u8 = 1;
pub(crate) const CMD_UDP_ASSOCIATE: u8 = 3;

pub(crate) const ATYP_IPV4: u8 = 1;
pub(crate) const ATYP_IPV6: u8 = 4;
pub(crate) const ATYP_DOMAIN: u8 = 3;

pub(crate) const REP_SUCCESS: u8 = 0;
pub(crate) const REP_HOST_UNREACHABLE: u8 = 4;

#[derive(Clone)]
pub enum Address {
    Host(String),
    Ip(SocketAddr),
}
