/// Which listener a connection arrived on.
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Http,
    Socks5,
}

impl Protocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
        }
    }
}
