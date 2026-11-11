//! Akış anahtarı ve yön tipleri.

use std::fmt;
use std::net::SocketAddr;

/// Taşıma protokolü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        })
    }
}

/// Paketin normalize anahtara göre yönü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyDir {
    /// `key.a` → `key.b`.
    AtoB,
    /// `key.b` → `key.a`.
    BtoA,
}

/// İstemci/sunucu yönü (istemci = ilk SYN'i, yoksa ilk paketi gönderen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dir {
    /// İstemci → sunucu.
    Client,
    /// Sunucu → istemci.
    Server,
}

impl Dir {
    #[must_use]
    pub fn opposite(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }

    /// Yön başına dizilerde indeks (Client = 0, Server = 1).
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            Self::Client => 0,
            Self::Server => 1,
        }
    }
}

/// IP sürümünden bağımsız, yönsüz 5-tuple. `a <= b` her zaman sağlanır.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub proto: Proto,
    pub a: SocketAddr,
    pub b: SocketAddr,
}

impl FlowKey {
    /// Kaynak/hedeften normalize anahtar ve paketin yönü.
    #[must_use]
    pub fn new(proto: Proto, src: SocketAddr, dst: SocketAddr) -> (Self, KeyDir) {
        if src <= dst {
            (
                Self {
                    proto,
                    a: src,
                    b: dst,
                },
                KeyDir::AtoB,
            )
        } else {
            (
                Self {
                    proto,
                    a: dst,
                    b: src,
                },
                KeyDir::BtoA,
            )
        }
    }

    /// Verilen yön için (kaynak, hedef).
    #[must_use]
    pub fn endpoints(&self, dir: KeyDir) -> (SocketAddr, SocketAddr) {
        match dir {
            KeyDir::AtoB => (self.a, self.b),
            KeyDir::BtoA => (self.b, self.a),
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ↔ {}", self.proto, self.a, self.b)
    }
}
