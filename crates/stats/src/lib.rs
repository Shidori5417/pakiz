//! pakiz-stats: trafik istatistikleri, süreç eşleme ve DNS ad önbelleği.
//!
//! - [`Stats`]: pps/bps zaman serisi, protokol hiyerarşisi, top talker,
//!   konuşma ve port tabloları (bellek sınırlı).
//! - [`procmap::ProcessResolver`]: yerel soket → süreç (`sock_diag`, /proc yedeği).
//! - [`dnscache::DnsCache`]: DNS cevaplarından IP → ad.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::many_single_char_names
    )
)]

pub mod dnscache;
pub mod procmap;
mod stats;
mod table;

pub use stats::{
    Conversation, Counter, EndpointConversation, HierarchyNode, Stats, StatsConfig, Talker,
};
pub use table::{Table, Weighted};

use pakiz_dissect::{Dissection, FieldValue};
use std::net::{IpAddr, SocketAddr};

/// Crate hata tipi (yalnızca iç/düşük seviye API'lerde; üst API best-effort).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("G/Ç hatası: {0}")]
    Io(#[from] std::io::Error),
    #[error("netlink: {0}")]
    Netlink(String),
    #[error("ayrıştırma hatası: {0}")]
    Parse(String),
}

/// Taşıma protokolü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    /// IP protokol numarası.
    #[must_use]
    pub fn ip_proto(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

/// Paketin IP / port uç noktaları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoints {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// TCP/UDP ise taşıma ve portlar.
    pub l4: Option<(Transport, u16, u16)>,
}

impl Endpoints {
    /// Dissection'dan IP adresleri ve (varsa) TCP/UDP portları.
    #[must_use]
    pub fn from_dissection(d: &Dissection) -> Option<Self> {
        let ip = |name| match d.find(name).map(|f| &f.value) {
            Some(FieldValue::Ipv4(a)) => Some(IpAddr::V4(*a)),
            Some(FieldValue::Ipv6(a)) => Some(IpAddr::V6(*a)),
            _ => None,
        };
        let (src, dst) = match (ip("ip.src"), ip("ip.dst")) {
            (Some(s), Some(t)) => (s, t),
            _ => (ip("ipv6.src")?, ip("ipv6.dst")?),
        };
        let port = |name| match d.find(name).map(|f| &f.value) {
            Some(FieldValue::U16(p)) => Some(*p),
            _ => None,
        };
        let l4 = [
            (Transport::Tcp, "tcp.srcport", "tcp.dstport"),
            (Transport::Udp, "udp.srcport", "udp.dstport"),
        ]
        .into_iter()
        .find_map(|(t, s, d)| Some((t, port(s)?, port(d)?)));
        Some(Self { src, dst, l4 })
    }

    /// Kaynak soket adresi (L4 varsa).
    #[must_use]
    pub fn src_sock(&self) -> Option<SocketAddr> {
        self.l4.map(|(_, sp, _)| SocketAddr::new(self.src, sp))
    }

    /// Hedef soket adresi (L4 varsa).
    #[must_use]
    pub fn dst_sock(&self) -> Option<SocketAddr> {
        self.l4.map(|(_, _, dp)| SocketAddr::new(self.dst, dp))
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use pakiz_dissect::{Dissection, RawPacket, Registry};
    use std::time::SystemTime;

    pub fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    pub fn dissect(h: &str) -> Dissection {
        dissect_bytes(hex(h))
    }

    pub fn dissect_bytes(data: Vec<u8>) -> Dissection {
        Registry::default().dissect(&RawPacket {
            ts: SystemTime::UNIX_EPOCH,
            orig_len: u32::try_from(data.len()).unwrap(),
            data,
            ifindex: 1,
        })
    }
}
